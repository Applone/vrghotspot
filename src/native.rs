pub(crate) mod network;
use crate::{
    diagnostics::options::Options,
    os::hotspot::{ICS_CLIENT_DLL, IcsMismatchReason, IcsSignatureMismatch},
    pe::{Image, matches},
};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    path::{Path, PathBuf},
    ptr,
};
use windows::{
    Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::{
            Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree},
            LibraryLoader::{
                GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
                LoadLibraryExW,
            },
            Registry::{
                HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ,
                RRF_RT_REG_SZ, RegGetValueW,
            },
            SystemInformation::GetSystemDirectoryW,
            WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
        },
        UI::Shell::IsUserAnAdmin,
    },
    core::{GUID, HRESULT, IUnknown, Interface, PCWSTR, s, w},
};

const CLASS: GUID = GUID::from_u128(0x46c166aa_3108_11d4_9348_00c04f8eeb71);
const MANAGER: GUID = GUID::from_u128(0x85d18b6c_3032_11d4_9348_00c04f8eeb71);
const SETTINGS: GUID = GUID::from_u128(0x85d18b6f_3032_11d4_9348_00c04f8eeb71);

type GetObject = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;
type GetByGuid =
    unsafe extern "system" fn(*mut c_void, *const GUID, u8, u8, *mut *mut c_void) -> HRESULT;
type Disable = unsafe extern "system" fn(*mut c_void, *mut u32, *mut u32) -> HRESULT;
type Remove = unsafe extern "system" fn(*mut c_void) -> HRESULT;
type GetIndex = unsafe extern "system" fn(*mut u32) -> HRESULT;

pub(crate) struct Apartment;
impl Apartment {
    pub(crate) fn new() -> Result<Self> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED)?;
        }
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            RoUninitialize();
        }
    }
}

struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}

// Own an out-parameter even when a private call returns an error after setting it.
#[derive(Default)]
struct ComObject(*mut c_void);
impl Drop for ComObject {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                drop(IUnknown::from_raw(self.0));
            }
        }
    }
}

fn check(hr: HRESULT, operation: &str) -> Result<()> {
    println!("{operation}: 0x{:08X}", hr.0 as u32);
    hr.ok().with_context(|| operation.to_owned())
}

pub fn system_directory() -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    ensure!(
        length > 0 && length < buffer.len(),
        "Cannot resolve native System32 directory"
    );
    use std::os::windows::ffi::OsStringExt;
    Ok(std::ffi::OsString::from_wide(&buffer[..length]).into())
}

pub(crate) fn wide(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut result: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(!result.contains(&0), "Path contains a null character");
    result.push(0);
    Ok(result)
}

fn validate_registration(path: &Path) -> Result<()> {
    let mut buffer = vec![0u16; 32768];
    let mut bytes = (buffer.len() * 2) as u32;
    // RegGetValue expands REG_EXPAND_SZ using the native process environment.
    unsafe {
        RegGetValueW(
            HKEY_CLASSES_ROOT,
            w!("CLSID\\{46C166AA-3108-11D4-9348-00C04F8EEB71}\\InProcServer32"),
            PCWSTR::null(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
        .ok()?;
    }
    let end = buffer
        .iter()
        .position(|&c| c == 0)
        .context("Unterminated COM registration")?;
    use std::os::windows::ffi::OsStringExt;
    let registered = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end]));
    let registered = registered
        .canonicalize()
        .context("Resolving registered COM server")?;
    let actual = path.canonicalize()?;
    ensure!(
        registered.as_os_str().to_string_lossy().to_lowercase()
            == actual.as_os_str().to_string_lossy().to_lowercase(),
        "DLL does not match the registered in-process COM server."
    );
    Ok(())
}

fn library_checks() -> Result<bool> {
    let system = system_directory()?;
    let libraries: &[(&str, &[&str])] = &[
        (
            "hnetcfgclient.dll",
            &[
                "DllGetClassObject",
                "HNetCfgGetPublicIndex",
                "HNetCfgGetPrivateIndex",
            ],
        ),
        (
            "ipnathlpclient.dll",
            &[
                "IpNatHlpStartSharing",
                "IpNatHlpStopSharing",
                "IpNatHlpUpdateSharingSettingsFromStorage",
            ],
        ),
        (
            "iphlpapi.dll",
            &["ConvertInterfaceGuidToLuid", "ConvertInterfaceLuidToIndex"],
        ),
        ("ole32.dll", &["CoCreateInstance"]),
        (
            "kernel32.dll",
            &["LoadLibraryExW", "GetProcAddress", "FreeLibrary"],
        ),
    ];
    let mut success = true;
    for &(name, exports) in libraries {
        let path = system.join(name);
        println!("Checking {}", path.display());
        let result = (|| -> Result<()> {
            let mut image = Image::read(&path)?;
            println!("  PASS: AMD64 PE DLL; SHA-256={}", image.hash);
            image.require_exports(exports)?;
            if name == "hnetcfgclient.dll" {
                let resolved = image.scan()?;
                if !resolved {
                    success = false;
                    println!(
                        "  FAIL: private ICS signatures are missing, ambiguous, or outside function boundaries."
                    );
                }
                if !image.verified() {
                    success = false;
                    println!("  FAIL: runtime ABI not reviewed for this DLL build.");
                } else {
                    println!("  PASS: reviewed private ICS ABI.");
                }
                validate_registration(&path)?;
                println!("  PASS: COM registration points to this System32 DLL.");
            }
            Ok(())
        })();
        if let Err(error) = result {
            success = false;
            println!("  FAIL: {error:#}");
        }
    }
    println!(
        "System32 library checks {}.",
        if success { "passed" } else { "failed" }
    );
    Ok(success)
}

struct Binding<'a> {
    image: &'a Image,
    module: Module,
    _file: std::fs::File,
}
impl Binding<'_> {
    fn open<'a>(path: &Path, image: &'a Image) -> Result<Binding<'a>> {
        image.require_verified()?;
        validate_registration(path)?;
        // Hold a read handle denying writes/deletion until all calls and COM releases finish.
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(path)?;
        ensure!(
            Image::read(path)?.hash == image.hash,
            "DLL changed after scanning"
        );
        let encoded = wide(path)?;
        Ok(Binding {
            image,
            module: Module(unsafe {
                LoadLibraryExW(
                    PCWSTR(encoded.as_ptr()),
                    None,
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )?
            }),
            _file: file,
        })
    }

    fn indexes(&self) -> Result<(u32, u32)> {
        Ok((self.index(true)?, self.index(false)?))
    }

    fn disable(&self, settings: &ComObject) -> Result<()> {
        let disable: Disable =
            unsafe { std::mem::transmute(self.address("DisableIcs", settings)?) };
        let (mut public_count, mut private_count) = (0, 0);
        check(
            unsafe { disable(settings.0, &mut public_count, &mut private_count) },
            "DisableIcs",
        )?;
        println!(
            "Visited public={public_count}, private={private_count}; counts do not prove removal."
        );
        Ok(())
    }

    fn address(&self, name: &str, object: &ComObject) -> Result<*const c_void> {
        ensure!(!object.0.is_null(), "Null interface for {name}");
        // Objects come only from the hash-gated in-process COM implementation.
        // Read only the public IUnknown vtable pointer, never private slots.
        let table = unsafe { *object.0.cast::<usize>() };
        let base = self.module.0.0 as usize;
        ensure!(
            table
                .checked_sub(base)
                .is_some_and(|rva| self.image.readable_data_rva(rva)),
            "Unexpected/proxied interface implementation for {name}"
        );
        let (rva, signature) = self.image.method(name)?;
        let address = base
            .checked_add(rva as usize)
            .context("Loaded address overflow")? as *const u8;
        // The reviewed DLL remains loaded for this binding's entire lifetime.
        let loaded = unsafe { std::slice::from_raw_parts(address, signature.len()) };
        if !matches(loaded, &signature) {
            return Err(IcsSignatureMismatch {
                sha256: self.image.hash.clone(),
                reason: IcsMismatchReason::LoadedCodeMismatch,
            }
            .into());
        }
        Ok(address.cast())
    }

    fn index(&self, public: bool) -> Result<u32> {
        let (symbol, name) = if public {
            (s!("HNetCfgGetPublicIndex"), "HNetCfgGetPublicIndex")
        } else {
            (s!("HNetCfgGetPrivateIndex"), "HNetCfgGetPrivateIndex")
        };
        let address =
            unsafe { GetProcAddress(self.module.0, symbol) }.context("Missing ICS index export")?;
        let call: GetIndex = unsafe { std::mem::transmute(address) };
        let mut index = 0;
        check(unsafe { call(&mut index) }, name)?;
        Ok(index)
    }

    fn object(&self, name: &str, object: &ComObject, result: &mut ComObject) -> Result<()> {
        let call: GetObject = unsafe { std::mem::transmute(self.address(name, object)?) };
        check(unsafe { call(object.0, &mut result.0) }, name)?;
        ensure!(!result.0.is_null(), "{name} returned null");
        Ok(())
    }

    fn identity(&self, object: &ComObject) -> Result<GUID> {
        struct Memory(*mut c_void);
        impl Drop for Memory {
            fn drop(&mut self) {
                unsafe {
                    CoTaskMemFree(Some(self.0));
                }
            }
        }
        let mut data = Memory(ptr::null_mut());
        let call: GetObject = unsafe { std::mem::transmute(self.address("GetGuid", object)?) };
        check(unsafe { call(object.0, &mut data.0) }, "GetGuid")?;
        ensure!(!data.0.is_null(), "Null GUID");
        Ok(unsafe { ptr::read_unaligned(data.0.cast::<GUID>()) })
    }

    fn rollback(&self, name: &str, role: &ComObject) {
        if role.0.is_null() {
            return;
        }
        let result = (|| -> Result<()> {
            let call: Remove = unsafe { std::mem::transmute(self.address(name, role)?) };
            check(unsafe { call(role.0) }, &format!("Rollback {name}"))
        })();
        if let Err(error) = result {
            eprintln!("Rollback failed: {error:#}");
        }
    }
}

fn sharing_interfaces() -> Result<(ComObject, ComObject)> {
    let root: IUnknown = unsafe { CoCreateInstance(&CLASS, None, CLSCTX_INPROC_SERVER)? };
    let mut manager = ComObject::default();
    check(
        unsafe { root.query(&MANAGER, &mut manager.0) },
        "Query IHNetCfgMgr",
    )?;
    ensure!(!manager.0.is_null(), "Null manager interface");
    let mut settings = ComObject::default();
    // Query on the manager so the same COM identity supplies both interfaces.
    let borrowed = unsafe { std::mem::ManuallyDrop::new(IUnknown::from_raw(manager.0)) };
    check(
        unsafe { borrowed.query(&SETTINGS, &mut settings.0) },
        "Query IHNetIcsSettings",
    )?;
    Ok((manager, settings))
}

pub(crate) fn reviewed_system_image() -> Result<(PathBuf, Image)> {
    let path = system_directory()?.join(ICS_CLIENT_DLL);
    let mut image = Image::read(&path)?;
    let reason = if !image.verified() {
        Some(IcsMismatchReason::UnrecognizedDll)
    } else if !image.scan()? {
        Some(IcsMismatchReason::UnresolvedSignatures)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(IcsSignatureMismatch {
            sha256: image.hash,
            reason,
        }
        .into());
    }
    image.require_exports(&[
        "DllGetClassObject",
        "HNetCfgGetPublicIndex",
        "HNetCfgGetPrivateIndex",
    ])?;
    validate_registration(&path)?;
    Ok((path, image))
}

pub(crate) fn windows_build() -> Option<String> {
    let build = sysinfo::System::kernel_version()
        .ok()?
        .parse::<u32>()
        .ok()?;
    let mut revision = 0u32;
    let mut bytes = size_of::<u32>() as u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            w!("UBR"),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut revision as *mut u32).cast()),
            Some(&mut bytes),
        )
    };
    Some(if result.is_ok() {
        format!("{build}.{revision}")
    } else {
        build.to_string()
    })
}

pub(crate) fn clear_sharing(path: &Path, image: &Image, pair: (GUID, GUID)) -> Result<()> {
    let binding = Binding::open(path, image)?;
    let indexes = binding.indexes()?;
    if indexes.0 == 0 || indexes.1 == 0 {
        return Ok(());
    }

    if (
        network::interface_index(&pair.0).ok(),
        network::interface_index(&pair.1).ok(),
    ) == (Some(indexes.0), Some(indexes.1))
    {
        let (_manager, settings) = sharing_interfaces()?;
        binding.disable(&settings)?;
    }
    Ok(())
}

pub(crate) fn apply(path: &Path, image: &Image, pair: Option<(GUID, GUID)>) -> Result<()> {
    let expected = pair
        .map(|(public, private)| -> Result<_> {
            ensure!(
                public != private && public != GUID::zeroed() && private != GUID::zeroed(),
                "Two distinct, nonempty adapter GUIDs are required"
            );
            Ok((
                network::interface_index(&public)?,
                network::interface_index(&private)?,
            ))
        })
        .transpose()?;
    let binding = Binding::open(path, image)?;
    let (public_index, private_index) = binding.indexes()?;
    println!("Stored interface indexes: public={public_index}, private={private_index}");
    let Some((public, private)) = pair else {
        return Ok(());
    };
    let (manager, settings) = sharing_interfaces()?;
    let mut public_connection = ComObject::default();
    let mut private_connection = ComObject::default();
    let resolve: GetByGuid =
        unsafe { std::mem::transmute(binding.address("GetIHNetConnectionForGuid", &manager)?) };
    check(
        unsafe { resolve(manager.0, &public, 1, 1, &mut public_connection.0) },
        "Resolve public GUID",
    )?;
    check(
        unsafe { resolve(manager.0, &private, 1, 1, &mut private_connection.0) },
        "Resolve private GUID",
    )?;
    ensure!(
        binding.identity(&public_connection)? == public
            && binding.identity(&private_connection)? == private,
        "Resolved adapter identity mismatch"
    );
    binding.disable(&settings)?;
    let mut public_role = ComObject::default();
    let mut private_role = ComObject::default();
    let result = (|| -> Result<()> {
        binding.object("SharePublic", &public_connection, &mut public_role)?;
        binding.object("SharePrivate", &private_connection, &mut private_role)?;
        ensure!(
            Some(binding.indexes()?) == expected,
            "Stored public/private index verification failed"
        );
        Ok(())
    })();
    if let Err(error) = result {
        binding.rollback("RemovePrivate", &private_role);
        binding.rollback("RemovePublic", &public_role);
        return Err(error);
    }
    println!(
        "Stored interface indexes verified. Test internet access from a hotspot client separately."
    );
    Ok(())
}

pub fn run(options: &Options, image: Option<(&Path, &Image)>) -> Result<()> {
    if options.self_test {
        println!("PASS: Windows; x86-64 process.");
        let wifi = match network::check_wifi() {
            Ok(success) => success,
            Err(error) => {
                println!("FAIL: could not inspect Wi-Fi adapters: {error:#}");
                false
            }
        };
        let libraries = library_checks()?;
        ensure!(
            wifi && libraries,
            "Self-test failed. See Wi-Fi and System32 library results above."
        );
        println!("Self-test passed. ICS activation was not tested.");
        return Ok(());
    }
    if options.apply || options.hotspot_tun {
        ensure!(
            unsafe { IsUserAnAdmin() }.as_bool(),
            "Apply/hotspot setup requires an elevated session."
        );
    }
    if options.hotspot_tun {
        ensure!(
            library_checks()?,
            "Installed DLL prerequisites failed; no hotspot settings were changed."
        );
    }
    let _apartment = Apartment::new()?;
    if options.hotspot_tun {
        let tun = network::discover(true, options.public.map(GUID::from_u128))?;
        network::start_hotspot(options.force_restart)?;
        let hotspot = network::discover(false, options.private.map(GUID::from_u128))?;
        ensure!(
            tun.guid != hotspot.guid,
            "TUN and hotspot must be distinct adapters."
        );
        network::configure(&tun, &hotspot)?;
        let path = system_directory()?.join(ICS_CLIENT_DLL);
        let mut image = Image::read(&path)?;
        ensure!(image.scan()?, "Installed signatures no longer resolve");
        apply(&path, &image, Some((tun.guid, hotspot.guid)))?;
        if let Err(error) = network::check_dns(hotspot.index) {
            eprintln!("Warning: Hotspot DNS check did not pass: {error:#}");
        }
        println!(
            "Hotspot/TUN configuration applied. Verify internet access from a connected client; host DNS alone does not verify client routing."
        );
    } else {
        let (path, image) = image.context("Missing scanned image")?;
        let path = path.canonicalize()?;
        let pair = if options.apply {
            Some((
                GUID::from_u128(options.public.context("Missing public GUID")?),
                GUID::from_u128(options.private.context("Missing private GUID")?),
            ))
        } else {
            None
        };
        apply(&path, image, pair)?;
    }
    Ok(())
}
