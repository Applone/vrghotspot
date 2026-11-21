use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    net::Ipv4Addr,
    ptr, thread,
    time::{Duration, Instant},
};
use windows::{
    Networking::{
        Connectivity::NetworkInformation,
        NetworkOperators::{
            NetworkOperatorTetheringManager, NetworkOperatorTetheringOperationResult,
            TetheringOperationStatus, TetheringOperationalState,
        },
    },
    Win32::{
        NetworkManagement::{
            Dns::*,
            IpHelper::*,
            Ndis::{IfOperStatusUp, NET_LUID_LH},
        },
        Networking::WinSock::{AF_INET, AF_UNSPEC, IpDadStatePreferred},
        System::{Com::*, Variant::VARIANT, Wmi::*},
    },
    core::{BSTR, GUID, PCWSTR, w},
};
use windows_future::{AsyncStatus, IAsyncOperation};

struct MibMemory(*const c_void);
impl Drop for MibMemory {
    fn drop(&mut self) {
        unsafe {
            FreeMibTable(self.0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Adapter {
    pub guid: GUID,
    pub index: u32,
    pub name: String,
    pub(crate) description: String,
    pub up: bool,
    pub physical_wifi: bool,
    pub interface_type: u32,
}

impl Adapter {
    pub fn is_tun(&self) -> bool {
        let description = self.description.to_ascii_lowercase();
        self.interface_type == IF_TYPE_TUNNEL
            || description.contains("wintun")
            || description.contains("wireguard")
            // The vendored Mihomo core creates its Wintun adapter as "Meta".
            || description.contains("meta tunnel")
    }

    pub(crate) fn is_hotspot(&self) -> bool {
        self.description
            .to_ascii_lowercase()
            .contains("wi-fi direct virtual adapter")
    }
}

fn text(value: &[u16]) -> String {
    String::from_utf16_lossy(&value[..value.iter().position(|&c| c == 0).unwrap_or(value.len())])
}

fn adapter_from_row(row: &MIB_IF_ROW2) -> Option<Adapter> {
    // GetIfTable2 also returns NDIS filter modules with their parent adapter's
    // description. Only the underlying interface can be used for sharing.
    const HARDWARE_INTERFACE: u8 = 1 << 0;
    const FILTER_INTERFACE: u8 = 1 << 1;
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    if flags & FILTER_INTERFACE != 0 {
        return None;
    }
    Some(Adapter {
        guid: row.InterfaceGuid,
        index: row.InterfaceIndex,
        name: text(&row.Alias),
        description: text(&row.Description),
        up: row.OperStatus == IfOperStatusUp,
        interface_type: row.Type,
        physical_wifi: flags & HARDWARE_INTERFACE != 0 && matches!(row.PhysicalMediumType.0, 1 | 9),
    })
}

pub(crate) fn adapters() -> Result<Vec<Adapter>> {
    let mut table = ptr::null_mut();
    unsafe {
        GetIfTable2(&mut table).ok()?;
    }
    ensure!(!table.is_null(), "GetIfTable2 returned a null table");
    let _memory = MibMemory(table.cast());
    // Windows supplies NumEntries contiguous rows starting at Table, including ABI padding.
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    Ok(rows.iter().filter_map(adapter_from_row).collect())
}

pub(crate) fn addresses() -> Result<HashSet<u32>> {
    let mut table = ptr::null_mut();
    unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table).ok()? };
    ensure!(
        !table.is_null(),
        "GetUnicastIpAddressTable returned a null table"
    );
    let _memory = MibMemory(table.cast());
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            (*table).NumEntries as usize,
        )
    };
    Ok(rows
        .iter()
        .filter(|row| row.DadState == IpDadStatePreferred)
        .map(|row| row.InterfaceIndex)
        .collect())
}

pub(crate) fn default_routes() -> Result<HashSet<u32>> {
    let mut table = ptr::null_mut();
    unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table).ok()? };
    ensure!(!table.is_null(), "GetIpForwardTable2 returned a null table");
    let _memory = MibMemory(table.cast());
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    Ok(rows
        .iter()
        .filter(|row| !row.Loopback && row.DestinationPrefix.PrefixLength == 0)
        .map(|row| row.InterfaceIndex)
        .collect())
}

pub fn check_wifi() -> Result<bool> {
    let wifi: Vec<_> = adapters()?
        .into_iter()
        .filter(|a| a.physical_wifi)
        .collect();
    for adapter in &wifi {
        println!(
            "PASS: physical Wi-Fi adapter '{}' ({}); up={}.",
            adapter.name, adapter.description, adapter.up
        );
    }
    if wifi.is_empty() {
        println!("FAIL: no physical Wi-Fi adapter was found.");
    }
    Ok(!wifi.is_empty())
}

pub fn interface_index(guid: &GUID) -> Result<u32> {
    let mut luid = NET_LUID_LH::default();
    let mut index = 0;
    println!("Resolving adapter: GUID={guid:?}");
    unsafe {
        ConvertInterfaceGuidToLuid(guid, &mut luid)
            .ok()
            .context("ConvertInterfaceGuidToLuid")?;
        ConvertInterfaceLuidToIndex(&luid, &mut index)
            .ok()
            .context("ConvertInterfaceLuidToIndex")?;
    }
    println!("Interface index: {index}");
    Ok(index)
}

pub fn discover(tun: bool, guid: Option<GUID>) -> Result<Adapter> {
    let role = if tun { "TUN" } else { "Hotspot" };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut found: Vec<_> = adapters()?
            .into_iter()
            .filter(|a| {
                a.up && match guid {
                    Some(guid) => guid == a.guid,
                    None if tun => {
                        a.description.to_lowercase().contains("wintun")
                            || a.name.to_lowercase().contains("tun")
                    }
                    None => a.is_hotspot(),
                }
            })
            .collect();
        ensure!(
            found.len() <= 1,
            "Multiple active {role} adapters found ({}); specify --{}-guid.",
            found
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            if tun { "public" } else { "private" }
        );
        if let Some(adapter) = found.pop() {
            return Ok(adapter);
        }
        ensure!(
            Instant::now() < deadline,
            "No active {role} adapter found. Start the TUN client or check the hotspot and supplied GUID."
        );
        thread::sleep(Duration::from_millis(500));
    }
}

pub(crate) fn wait(
    operation: IAsyncOperation<NetworkOperatorTetheringOperationResult>,
    name: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while operation.Status()? == AsyncStatus::Started {
        if Instant::now() >= deadline {
            let _ = operation.Cancel();
            bail!("{name} timed out after 30 seconds; check the Windows Mobile Hotspot state");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let result = operation.GetResults()?;
    ensure!(
        result.Status()? == TetheringOperationStatus::Success,
        "{name} failed: {:?}; {}",
        result.Status()?,
        result.AdditionalErrorMessage()?
    );
    println!("{name}: Success");
    Ok(())
}

fn ipv4_interface(guid: &GUID) -> Result<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
        row.Family = AF_INET;
        ConvertInterfaceGuidToLuid(guid, &mut row.InterfaceLuid)
            .ok()
            .context("ConvertInterfaceGuidToLuid")?;
        GetIpInterfaceEntry(&mut row)
            .ok()
            .context("GetIpInterfaceEntry")?;
    }
    Ok(row)
}

pub(crate) struct ForwardingSettings {
    guid: GUID,
    forwarding: bool,
    dad_transmits: Option<u32>,
}

impl ForwardingSettings {
    pub(crate) fn enable(adapter: &Adapter, enable_dad_override: bool) -> Result<Self> {
        let row = ipv4_interface(&adapter.guid)
            .with_context(|| format!("Reading IPv4 interface {}", adapter.name))?;
        ensure!(
            row.InterfaceIndex == adapter.index,
            "Adapter index changed during setup"
        );
        let mut original = Self {
            guid: adapter.guid,
            forwarding: row.ForwardingEnabled,
            dad_transmits: enable_dad_override.then_some(row.DadTransmits),
        };
        let mut update = with_ipv4_forwarding(row, true, enable_dad_override.then_some(0));
        let configured = (|| -> Result<()> {
            unsafe { SetIpInterfaceEntry(&mut update).ok() }
                .with_context(|| format!("SetIpInterfaceEntry for {}", adapter.name))?;
            let row = ipv4_interface(&adapter.guid)
                .with_context(|| format!("Verifying IPv4 interface {}", adapter.name))?;
            ensure!(
                row.ForwardingEnabled && (!enable_dad_override || row.DadTransmits == 0),
                "IPv4 forwarding setup could not be verified for {}",
                adapter.name
            );
            Ok(())
        })();
        if let Err(error) = configured {
            original.restore();
            return Err(error);
        }
        Ok(original)
    }

    pub(crate) fn restore(&mut self) {
        // The Wi-Fi Direct interface can already have disappeared if Windows
        // stopped Mobile Hotspot outside the app.
        if let Ok(row) = ipv4_interface(&self.guid) {
            let mut update = with_ipv4_forwarding(row, self.forwarding, self.dad_transmits);
            if let Err(err) = unsafe { SetIpInterfaceEntry(&mut update).ok() } {
                tracing::warn!(error = %err, interface_index = row.InterfaceIndex, "could not restore IPv4 forwarding settings");
            }
        }
    }
}

fn with_ipv4_forwarding(
    mut row: MIB_IPINTERFACE_ROW,
    enabled: bool,
    dad_transmits: Option<u32>,
) -> MIB_IPINTERFACE_ROW {
    // SetIpInterfaceEntry requires zero for IPv4, even when the getter reports
    // a different value.
    row.SitePrefixLength = 0;
    row.ForwardingEnabled = enabled;
    if let Some(value) = dad_transmits {
        row.DadTransmits = value;
    }
    row
}

pub fn start_hotspot(force_restart: bool) -> Result<()> {
    let profile = NetworkInformation::GetInternetConnectionProfile()
        .context("No Internet connection profile is available to start Mobile Hotspot")?;
    let manager = NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile)?;
    let mut state = manager.TetheringOperationalState()?;
    ensure!(
        state == TetheringOperationalState::On || state == TetheringOperationalState::Off,
        "Hotspot state is {state:?}; wait for it to settle before retrying."
    );
    if force_restart && state == TetheringOperationalState::On {
        wait(manager.StopTetheringAsync()?, "Stop hotspot")?;
        state = TetheringOperationalState::Off;
    }
    if state == TetheringOperationalState::Off {
        wait(manager.StartTetheringAsync()?, "Start hotspot")?;
    } else {
        println!("Hotspot is already on.");
    }
    NetworkOperatorTetheringManager::DisableNoConnectionsTimeout()?;
    println!("Hotspot idle timeout disabled.");
    Ok(())
}

fn cim() -> Result<IWbemServices> {
    // WMI uses the caller's elevated token; no credentials or shell subprocesses.
    unsafe {
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let service = locator.ConnectServer(
            &BSTR::from("ROOT\\StandardCimv2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )?;
        CoSetProxyBlanket(
            &service,
            10,
            0,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )?;
        Ok(service)
    }
}

fn interface(
    service: &IWbemServices,
    index: u32,
    context: Option<&IWbemContext>,
) -> Result<IWbemClassObject> {
    let query = BSTR::from(format!(
        "SELECT * FROM MSFT_NetIPInterface WHERE InterfaceIndex = {index} AND AddressFamily = 2"
    ));
    let enumeration = unsafe {
        service.ExecQuery(
            &BSTR::from("WQL"),
            &query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            context,
        )?
    };
    let mut objects = [None, None];
    let mut count = 0;
    // A finite wait prevents an unresponsive provider from hanging setup indefinitely.
    let hr = unsafe { enumeration.Next(15000, &mut objects, &mut count) };
    hr.ok()?;
    ensure!(
        hr.0 != WBEM_S_TIMEDOUT.0,
        "Timed out querying IPv4 interface {index}"
    );
    ensure!(
        count == 1,
        "Expected one IPv4 interface for index {index}, found {count}"
    );
    objects[0].take().context("CIM returned a null interface")
}

fn property(object: &IWbemClassObject, name: PCWSTR) -> Result<u32> {
    let mut value = VARIANT::default();
    unsafe {
        object.Get(name, 0, &mut value, None, None)?;
    }
    Ok(u32::try_from(&value)?)
}

pub fn configure(tun: &Adapter, hotspot: &Adapter) -> Result<()> {
    let service = cim()?;
    for (adapter, is_tun) in [(hotspot, false), (tun, true)] {
        // Re-resolve the GUID so an interface index recycled during hotspot startup
        // cannot silently configure another adapter.
        ensure!(
            interface_index(&adapter.guid)? == adapter.index,
            "Adapter index changed during setup"
        );
        println!(
            "Adapter: {}; index={}; GUID={:?}",
            adapter.name, adapter.index, adapter.guid
        );
        let object = interface(&service, adapter.index, None)?;
        let (name, value) = if is_tun {
            (w!("NlMtu"), 1420u32)
        } else {
            (w!("DadTransmits"), 0u32)
        };
        unsafe {
            object.Put(w!("Forwarding"), 0, &VARIANT::from(1u8), 0)?;
            // CIM uint32 maps to VT_I4 in the WMI COM API.
            object.Put(name, 0, &VARIANT::from(value as i32), 0)?;
            service.PutInstance(
                &object,
                WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_UPDATE_ONLY.0),
                None,
                None,
            )?;
        }
        // The provider's default write policy targets both stores, as with
        // Set-NetIPInterface without -PolicyStore. Verify both before applying ICS.
        for store in ["ActiveStore", "PersistentStore"] {
            let context: IWbemContext =
                unsafe { CoCreateInstance(&WbemContext, None, CLSCTX_INPROC_SERVER)? };
            unsafe {
                context.SetValue(w!("PolicyStore"), 0, &VARIANT::from(store))?;
            }
            let updated = interface(&service, adapter.index, Some(&context))?;
            let expected_store = u32::from(store == "ActiveStore");
            ensure!(
                property(&updated, w!("Store"))? == expected_store,
                "CIM provider did not return requested {store}"
            );
            ensure!(
                property(&updated, w!("Forwarding"))? == 1 && property(&updated, name)? == value,
                "Interface settings verification failed for {} in {store}",
                adapter.name
            );
        }
    }
    println!(
        "IPv4 forwarding enabled, hotspot DAD disabled, and TUN MTU set to 1420 in active and persistent stores."
    );
    Ok(())
}

pub(crate) fn ipv4_addresses() -> Result<HashMap<u32, Vec<Ipv4Addr>>> {
    let mut table = ptr::null_mut();
    unsafe {
        GetUnicastIpAddressTable(AF_INET, &mut table).ok()?;
    }
    ensure!(!table.is_null(), "Null address table");
    let _memory = MibMemory(table.cast());
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            (*table).NumEntries as usize,
        )
    };
    let mut addresses = HashMap::<_, Vec<_>>::new();
    for row in rows
        .iter()
        .filter(|row| row.DadState == IpDadStatePreferred)
    {
        let address =
            Ipv4Addr::from(unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
        if !address.is_link_local() {
            addresses
                .entry(row.InterfaceIndex)
                .or_default()
                .push(address);
        }
    }
    Ok(addresses)
}

pub fn check_dns(index: u32) -> Result<()> {
    let addresses = ipv4_addresses()?.remove(&index).unwrap_or_default();
    ensure!(
        addresses.len() == 1,
        "Could not determine a unique hotspot gateway IPv4 address."
    );
    let gateway = addresses[0];
    let address = u32::from_ne_bytes(gateway.octets());
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // DnsQuery_W owns all query buffers on this worker. On timeout it can finish
    // independently without retaining references to the caller's address table.
    thread::Builder::new()
        .name("hotspot-dns".into())
        .spawn(move || {
            let _ = sender.send(dns_answers(address));
        })?;
    let answers = receiver
        .recv_timeout(Duration::from_secs(5))
        .context("Gateway DNS query did not complete within five seconds")??;
    println!(
        "DNS query through {gateway} returned: {}",
        answers.join(", ")
    );
    Ok(())
}

fn dns_answers(address: u32) -> Result<Vec<String>> {
    let mut servers = IP4_ARRAY {
        AddrCount: 1,
        AddrArray: [address],
    };
    struct Records(*mut DNS_RECORDA);
    impl Drop for Records {
        fn drop(&mut self) {
            unsafe {
                DnsFree(Some(self.0.cast()), DnsFreeRecordList);
            }
        }
    }
    let mut records = Records(ptr::null_mut());
    unsafe {
        DnsQuery_W(
            w!("google.com"),
            DNS_TYPE_A,
            DNS_QUERY_BYPASS_CACHE
                | DNS_QUERY_NO_HOSTS_FILE
                | DNS_QUERY_NO_NETBT
                | DNS_QUERY_NO_MULTICAST,
            Some(ptr::from_mut(&mut servers).cast()),
            &mut records.0,
            None,
        )
        .ok()?;
    }
    let mut current = records.0;
    let mut answers = Vec::new();
    while !current.is_null() {
        // The DNS API owns a valid linked list until Records is dropped.
        let record = unsafe { &*current };
        if record.wType == DNS_TYPE_A.0 {
            answers
                .push(Ipv4Addr::from(unsafe { record.Data.A.IpAddress }.to_ne_bytes()).to_string());
        }
        current = record.pNext;
    }
    if answers.is_empty() {
        bail!("The gateway returned no IPv4 DNS answers.");
    }
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_filter_modules_do_not_duplicate_a_wifi_direct_adapter() {
        let mut hotspot = MIB_IF_ROW2 {
            InterfaceGuid: GUID::from_u128(15),
            OperStatus: IfOperStatusUp,
            ..Default::default()
        };
        for (slot, unit) in hotspot
            .Description
            .iter_mut()
            .zip("Microsoft Wi-Fi Direct Virtual Adapter #15".encode_utf16())
        {
            *slot = unit;
        }
        let mut filter = hotspot;
        filter.InterfaceGuid = GUID::from_u128(16);
        filter.InterfaceAndOperStatusFlags._bitfield = 0b0000_0110; // FilterInterface and ConnectorPresent
        let second_hotspot = MIB_IF_ROW2 {
            InterfaceGuid: GUID::from_u128(17),
            ..hotspot
        };
        let active = |rows: &[MIB_IF_ROW2]| {
            rows.iter()
                .filter_map(adapter_from_row)
                .filter(|adapter| adapter.up && adapter.is_hotspot())
                .map(|adapter| adapter.guid)
                .collect::<Vec<_>>()
        };
        assert_eq!(active(&[filter, hotspot]), [hotspot.InterfaceGuid]);
        assert_eq!(
            active(&[hotspot, filter, second_hotspot]),
            [hotspot.InterfaceGuid, second_hotspot.InterfaceGuid]
        );
    }

    #[test]
    fn forwarding_updates_clear_the_ipv4_site_prefix_length() {
        let row = MIB_IPINTERFACE_ROW {
            SitePrefixLength: 255,
            InterfaceIndex: 14,
            DadTransmits: 3,
            NlMtu: 1420,
            ..Default::default()
        };

        let enabled = with_ipv4_forwarding(row, true, None);
        assert_eq!(enabled.SitePrefixLength, 0);
        assert_eq!(enabled.InterfaceIndex, 14);
        assert_eq!(enabled.NlMtu, 1420);
        assert_eq!(enabled.DadTransmits, 3);
        assert!(enabled.ForwardingEnabled);

        let restored = with_ipv4_forwarding(row, false, Some(0));
        assert_eq!(restored.SitePrefixLength, 0);
        assert_eq!(restored.DadTransmits, 0);
        assert!(!restored.ForwardingEnabled);
    }

    #[test]
    fn identifies_mihomos_wintun_under_its_windows_driver_description() {
        let mut adapter = Adapter {
            guid: GUID::zeroed(),
            index: 1,
            name: crate::core::config::TUN_DEVICE_NAME.to_owned(),
            description: "Meta Tunnel".to_owned(),
            up: true,
            physical_wifi: false,
            interface_type: IF_TYPE_PROP_VIRTUAL,
        };
        assert!(adapter.is_tun());
        adapter.description = "Microsoft Wi-Fi Direct Virtual Adapter #2".to_owned();
        assert!(!adapter.is_tun());
        assert!(adapter.is_hotspot());
    }
}
