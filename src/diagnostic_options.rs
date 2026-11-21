use anyhow::{Result, bail, ensure};
use std::{ffi::OsString, path::PathBuf};

pub const HELP: &str = "vrghotspot-diagnostics [OPTIONS]
  --scan-only --dll-path PATH   Inspect an AMD64 DLL without loading code
  --self-test                   Check Windows, Wi-Fi, DLLs and COM registration
  --apply --public-guid GUID --private-guid GUID
                                Replace current ICS sharing (requires elevation)
  --hotspot-tun                 Start hotspot, configure TUN and apply ICS
  --force-restart-hotspot       Restart hotspot (requires --hotspot-tun)
  --public-guid / --private-guid override hotspot adapter discovery
  --help                       Show this help
With no mode, inspect installed ICS and print stored interface indexes.
Original PowerShell parameter names (e.g. -ScanOnly) are also accepted.
Apply does not restore the previous sharing pair. Hotspot settings persist.";

#[derive(Debug, Default)]
pub struct Options {
    pub self_test: bool,
    pub scan_only: bool,
    pub apply: bool,
    pub hotspot_tun: bool,
    pub force_restart: bool,
    pub dll_path: Option<PathBuf>,
    pub public: Option<u128>,
    pub private: Option<u128>,
}

pub fn guid(value: &str) -> Result<u128> {
    let value = if value.starts_with('{') && value.ends_with('}') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    ensure!(
        value.len() == 36
            && value.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }),
        "Invalid adapter GUID: {value}"
    );
    let result = u128::from_str_radix(&value.replace('-', ""), 16)?;
    ensure!(result != 0, "Adapter GUIDs must be nonempty.");
    Ok(result)
}

impl Options {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Self>> {
        let mut args = args.into_iter();
        let mut options = Self::default();
        let mut seen = std::collections::HashSet::new();
        while let Some(arg) = args.next() {
            let arg = arg
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid option encoding"))?;
            ensure!(arg.starts_with('-'), "Unexpected argument: {arg}");
            let key = arg
                .trim_start_matches('-')
                .replace('-', "")
                .to_ascii_lowercase();
            ensure!(seen.insert(key.clone()), "Repeated option: {arg}");
            match key.as_str() {
                "help" | "h" | "?" => return Ok(None),
                "selftest" => options.self_test = true,
                "scanonly" => options.scan_only = true,
                "apply" => options.apply = true,
                "hotspottun" => options.hotspot_tun = true,
                "forcerestarthotspot" => options.force_restart = true,
                "dllpath" | "publicguid" | "privateguid" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("{arg} requires a value"))?;
                    ensure!(!value.is_empty(), "{arg} requires a nonempty value");
                    if key == "dllpath" {
                        options.dll_path = Some(value.into());
                    } else {
                        let value = guid(
                            value
                                .to_str()
                                .ok_or_else(|| anyhow::anyhow!("Invalid GUID encoding"))?,
                        )?;
                        if key == "publicguid" {
                            options.public = Some(value);
                        } else {
                            options.private = Some(value);
                        }
                    }
                }
                _ => bail!("Unknown option: {arg}"),
            }
        }
        ensure!(
            !options.self_test || seen.len() == 1,
            "--self-test cannot be combined with other parameters."
        );
        ensure!(
            !options.scan_only || !(options.apply || options.hotspot_tun),
            "--scan-only cannot be combined with --apply or --hotspot-tun."
        );
        ensure!(
            !options.force_restart || options.hotspot_tun,
            "--force-restart-hotspot requires --hotspot-tun."
        );
        ensure!(
            !options.hotspot_tun || options.dll_path.is_none(),
            "--hotspot-tun uses the installed System32 DLL; omit --dll-path."
        );
        ensure!(
            !options.apply
                || options.hotspot_tun
                || (options.public.is_some() && options.private.is_some()),
            "--apply requires both --public-guid and --private-guid."
        );
        ensure!(
            options.public.is_none()
                || options.private.is_none()
                || options.public != options.private,
            "Two distinct adapter GUIDs are required."
        );
        Ok(Some(options))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Option<Options>> {
        Options::parse(args.iter().map(OsString::from))
    }
    #[test]
    fn conflicts_and_missing_values() {
        for args in [
            vec!["--self-test", "--scan-only"],
            vec!["--scan-only", "--apply"],
            vec!["--force-restart-hotspot"],
            vec!["--hotspot-tun", "--dll-path", "x"],
            vec!["--apply"],
            vec!["--dll-path"],
            vec!["--bogus"],
            vec!["--scan-only", "-ScanOnly"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn aliases_and_unicode_paths() {
        let parsed = parse(&["-sCaNoNlY", "-DllPath", "путь.dll"])
            .unwrap()
            .unwrap();
        assert!(parsed.scan_only);
        assert_eq!(parsed.dll_path.unwrap(), PathBuf::from("путь.dll"));
        assert!(parse(&[]).unwrap().is_some());
        assert!(parse(&["--help"]).unwrap().is_none());
    }
    #[test]
    fn validates_guids() {
        assert_eq!(
            guid("{46C166AA-3108-11D4-9348-00C04F8EEB71}").unwrap(),
            0x46c166aa310811d4934800c04f8eeb71
        );
        for value in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "{46C166AA-3108-11D4-9348-00C04F8EEB71",
            "46C166AA3108-11D4-9348-00C04F8EEB71",
        ] {
            assert!(guid(value).is_err());
        }
        assert!(
            parse(&[
                "--apply",
                "--public-guid",
                "46C166AA-3108-11D4-9348-00C04F8EEB71",
                "--private-guid",
                "46c166aa-3108-11d4-9348-00c04f8eeb71"
            ])
            .is_err()
        );
    }
}
