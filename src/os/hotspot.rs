use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IcsMismatchReason {
    UnrecognizedDll,
    UnresolvedSignatures,
    LoadedCodeMismatch,
}

#[cfg(any(windows, test))]
pub(crate) const ICS_CLIENT_DLL: &str = "hnetcfgclient.dll";

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Error)]
#[error("hnetcfgclient.dll signature verification failed ({reason:?})")]
pub(crate) struct IcsSignatureMismatch {
    pub sha256: String,
    pub reason: IcsMismatchReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterKind {
    Ethernet,
    WiFi,
    Tun,
    Loopback,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub id: String,
    pub name: String,
    #[cfg(windows)]
    #[serde(default)]
    pub description: String,
    #[cfg(windows)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv4_addresses: Vec<std::net::Ipv4Addr>,
    pub kind: AdapterKind,
    pub is_up: bool,
    pub has_ip_address: bool,
    pub has_default_route: bool,
    pub supports_hotspot: bool,
    /// This Wi-Fi device is currently associated with an access point as a
    /// station. Taking such a device over for AP mode drops that association.
    #[serde(default)]
    pub is_associated_station: bool,
    /// Operating frequency of the current station association, in MHz. An AP
    /// hosted on the same radio must use this same channel.
    #[serde(default)]
    pub station_frequency_mhz: Option<u32>,
    /// mac80211 phy this interface belongs to (e.g. "phy0"), used to create a
    /// second AP virtual interface on the same radio.
    #[serde(default)]
    pub phy: Option<String>,
}

/// What the machine currently has to share, in the terms the interface speaks.
///
/// A phone put into USB-modem mode appears to Linux as an ordinary Ethernet
/// device, so "wired" here covers both a real cable and a tethered phone —
/// which is exactly the distinction the user does not need to make.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UplinkStatus {
    /// A wired link is present and has an address.
    pub wired_present: bool,
    /// Interface name of that link, for diagnostics only — never shown in the UI.
    pub wired_interface: Option<String>,
    /// The wired link is the machine's route out.
    pub wired_has_internet: bool,
    /// Some non-tunnel interface carries a default route. Used to explain why
    /// the hotspot cannot start rather than merely greying the button out.
    pub any_uplink: bool,
}

impl UplinkStatus {
    pub fn from_adapters(adapters: &[NetworkAdapter]) -> Self {
        // Prefer a wired link that actually routes; fall back to one that is
        // merely up so the UI can say "connected, waiting for internet".
        let wired = |routing: bool| {
            adapters.iter().find(|adapter| {
                adapter.kind == AdapterKind::Ethernet
                    && adapter.is_up
                    && adapter.has_ip_address
                    && (!routing || adapter.has_default_route)
            })
        };
        let wired = wired(true).or_else(|| wired(false));

        let any_uplink = adapters.iter().any(|adapter| {
            adapter.has_default_route
                && adapter.kind != AdapterKind::Loopback
                && adapter.kind != AdapterKind::Tun
        });

        Self {
            wired_present: wired.is_some(),
            wired_interface: wired.map(|adapter| adapter.name.clone()),
            wired_has_internet: wired.is_some_and(|adapter| adapter.has_default_route),
            any_uplink,
        }
    }
}

impl NetworkAdapter {
    pub fn eligible_private_adapter(&self) -> bool {
        self.kind == AdapterKind::WiFi
    }

    pub fn eligible_public_adapter(&self) -> bool {
        self.is_up && self.kind == AdapterKind::Tun
    }

    pub fn physical_wifi_adapter(&self) -> bool {
        self.kind == AdapterKind::WiFi
    }
}

fn validate_credentials(ssid: &str, passphrase: &str) -> Result<(), CredentialError> {
    // 802.11 caps the SSID at 32 OCTETS, not characters. `str::len()` is already
    // bytes, which is the same unit the frontend must use — a Cyrillic letter
    // costs two, so a character count would promise more than the radio accepts.
    if ssid.is_empty() {
        return Err(CredentialError::SsidEmpty);
    }
    if ssid.len() > 32 {
        return Err(CredentialError::SsidTooLong { bytes: ssid.len() });
    }
    if ssid.chars().any(char::is_control) {
        return Err(CredentialError::SsidHasControlCharacters);
    }
    if passphrase.len() < 8 {
        return Err(CredentialError::PassphraseTooShort {
            bytes: passphrase.len(),
        });
    }
    if passphrase.len() > 63 {
        return Err(CredentialError::PassphraseTooLong {
            bytes: passphrase.len(),
        });
    }
    // A WPA-PSK passphrase is defined only over printable ASCII (32..=126).
    // Anything outside that derives a PSK clients compute differently, if they
    // accept it at all — and it is also the route a control character would
    // take. Failing here keeps the error on the settings screen rather than
    // producing a network nobody can join.
    if !passphrase.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(CredentialError::PassphraseNotAscii);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum CredentialError {
    // One variant per rejection, so the text the interface shows names the real
    // cause. These messages are user-visible now, not only log lines, so they say
    // what is wrong and in which unit — the SSID limit is octets, and a Cyrillic
    // letter spends two of them.
    #[error("the hotspot network name is empty")]
    SsidEmpty,
    #[error(
        "the hotspot network name is {bytes} bytes long, and the Wi-Fi standard allows at most 32 (a Cyrillic letter counts as two)"
    )]
    SsidTooLong { bytes: usize },
    #[error(
        "the hotspot network name contains a line break or control character, which is not allowed"
    )]
    SsidHasControlCharacters,
    #[error("the Wi-Fi password is {bytes} bytes long, and WPA2 requires at least 8")]
    PassphraseTooShort { bytes: usize },
    #[error("the Wi-Fi password is {bytes} bytes long, and WPA2 allows at most 63")]
    PassphraseTooLong { bytes: usize },
    #[error(
        "the Wi-Fi password contains characters WPA2 does not support; use only Latin letters, digits and punctuation"
    )]
    PassphraseNotAscii,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WPA-PSK is defined over printable ASCII only; a Cyrillic passphrase
    /// derives a key clients cannot reproduce, so it must fail early and loudly
    /// rather than at association time.
    #[test]
    fn rejects_non_ascii_passphrase() {
        assert!(validate_credentials("MyNet", "пароль123").is_err());
        assert!(validate_credentials("MyNet", "emoji\u{1F600}pass").is_err());
        // The full printable ASCII range stays acceptable.
        assert!(validate_credentials("MyNet", "p@ssw0rd! \"#$%&'()*+,-./:;<=>?").is_ok());
    }

    /// The interface now shows these messages verbatim, so each rejection must
    /// produce its own variant and each message must describe the cause it was
    /// actually returned for. Previously one `InvalidSsid` served three different
    /// problems and claimed all of them were a length violation.
    #[test]
    fn each_rejection_reports_its_own_cause() {
        use std::mem::discriminant;

        // Bound separately: an inline `&"x".repeat(64)` inside the array would
        // rely on temporary lifetime extension to survive the statement.
        let too_long_passphrase = "x".repeat(64);

        let cases: [(&str, &str, CredentialError, &str); 6] = [
            ("", "secret12", CredentialError::SsidEmpty, "empty"),
            (
                "СетьСетьСетьСетьС",
                "secret12",
                CredentialError::SsidTooLong { bytes: 0 },
                "34 bytes",
            ),
            (
                "MyNet\nbridge=br0",
                "secret12",
                CredentialError::SsidHasControlCharacters,
                "control character",
            ),
            (
                "MyNet",
                "short",
                CredentialError::PassphraseTooShort { bytes: 0 },
                "at least 8",
            ),
            (
                "MyNet",
                too_long_passphrase.as_str(),
                CredentialError::PassphraseTooLong { bytes: 0 },
                "at most 63",
            ),
            (
                "MyNet",
                "пароль123",
                CredentialError::PassphraseNotAscii,
                "does not support",
            ),
        ];

        for (ssid, passphrase, expected, needle) in cases {
            let error = validate_credentials(ssid, passphrase)
                .expect_err("these credentials must be rejected");
            assert_eq!(
                discriminant(&error),
                discriminant(&expected),
                "wrong variant for ssid={ssid:?} passphrase={passphrase:?}: got {error}"
            );
            let message = error.to_string();
            assert!(
                message.contains(needle),
                "message for {ssid:?}/{passphrase:?} should mention {needle:?}, got: {message}"
            );
        }
    }

    /// The byte counts are interpolated, so they must be the real measured length
    /// rather than the limit — the person needs to know how far over they are.
    #[test]
    fn length_errors_report_the_measured_size() {
        let seventeen_cyrillic = "СетьСетьСетьСетьС"; // 17 chars, 34 bytes
        let error = validate_credentials(seventeen_cyrillic, "secret12").expect_err("too long");
        assert!(error.to_string().contains("34 bytes"), "got: {error}");

        let error = validate_credentials("MyNet", "short").expect_err("too short");
        assert!(error.to_string().contains("5 bytes"), "got: {error}");
    }
}
