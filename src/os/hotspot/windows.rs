use super::{AdapterKind, CredentialError, NetworkAdapter, UplinkStatus, validate_credentials};
use crate::core::config::TUN_DEVICE_NAME;
use crate::native::{self, Apartment, network};
use crate::pe::Image;
use anyhow::{Context, Result, ensure};
use std::collections::HashSet;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use windows::{
    Networking::{
        Connectivity::{ConnectionProfile, NetworkInformation},
        NetworkOperators::{NetworkOperatorTetheringManager, TetheringOperationalState},
    },
    Win32::{
        NetworkManagement::IpHelper::{IF_TYPE_ETHERNET_CSMACD, IF_TYPE_SOFTWARE_LOOPBACK},
        UI::{
            Shell::{IsUserAnAdmin, ShellExecuteW},
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    },
    core::{AgileReference, GUID, HSTRING, PCWSTR, w},
};
use windows_future::AsyncStatus;

pub struct HotspotController;

impl HotspotController {
    pub fn system() -> Self {
        Self
    }

    pub fn enumerate_all(&self) -> Result<Vec<NetworkAdapter>, HotspotError> {
        let addresses = network::addresses()?;
        let routes = network::default_routes()?;
        Ok(network::adapters()?
            .iter()
            .map(|adapter| {
                let mut result = adapter_info(adapter);
                result.has_ip_address = addresses.contains(&adapter.index);
                result.has_default_route = routes.contains(&adapter.index);
                result.is_associated_station =
                    adapter.physical_wifi && adapter.up && result.has_ip_address;
                result
            })
            .collect())
    }

    pub fn eligible_wifi_adapters(&self) -> Result<Vec<NetworkAdapter>, HotspotError> {
        let mut adapters = self.enumerate_all()?;
        adapters.retain(NetworkAdapter::eligible_private_adapter);
        adapters.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(adapters)
    }

    pub fn hotspot_adapters(&self) -> Result<Vec<NetworkAdapter>, HotspotError> {
        // The target-adapter overload requires a WinRT NetworkAdapter from a
        // connection profile. A disconnected radio may have no such profile.
        let mut radios = HashSet::new();
        if let Ok(_apartment) = Apartment::new()
            && let Ok(profiles) = NetworkInformation::GetConnectionProfiles()
        {
            radios.extend(
                profiles
                    .into_iter()
                    .chain(NetworkInformation::GetInternetConnectionProfile())
                    .filter_map(|profile| profile.NetworkAdapter().ok()?.NetworkAdapterId().ok()),
            );
        }
        let mut addresses = network::ipv4_addresses().unwrap_or_default();
        Ok(network::adapters()?
            .iter()
            .filter(|adapter| {
                adapter.is_hotspot() || (adapter.physical_wifi && radios.contains(&adapter.guid))
            })
            .map(|adapter| {
                let mut info = adapter_info(adapter);
                if adapter.is_hotspot() && adapter.up {
                    info.ipv4_addresses = addresses.remove(&adapter.index).unwrap_or_default();
                }
                info
            })
            .collect())
    }

    pub fn uplink_status(&self) -> Result<UplinkStatus, HotspotError> {
        Ok(UplinkStatus::from_adapters(&self.enumerate_all()?))
    }

    pub fn has_physical_wifi_adapter(&self) -> Result<bool, HotspotError> {
        Ok(network::adapters()?
            .iter()
            .any(|adapter| adapter.physical_wifi))
    }

    pub fn prepare_tunnel_routing(&self) -> Result<TunnelRoutingSession, HotspotError> {
        if !unsafe { IsUserAnAdmin() }.as_bool() {
            return Err(HotspotError::ElevationRequired);
        }
        let _apartment = Apartment::new()?;
        // Capture the physical uplink before Mihomo installs the Wintun routes.
        // A missing profile still permits local VPN startup.
        Ok(TunnelRoutingSession {
            uplink: NetworkInformation::GetInternetConnectionProfile(),
        })
    }
}

pub fn launch_elevated() -> Result<bool> {
    if unsafe { IsUserAnAdmin() }.as_bool() {
        return Ok(false);
    }
    let executable = native::wide(&std::env::current_exe()?)?;
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR(executable.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    ensure!(
        result.0 as isize > 32,
        "Windows did not start the elevated application"
    );
    Ok(true)
}

pub fn tunnel_device_present() -> bool {
    find_app_tun().is_ok_and(|adapter| adapter.is_some())
}

fn find_app_tun() -> Result<Option<network::Adapter>> {
    Ok(network::adapters()?.into_iter().find(|adapter| {
        adapter.up && adapter.is_tun() && adapter.name.eq_ignore_ascii_case(TUN_DEVICE_NAME)
    }))
}

fn adapter_info(adapter: &network::Adapter) -> NetworkAdapter {
    let kind = if adapter.physical_wifi {
        AdapterKind::WiFi
    } else if adapter.is_tun() {
        AdapterKind::Tun
    } else {
        match adapter.interface_type {
            IF_TYPE_ETHERNET_CSMACD => AdapterKind::Ethernet,
            IF_TYPE_SOFTWARE_LOOPBACK => AdapterKind::Loopback,
            _ => AdapterKind::Other,
        }
    };
    NetworkAdapter {
        id: format!("{:?}", adapter.guid),
        name: adapter.name.clone(),
        description: adapter.description.clone(),
        ipv4_addresses: Vec::new(),
        kind,
        is_up: adapter.up,
        has_ip_address: false,
        has_default_route: false,
        supports_hotspot: adapter.physical_wifi,
        is_associated_station: false,
        station_frequency_mhz: None,
        phy: None,
    }
}

pub struct TunnelRoutingSession {
    uplink: windows::core::Result<ConnectionProfile>,
}

impl TunnelRoutingSession {
    pub fn enable_sharing(
        &self,
        selected: Option<&str>,
        ssid: &str,
        passphrase: &str,
    ) -> Result<SharingSession, HotspotError> {
        validate_credentials(ssid, passphrase)?;
        let _apartment = Apartment::new()?;
        let tun = find_app_tun()?.ok_or(HotspotError::NoTunInterface)?;
        let uplink = self.uplink.clone().context(
            "no Windows internet connection profile was available before starting the VPN",
        )?;
        let profile_adapter = uplink
            .NetworkAdapter()
            .context("Windows uplink has no network adapter")?;
        if profile_adapter
            .NetworkAdapterId()
            .context("could not identify Windows uplink")?
            == tun.guid
        {
            return Err(anyhow::anyhow!(
                "Windows Mobile Hotspot requires a physical uplink profile"
            )
            .into());
        }

        let selected = selected
            .map(|id| {
                GUID::try_from(id).map_err(|_| HotspotError::InvalidHotspotAdapter(id.to_owned()))
            })
            .transpose()?;
        let adapters = network::adapters()?;
        // Existing settings can specify a physical Wi-Fi radio. A Wi-Fi Direct
        // selection is used after Mobile Hotspot starts, when Windows brings it up.
        let physical = selected.filter(|id| {
            adapters
                .iter()
                .any(|adapter| adapter.physical_wifi && adapter.guid == *id)
        });
        let private = selected.filter(|_| physical.is_none());
        let manager = if let Some(radio) = physical {
            let profiles = NetworkInformation::GetConnectionProfiles()
                .context("could not read Windows connection profiles")?;
            let target = std::iter::once(profile_adapter)
                .chain(
                    profiles
                        .into_iter()
                        .filter_map(|profile| profile.NetworkAdapter().ok()),
                )
                .find(|adapter| adapter.NetworkAdapterId().is_ok_and(|id| id == radio))
                .context("the selected Wi-Fi adapter has no Windows connection profile")?;
            NetworkOperatorTetheringManager::CreateFromConnectionProfileWithTargetAdapter(
                &uplink, &target,
            )
        } else {
            NetworkOperatorTetheringManager::CreateFromConnectionProfile(&uplink)
        }
        .context("could not create the Windows Mobile Hotspot manager")?;

        if manager
            .TetheringOperationalState()
            .context("could not query Mobile Hotspot state")?
            != TetheringOperationalState::Off
        {
            return Err(anyhow::anyhow!(
                "turn off Windows Mobile Hotspot before starting sharing with VRG Hotspot"
            )
            .into());
        }

        // Validate the installed private ABI before enabling a network that would
        // otherwise share the physical uplink directly.
        let (path, image) =
            native::reviewed_system_image().context("Windows ICS prerequisite check failed")?;
        let config = manager
            .GetCurrentAccessPointConfiguration()
            .context("could not read Windows Mobile Hotspot credentials")?;
        let mut hotspot = MobileHotspot {
            manager: AgileReference::new(&manager)
                .context("could not retain the Mobile Hotspot manager")?,
            path,
            image,
            original_credentials: Some((
                config
                    .Ssid()
                    .context("could not read Windows Mobile Hotspot SSID")?,
                config
                    .Passphrase()
                    .context("could not read Windows Mobile Hotspot passphrase")?,
            )),
            started: false,
            restore_timeout: false,
            pair: None,
            forwarding: Vec::new(),
        };

        set_credentials(&manager, &HSTRING::from(ssid), &HSTRING::from(passphrase))?;
        let previously_active = network::adapters()?
            .into_iter()
            .filter(|adapter| adapter.up && adapter.is_hotspot())
            .map(|adapter| adapter.guid)
            .collect();
        let operation = manager
            .StartTetheringAsync()
            .context("could not start Windows Mobile Hotspot")?;
        hotspot.started = true;
        network::wait(operation, "Start Windows Mobile Hotspot")?;
        if NetworkOperatorTetheringManager::IsNoConnectionsTimeoutEnabled()
            .context("could not read the Windows Mobile Hotspot idle timeout")?
        {
            NetworkOperatorTetheringManager::DisableNoConnectionsTimeout()
                .context("could not disable the Windows Mobile Hotspot idle timeout")?;
            hotspot.restore_timeout = true;
        }

        let wifi = wait_for_hotspot_adapter(private, &previously_active)?;
        hotspot
            .forwarding
            .push(network::ForwardingSettings::enable(&tun, false)?);
        hotspot
            .forwarding
            .push(network::ForwardingSettings::enable(&wifi, true)?);
        let pair = (tun.guid, wifi.guid);
        native::apply(&hotspot.path, &hotspot.image, Some(pair))
            .context("could not share the Mihomo tunnel over Windows Mobile Hotspot")?;
        hotspot.pair = Some(pair);

        if let Err(error) = network::check_dns(wifi.index) {
            tracing::warn!(%error, "Windows Mobile Hotspot gateway DNS check failed");
        }

        Ok(SharingSession {
            tun_interface: adapter_info(&tun),
            wifi_interface: adapter_info(&wifi),
            hotspot,
        })
    }
}

fn wait_for_hotspot_adapter(
    selected: Option<GUID>,
    previously_active: &HashSet<GUID>,
) -> Result<network::Adapter, HotspotError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut active: Vec<_> = network::adapters()?
            .into_iter()
            .filter(|adapter| adapter.up && adapter.is_hotspot())
            .collect();
        let settled = Instant::now() >= deadline;
        if let Some(index) = select_hotspot_adapter(
            &active
                .iter()
                .map(|adapter| adapter.guid)
                .collect::<Vec<_>>(),
            selected,
            previously_active,
            settled,
        ) {
            return Ok(active.swap_remove(index));
        }
        if settled {
            return Err(if let Some(id) = selected {
                HotspotError::InactiveHotspotAdapter {
                    id: format!("{id:?}"),
                    adapters: active.iter().map(adapter_info).collect(),
                }
            } else if active.is_empty() {
                HotspotError::NoActiveHotspotAdapter
            } else {
                HotspotError::AmbiguousHotspotAdapters(active.iter().map(adapter_info).collect())
            });
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn select_hotspot_adapter(
    active: &[GUID],
    selected: Option<GUID>,
    previously_active: &HashSet<GUID>,
    settled: bool,
) -> Option<usize> {
    if let Some(id) = selected {
        return active.iter().position(|candidate| *candidate == id);
    }
    let mut newly_active = active
        .iter()
        .enumerate()
        .filter(|(_, id)| !previously_active.contains(id));
    if let Some((index, _)) = newly_active.next() {
        return newly_active.next().is_none().then_some(index);
    }
    // Give Windows time to start its hotspot interface before reusing a
    // Wi-Fi Direct interface that was already active.
    (settled && active.len() == 1).then_some(0)
}

pub struct SharingSession {
    pub tun_interface: NetworkAdapter,
    pub wifi_interface: NetworkAdapter,
    hotspot: MobileHotspot,
}

impl SharingSession {
    pub fn stop(mut self) -> Result<(), HotspotError> {
        self.hotspot.stop()?;
        Ok(())
    }

    pub fn connected_clients(&self) -> Option<u32> {
        let _apartment = Apartment::new().ok()?;
        self.hotspot.manager.resolve().ok()?.ClientCount().ok()
    }
}

struct MobileHotspot {
    manager: AgileReference<NetworkOperatorTetheringManager>,
    path: PathBuf,
    image: Image,
    original_credentials: Option<(HSTRING, HSTRING)>,
    started: bool,
    restore_timeout: bool,
    pair: Option<(GUID, GUID)>,
    forwarding: Vec<network::ForwardingSettings>,
}

impl MobileHotspot {
    fn stop(&mut self) -> Result<()> {
        let _apartment = Apartment::new()?;
        let manager = self.manager.resolve()?;

        let mut result = Ok(());
        if let Some(pair) = self.pair.take() {
            result = native::clear_sharing(&self.path, &self.image, pair);
        }
        for mut settings in self.forwarding.drain(..).rev() {
            settings.restore();
        }
        if self.started {
            let stopped = (|| -> Result<()> {
                if manager.TetheringOperationalState()? != TetheringOperationalState::Off {
                    network::wait(manager.StopTetheringAsync()?, "Stop Windows Mobile Hotspot")?;
                }
                self.started = false;
                Ok(())
            })();
            result = result.and(stopped);
        }
        if let Some((ssid, passphrase)) = self.original_credentials.take() {
            result = result.and(set_credentials(&manager, &ssid, &passphrase));
        }
        if self.restore_timeout {
            self.restore_timeout = false;
            result = result.and(
                NetworkOperatorTetheringManager::EnableNoConnectionsTimeout()
                    .context("could not restore the Windows Mobile Hotspot idle timeout"),
            );
        }
        result
    }
}

impl Drop for MobileHotspot {
    fn drop(&mut self) {
        if (self.started || self.original_credentials.is_some() || self.restore_timeout)
            && let Err(error) = self.stop()
        {
            tracing::warn!(%error, "Windows Mobile Hotspot cleanup failed");
        }
    }
}

fn set_credentials(
    manager: &NetworkOperatorTetheringManager,
    ssid: &HSTRING,
    passphrase: &HSTRING,
) -> Result<()> {
    let config = manager.GetCurrentAccessPointConfiguration()?;
    config.SetSsid(ssid)?;
    config.SetPassphrase(passphrase)?;
    let operation = manager.ConfigureAccessPointAsync(&config)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while operation.Status()? == AsyncStatus::Started {
        if Instant::now() >= deadline {
            let _ = operation.Cancel();
            anyhow::bail!("Windows Mobile Hotspot credentials did not update within 30 seconds");
        }
        thread::sleep(Duration::from_millis(50));
    }
    operation.GetResults()?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum HotspotError {
    #[error("network adapter not found: {0}")]
    AdapterNotFound(String),
    #[error("invalid Windows hotspot adapter ID: {0}")]
    InvalidHotspotAdapter(String),
    #[error(
        "the selected Windows hotspot adapter did not become active ({id}); choose another adapter or Automatic in Settings"
    )]
    InactiveHotspotAdapter {
        id: String,
        adapters: Vec<NetworkAdapter>,
    },
    #[error("no Windows Wi-Fi Direct hotspot adapter became active")]
    NoActiveHotspotAdapter,
    #[error(
        "Multiple active Hotspot adapters found. Stop the connection and choose a Wi-Fi Direct adapter in Settings"
    )]
    AmbiguousHotspotAdapters(Vec<NetworkAdapter>),
    #[error("no physical Wi-Fi adapter is available on Windows")]
    NoWifiAdapter,
    #[error("the Mihomo TUN interface is not ready")]
    NoTunInterface,
    #[error("start VRG Hotspot as Administrator to create the Windows tunnel and share it")]
    ElevationRequired,
    #[error(transparent)]
    Credentials(#[from] CredentialError),
    #[error("Windows networking setup failed: {0:#}")]
    Windows(#[from] anyhow::Error),
    #[error("network worker thread failed: {0}")]
    Worker(String),
}

impl HotspotError {
    pub fn diagnostic_hint(&self) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_selection_uses_only_the_saved_adapter() {
        let first = GUID::from_u128(1);
        let second = GUID::from_u128(2);
        let previous = HashSet::from([second]);
        assert_eq!(
            select_hotspot_adapter(&[first, second], Some(second), &previous, false),
            Some(1)
        );
        assert_eq!(
            select_hotspot_adapter(&[first], Some(second), &previous, true),
            None
        );
    }

    #[test]
    fn automatic_selection_prefers_the_newly_active_adapter() {
        let first = GUID::from_u128(1);
        let second = GUID::from_u128(2);
        let previous = HashSet::from([first]);
        assert_eq!(
            select_hotspot_adapter(&[first, second], None, &previous, false),
            Some(1)
        );
        assert_eq!(
            select_hotspot_adapter(&[first], None, &previous, false),
            None
        );
        assert_eq!(
            select_hotspot_adapter(&[first], None, &previous, true),
            Some(0)
        );
    }

    #[test]
    fn automatic_selection_leaves_ambiguous_adapters_for_the_user() {
        let first = GUID::from_u128(1);
        let second = GUID::from_u128(2);
        assert_eq!(
            select_hotspot_adapter(&[first, second], None, &HashSet::new(), true),
            None
        );
        assert_eq!(
            select_hotspot_adapter(
                &[first, second],
                None,
                &HashSet::from([first, second]),
                true
            ),
            None
        );
    }
}
