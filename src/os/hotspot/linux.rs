use super::{AdapterKind, CredentialError, NetworkAdapter, UplinkStatus, validate_credentials};
use crate::core::config::MIHOMO_ROUTING_MARK;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const NM_DESTINATION: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_INTERFACE: &str = "org.freedesktop.NetworkManager";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";
const ACTIVE_CONNECTION_INTERFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const WIRELESS_DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const ACCESS_POINT_INTERFACE: &str = "org.freedesktop.NetworkManager.AccessPoint";
const WIFI_DEVICE_TYPE: u32 = 2;
const TUN_DEVICE_TYPE: u32 = 16;
const WIREGUARD_DEVICE_TYPE: u32 = 29;
const ACTIVATED_STATE: u32 = 100;
const ACTIVE_CONNECTION_ACTIVATED: u32 = 2;
const ACTIVE_CONNECTION_DEACTIVATED: u32 = 4;
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(250);
const ROUTING_RULE_PRIORITY: &str = "8000";
const NFT_TABLE: &str = "vrghotspot";
/// Name of the dedicated AP virtual interface created on the station's radio
/// when sharing from a single adapter (concurrent AP+STA). Must stay within the
/// 15-byte Linux interface name limit. hostapd (not wpa_supplicant) owns this
/// vif; the NetworkManager `DirectDevice` path never creates one.
const AP_VIF_NAME: &str = "vrghotspot-ap";
/// IPv4 the single-radio AP vif serves to its clients (gateway + DHCP pool).
const AP_GATEWAY_CIDR: &str = "10.42.0.1/24";
const AP_GATEWAY_ADDR: &str = "10.42.0.1";
const AP_DHCP_START: &str = "10.42.0.10";
const AP_DHCP_END: &str = "10.42.0.200";
const AP_DHCP_NETMASK: &str = "255.255.255.0";
/// Mihomo's embedded DNS listener; the AP's dnsmasq forwards here so client name
/// resolution is answered inside the tunnel (fake-ip), never leaking to the
/// physical uplink.
const MIHOMO_DNS_UPSTREAM: &str = "127.0.0.1#1053";
/// PID files for the AP daemons.
///
/// The daemons are started directly rather than through `systemd-run`: systemd
/// launches them in their confined SELinux domains (`hostapd_t`, `dnsmasq_t`),
/// which may not read a generated configuration outside their own policy paths,
/// so hostapd fails with "Could not open configuration file". Started from the
/// helper the daemons inherit its unconfined domain and work.
const HOSTAPD_PID_FILE: &str = "/run/vrghotspot/hostapd.pid";
const DNSMASQ_PID_FILE: &str = "/run/vrghotspot/dnsmasq.pid";
/// DHCP leases for the single-radio AP. Pinned to our own run directory rather
/// than dnsmasq's compiled-in default so it cannot collide with a system-wide
/// dnsmasq, and so the unprivileged UI can count connected devices by reading it.
const DNSMASQ_LEASE_FILE: &str = "/run/vrghotspot/dnsmasq.leases";
/// Where NetworkManager keeps the leases for a `ipv4.method=shared` AP, used by
/// the `DirectDevice` path where NM runs its own dnsmasq.
const NM_LEASE_DIR: &str = "/var/lib/NetworkManager";
/// Directory holding the generated, root-only hostapd config.
const AP_RUN_DIR: &str = "/run/vrghotspot";
/// How long to wait for hostapd to actually beacon before declaring failure.
const AP_BEACON_TIMEOUT: Duration = Duration::from_secs(12);
const AP_BEACON_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// firewalld zone that permits inbound traffic. The Mihomo TUN must live here:
/// otherwise it lands in the default `public` zone, whose INPUT policy rejects
/// the system-stack redirect to Mihomo's internal listener with ICMP, so Mihomo
/// never receives the connection.
const FIREWALLD_TRUSTED_ZONE: &str = "trusted";
/// How long to wait for the Wi-Fi device to become usable for activation.
const AP_DEVICE_READY_TIMEOUT: Duration = Duration::from_secs(10);
const AP_DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// NM_DEVICE_STATE_DISCONNECTED: the lowest state from which a connection can be
/// activated. Anything below this (`unmanaged`, `unavailable`) means the device
/// is not ready, which is what produced "device is not available".
const NM_DEVICE_STATE_DISCONNECTED: u32 = 30;
const NM_DEVICE_STATE_FAILED: u32 = 120;

/// Count the devices currently holding a DHCP lease on the hotspot.
///
/// Reads the lease file rather than asking the driver: `iw station dump` needs
/// privileges the desktop process deliberately does not have, and a lease is
/// the more honest signal anyway — a device that associated but never took an
/// address is not actually using the connection.
fn count_hotspot_clients(wifi_interface: &str) -> Option<u32> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    // The two hosting paths keep their leases in different places and never run
    // at once, so read whichever belongs to this one — summing them would count
    // a stale file from an earlier run of the other path.
    let ours = std::path::PathBuf::from(DNSMASQ_LEASE_FILE);
    let networkmanager =
        std::path::Path::new(NM_LEASE_DIR).join(format!("dnsmasq-{wifi_interface}.leases"));
    let candidates = if wifi_interface == AP_VIF_NAME {
        [ours, networkmanager]
    } else {
        [networkmanager, ours]
    };

    for path in candidates {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        return Some(count_active_leases(&contents, now));
    }
    None
}

/// Count unexpired leases in a dnsmasq lease file.
///
/// Each line is `<expiry-epoch> <mac> <ip> <hostname> <client-id>`; dnsmasq
/// writes `0` for a lease that never expires.
fn count_active_leases(contents: &str, now: u64) -> u32 {
    contents
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|expiry| expiry.parse::<u64>().ok())
        .filter(|expiry| *expiry == 0 || *expiry > now)
        .count() as u32
}

#[derive(Debug)]
pub struct SharingSession {
    pub tun_interface: NetworkAdapter,
    pub wifi_interface: NetworkAdapter,
    /// NetworkManager active-connection path when the AP is hosted by
    /// NetworkManager (`DirectDevice`). `None` for the single-radio path, where
    /// the AP runs under hostapd on a dedicated vif with no NM connection.
    active_connection: Option<OwnedObjectPath>,
    /// Name of the AP virtual interface we created for concurrent AP+STA, if
    /// any. Must be deleted on teardown.
    ap_vif: Option<String>,
    active: bool,
}

impl SharingSession {
    pub fn stop(mut self) -> Result<(), HotspotError> {
        self.active = false;
        HotspotController::system().disable(&self)
    }

    pub fn connected_clients(&self) -> Option<u32> {
        count_hotspot_clients(&self.wifi_interface.name)
    }
}

impl Drop for SharingSession {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = HotspotController::system().disable(self)
        {
            warn!(%error, "could not clean up interrupted hotspot startup");
        }
    }
}

pub fn tunnel_device_present() -> bool {
    std::path::Path::new("/sys/class/net")
        .join(crate::core::config::TUN_DEVICE_NAME)
        .exists()
}

/// How the access point will be hosted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApHosting {
    /// Use the Wi-Fi device directly, without pinning a channel. Either it is not
    /// associated as a station, or another interface (e.g. Ethernet) provides the
    /// default route, so losing its association does not cut the machine off.
    DirectDevice,
    /// The Wi-Fi radio is the only uplink: host the AP on a dedicated `__ap` vif
    /// on the SAME physical radio, pinned to the station's current channel so one
    /// radio can serve both roles (`#channels <= 1`).
    ///
    /// The AP must NOT be activated on the station's own device: NetworkManager
    /// allows one connection per Wi-Fi device, so bringing the AP up there tears
    /// the station down and drops the uplink (the "network falls" bug). Nor can
    /// NetworkManager host the AP on a pre-created vif — it hands managed Wi-Fi
    /// devices to wpa_supplicant, which refuses an externally created AP-mode vif
    /// ("couldn't grab this interface"). The working path is therefore hostapd:
    /// we create a `vrghotspot-ap` vif with `iw … type __ap`, mark it unmanaged so
    /// NetworkManager/wpa_supplicant leave it alone, and run hostapd + a scoped
    /// dnsmasq on it while the station stays associated on the real device.
    SameDevicePinnedChannel { channel: WifiChannel },
}

/// Decide how to host the AP on `candidate`, given the full adapter list.
///
/// The single most important rule: never destroy the machine's ONLY path to the
/// internet. A Wi-Fi device that merely *has* a default route is still fine to
/// use when some other interface also provides one (the Ethernet case) — the
/// earlier logic wrongly refused that, which is why plugging in a cable did not
/// help and the Wi-Fi had to be switched off by hand.
/// `ap_allowed_on_station_channel` reports whether the radio may actually
/// transmit (beacon) on the station's current channel, as derived from the phy's
/// frequency flags. `None` means it could not be determined.
pub fn plan_ap_hosting(
    candidate: &NetworkAdapter,
    adapters: &[NetworkAdapter],
    concurrent_supported: Option<bool>,
    ap_allowed_on_station_channel: Option<ChannelApCapability>,
) -> Result<ApHosting, HotspotError> {
    // Not associated: the radio is idle, take it directly.
    if !candidate.is_associated_station {
        return Ok(ApHosting::DirectDevice);
    }

    // Associated, but a non-Wi-Fi interface also carries a default route, so
    // connectivity survives without this association.
    let other_uplink_exists = adapters.iter().any(|adapter| {
        adapter.name != candidate.name
            && adapter.has_default_route
            && adapter.kind != AdapterKind::WiFi
            && adapter.kind != AdapterKind::Tun
            && adapter.kind != AdapterKind::Loopback
    });
    if other_uplink_exists {
        return Ok(ApHosting::DirectDevice);
    }

    // This Wi-Fi association is the only uplink, so the AP has to share the
    // radio with the station and must therefore sit on the station's channel.
    if concurrent_supported == Some(false) {
        return Err(HotspotError::ConcurrentApUnsupported {
            interface: candidate.name.clone(),
            reason:
                "the Wi-Fi driver does not allow an access point and a station at the same time"
                    .to_owned(),
        });
    }

    let frequency =
        candidate
            .station_frequency_mhz
            .ok_or_else(|| HotspotError::ConcurrentApUnsupported {
                interface: candidate.name.clone(),
                reason: "the current Wi-Fi channel could not be determined".to_owned(),
            })?;
    let channel =
        channel_from_frequency(frequency).ok_or_else(|| HotspotError::ConcurrentApUnsupported {
            interface: candidate.name.clone(),
            reason: format!("unrecognized Wi-Fi frequency {frequency} MHz"),
        })?;

    // Ask the hardware, rather than assuming. The kernel exposes per-frequency
    // regulatory flags: `no IR` means the radio may not *initiate* radiation
    // there (so it cannot beacon — this is how Intel's LAR blocks 5 GHz AP), and
    // `radar detection` marks DFS channels, which an AP cannot bring up either.
    match ap_allowed_on_station_channel {
        Some(ChannelApCapability::Allowed) | None => {}
        Some(ChannelApCapability::NoInitiatingRadiation) => {
            return Err(HotspotError::ApNotAllowedOnChannel {
                interface: candidate.name.clone(),
                channel: channel.channel,
                band: channel.band,
                reason: "the regulatory rules for this channel forbid initiating radiation \
                         (`no IR`), so the adapter cannot beacon on it"
                    .to_owned(),
            });
        }
        Some(ChannelApCapability::RadarDetection) => {
            return Err(HotspotError::DfsChannelUnsupported {
                interface: candidate.name.clone(),
                channel: channel.channel,
            });
        }
    }

    // Fall back to the static DFS channel list when the flags were unavailable.
    if ap_allowed_on_station_channel.is_none() && is_dfs_channel(&channel) {
        return Err(HotspotError::DfsChannelUnsupported {
            interface: candidate.name.clone(),
            channel: channel.channel,
        });
    }

    // Unknown capability on 5/6 GHz: refuse instead of gambling the only uplink.
    // Plenty of adapters (Intel's LAR above all) happily associate on 5 GHz but
    // may never beacon there, and finding that out by trying costs the machine
    // its one internet connection — exactly the failure this planner exists to
    // prevent. 2.4 GHz stays permissive, since beaconing there is near-universal.
    if ap_allowed_on_station_channel.is_none() && channel.band == "a" {
        return Err(HotspotError::ApNotAllowedOnChannel {
            interface: candidate.name.clone(),
            channel: channel.channel,
            band: channel.band,
            reason: "the adapter's regulatory flags for this channel could not be read, and \
                     5 GHz access points are commonly forbidden on this hardware"
                .to_owned(),
        });
    }

    Ok(ApHosting::SameDevicePinnedChannel { channel })
}

#[derive(Debug)]
pub struct TunnelRoutingSession {
    active: bool,
}

impl TunnelRoutingSession {
    pub fn enable_sharing(
        &self,
        selected: Option<&str>,
        ssid: &str,
        passphrase: &str,
    ) -> Result<SharingSession, HotspotError> {
        HotspotController::system().enable(selected, ssid, passphrase)
    }
}

impl Drop for TunnelRoutingSession {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = run_network_helper(&["cleanup-tunnel"])
        {
            warn!(%error, "failed to remove Mihomo policy-routing bypass");
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct HotspotController;

impl HotspotController {
    pub fn system() -> Self {
        Self
    }

    pub fn enumerate_all(&self) -> Result<Vec<NetworkAdapter>, HotspotError> {
        NetworkManager::connect()?.devices()
    }

    pub fn eligible_wifi_adapters(&self) -> Result<Vec<NetworkAdapter>, HotspotError> {
        let mut adapters = self
            .enumerate_all()?
            .into_iter()
            .filter(NetworkAdapter::eligible_private_adapter)
            .collect::<Vec<_>>();
        adapters.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(adapters)
    }

    /// Snapshot of what the machine has to share right now.
    pub fn uplink_status(&self) -> Result<UplinkStatus, HotspotError> {
        Ok(UplinkStatus::from_adapters(&self.enumerate_all()?))
    }

    pub fn has_physical_wifi_adapter(&self) -> Result<bool, HotspotError> {
        Ok(self
            .enumerate_all()?
            .iter()
            .any(NetworkAdapter::physical_wifi_adapter))
    }

    pub fn prepare_tunnel_routing(&self) -> Result<TunnelRoutingSession, HotspotError> {
        info!(
            routing_mark = format_args!("{MIHOMO_ROUTING_MARK:#x}"),
            rule_priority = ROUTING_RULE_PRIORITY,
            "installing Mihomo outbound policy-routing bypass"
        );
        run_network_helper(&["prepare-tunnel"])?;
        info!("Mihomo outbound policy-routing bypass installed");
        Ok(TunnelRoutingSession { active: true })
    }

    pub fn enable(
        &self,
        selected_wifi_interface: Option<&str>,
        ssid: &str,
        passphrase: &str,
    ) -> Result<SharingSession, HotspotError> {
        info!(
            selected_wifi_interface = selected_wifi_interface.unwrap_or("automatic"),
            ssid,
            passphrase_configured = !passphrase.is_empty(),
            "starting NetworkManager hotspot initialization"
        );
        validate_credentials(ssid, passphrase)?;
        debug!("hotspot credentials validated");
        let nm = NetworkManager::connect()?;
        let devices = nm.devices()?;
        info!(
            device_count = devices.len(),
            "enumerated NetworkManager devices"
        );
        let tun_interface = devices
            .iter()
            .find(|adapter| {
                adapter.eligible_public_adapter()
                    && adapter.name == crate::core::config::TUN_DEVICE_NAME
            })
            .cloned()
            .ok_or(HotspotError::NoTunInterface)?;
        // Pick the Wi-Fi radio. Prefer one that is not currently associated as a
        // station, because taking that over costs nothing.
        let candidate = match selected_wifi_interface {
            Some(id) => devices
                .iter()
                .find(|adapter| adapter.id == id && adapter.kind == AdapterKind::WiFi)
                .cloned()
                .ok_or_else(|| HotspotError::AdapterNotFound(id.to_owned()))?,
            None => devices
                .iter()
                .find(|adapter| adapter.kind == AdapterKind::WiFi && !adapter.is_associated_station)
                .or_else(|| {
                    devices
                        .iter()
                        .find(|adapter| adapter.kind == AdapterKind::WiFi)
                })
                .cloned()
                .ok_or(HotspotError::NoWifiAdapter)?,
        };

        // One `iw phy … info` snapshot answers both questions: can this radio do
        // AP+STA at all, and may it legally beacon on the station's channel.
        let phy_info = candidate.phy.as_deref().and_then(probe_phy_info);
        let concurrent_supported = phy_info.as_deref().map(supports_concurrent_ap_sta);
        let channel_capability = phy_info.as_deref().and_then(|info| {
            candidate
                .station_frequency_mhz
                .and_then(|frequency| channel_ap_capability(info, frequency))
        });
        if let Some(capability) = channel_capability {
            info!(
                station_frequency_mhz = ?candidate.station_frequency_mhz,
                ?capability,
                "access point capability on the station's channel"
            );
        }

        let hosting = plan_ap_hosting(
            &candidate,
            &devices,
            concurrent_supported,
            channel_capability,
        )?;
        info!(
            wifi_device = %candidate.name,
            associated_station = candidate.is_associated_station,
            ?hosting,
            "planned access point hosting"
        );

        // How the AP is hosted depends on whether the Wi-Fi radio is also the
        // uplink. `DirectDevice` hands the whole lifecycle to NetworkManager on
        // the real device. `SameDevicePinnedChannel` means the radio is the only
        // uplink, so the AP must NOT take over the station device — doing so tears
        // the station down and drops the uplink (the original "network falls"
        // bug). Instead we host the AP under hostapd on a dedicated vif on the
        // same radio, pinned to the station's channel, so one radio serves both.
        match &hosting {
            ApHosting::DirectDevice => {
                let wifi_interface = candidate.clone();
                info!(
                    wifi_interface = %wifi_interface.name,
                    tun_interface = %tun_interface.name,
                    "selected hotspot forwarding interfaces (NetworkManager-hosted AP)"
                );
                info!("applying nftables forwarding and masquerade rules");
                Nftables::apply(&wifi_interface.name, &tun_interface.name)?;
                info!("nftables forwarding rules applied");

                // Make sure the device can actually accept a connection before
                // asking NM to activate one; otherwise the request fails with the
                // opaque "device is not available".
                if let Err(error) = nm.wait_for_device_available(&wifi_interface.id) {
                    warn!(error = %error, "Wi-Fi device is not ready for the access point");
                    let _ = Nftables::remove();
                    return Err(error);
                }

                info!(wifi_interface = %wifi_interface.name, "requesting NetworkManager hotspot activation");
                let active_connection = match nm.activate_hotspot(
                    &wifi_interface.id,
                    &wifi_interface.name,
                    ssid,
                    passphrase,
                    None,
                ) {
                    Ok(active_connection) => active_connection,
                    Err(error) => {
                        // Log the verbatim service error plus the device's own
                        // state reason, so the real cause is visible here and not
                        // only in `journalctl -u NetworkManager`.
                        let device_state = nm.describe_device_state(&wifi_interface.id);
                        warn!(
                            error = %error,
                            device_state = %device_state,
                            "NetworkManager rejected hotspot activation; removing nftables rules"
                        );
                        let _ = Nftables::remove();
                        return Err(error);
                    }
                };
                if let Err(error) = nm.wait_for_activation(&active_connection, &wifi_interface.name)
                {
                    let device_state = nm.describe_device_state(&wifi_interface.id);
                    warn!(
                        error = %error,
                        device_state = %device_state,
                        "NetworkManager hotspot did not become active; rolling back"
                    );
                    let _ = nm.deactivate(&active_connection);
                    let _ = Nftables::remove();
                    return Err(error);
                }
                info!(wifi_interface = %wifi_interface.name, "NetworkManager hotspot is active");

                Ok(SharingSession {
                    tun_interface,
                    wifi_interface,
                    active_connection: Some(active_connection),
                    ap_vif: None,
                    active: true,
                })
            }
            ApHosting::SameDevicePinnedChannel { channel } => {
                let phy =
                    candidate
                        .phy
                        .clone()
                        .ok_or_else(|| HotspotError::ConcurrentApUnsupported {
                            interface: candidate.name.clone(),
                            reason: "the Wi-Fi phy backing this device could not be determined"
                                .to_owned(),
                        })?;
                info!(
                    station = %candidate.name,
                    phy = %phy,
                    ap_vif = AP_VIF_NAME,
                    channel = channel.channel,
                    band = channel.band,
                    "hosting the access point on a dedicated vif (single-radio AP+STA)"
                );

                // Create the AP vif on the station's radio (hostapd will own it).
                run_network_helper(&["create-ap-vif", &phy, AP_VIF_NAME])?;

                // A synthetic adapter so nft and the session refer to the AP vif
                // by name, exactly as the NM path refers to the real device.
                let wifi_interface = NetworkAdapter {
                    id: String::new(),
                    name: AP_VIF_NAME.to_owned(),
                    kind: AdapterKind::WiFi,
                    is_up: true,
                    has_ip_address: true,
                    has_default_route: false,
                    supports_hotspot: true,
                    is_associated_station: false,
                    station_frequency_mhz: None,
                    phy: Some(phy.clone()),
                };

                info!("applying nftables forwarding and masquerade rules");
                if let Err(error) = Nftables::apply(&wifi_interface.name, &tun_interface.name) {
                    let _ = run_network_helper(&["delete-ap-vif", AP_VIF_NAME]);
                    return Err(error);
                }
                info!("nftables forwarding rules applied");

                // Start hostapd plus a scoped DHCP/DNS server on the vif, pinned to
                // the station's channel. The config (with the WPA passphrase) is
                // passed on the helper's stdin, never on its command line.
                let country = detect_regulatory_country();
                let hostapd_config = build_hostapd_config(
                    &wifi_interface.name,
                    *channel,
                    ssid,
                    passphrase,
                    country.as_deref(),
                );
                if let Err(error) = run_network_helper_input(
                    &["start-ap", &wifi_interface.name],
                    Some(&hostapd_config),
                ) {
                    warn!(%error, "failed to start the hostapd access point; rolling back");
                    let _ = Nftables::remove();
                    let _ = run_network_helper(&["delete-ap-vif", AP_VIF_NAME]);
                    return Err(error);
                }

                // Permit client DHCP/DNS and forwarding through firewalld on the
                // vif (best-effort; a no-op when firewalld is not running).
                let _ = run_network_helper(&["trust-interface", &wifi_interface.name]);

                // Safety net: confirm bringing up the AP did not knock the station
                // off its upstream network. If it did, tear the AP back down and
                // fail loudly rather than leave the machine offline.
                std::thread::sleep(Duration::from_secs(2));
                let station_still_up = nm
                    .devices()
                    .ok()
                    .and_then(|devices| {
                        devices
                            .into_iter()
                            .find(|adapter| adapter.name == candidate.name)
                    })
                    .map(|adapter| adapter.is_associated_station)
                    .unwrap_or(true);
                if !station_still_up {
                    warn!(station = %candidate.name, "the station dropped when the AP came up; rolling back");
                    let _ = run_network_helper(&["stop-ap", &wifi_interface.name]);
                    self.untrust_tunnel_interface(&wifi_interface.name);
                    let _ = Nftables::remove();
                    let _ = run_network_helper(&["delete-ap-vif", AP_VIF_NAME]);
                    return Err(HotspotError::ConcurrentApDroppedStation {
                        station: candidate.name.clone(),
                    });
                }
                info!(
                    ap_vif = %wifi_interface.name,
                    station = %candidate.name,
                    "single-radio access point is up and the station is still connected"
                );

                Ok(SharingSession {
                    tun_interface,
                    wifi_interface,
                    active_connection: None,
                    ap_vif: Some(AP_VIF_NAME.to_owned()),
                    active: true,
                })
            }
        }
    }

    /// Put the Mihomo TUN into firewalld's trusted zone. Without this the
    /// interface falls into the default `public` zone, whose INPUT policy
    /// ICMP-rejects the system-stack redirect to Mihomo's internal listener, so
    /// Mihomo never sees the connection and the tunnel carries no traffic.
    pub fn trust_tunnel_interface(&self, tun_interface: &str) -> Result<(), HotspotError> {
        run_network_helper(&["trust-interface", tun_interface])
    }

    pub fn untrust_tunnel_interface(&self, tun_interface: &str) {
        if let Err(error) = run_network_helper(&["untrust-interface", tun_interface]) {
            warn!(%error, "failed to remove the tunnel interface from the firewalld trusted zone");
        }
    }

    /// Tear down in reverse order of setup, best-effort: every stage runs even if
    /// an earlier one fails, so nothing is left behind.
    fn disable(&self, session: &SharingSession) -> Result<(), HotspotError> {
        // Single-radio path: stop the hostapd AP + its DHCP/DNS first, then drop
        // the vif from firewalld's trusted zone.
        if let Some(ap_vif) = &session.ap_vif {
            info!(interface = %ap_vif, "stopping the hostapd access point");
            if let Err(error) = run_network_helper(&["stop-ap", ap_vif]) {
                warn!(%error, "failed to stop the hostapd access point");
            }
            self.untrust_tunnel_interface(ap_vif);
        }

        // Only the NetworkManager-hosted path has an active connection to drop.
        let deactivated = match &session.active_connection {
            Some(active_connection) => {
                NetworkManager::connect().and_then(|nm| nm.deactivate(active_connection))
            }
            None => Ok(()),
        };
        if let Err(error) = &deactivated {
            warn!(%error, "failed to deactivate the NetworkManager hotspot connection");
        }

        let rules_removed = Nftables::remove();
        if let Err(error) = &rules_removed {
            warn!(%error, "failed to remove nftables forwarding rules");
        }

        self.untrust_tunnel_interface(&session.tun_interface.name);

        if let Some(ap_vif) = &session.ap_vif {
            info!(interface = %ap_vif, "removing concurrent access point virtual interface");
            if let Err(error) = run_network_helper(&["delete-ap-vif", ap_vif]) {
                warn!(%error, "failed to delete the access point virtual interface");
            }
        }

        deactivated.and(rules_removed)
    }
}

struct NetworkManager {
    connection: Connection,
}

impl NetworkManager {
    fn connect() -> Result<Self, HotspotError> {
        debug!("connecting to NetworkManager on the D-Bus system bus");
        let connection = Connection::system()?;
        debug!("connected to the D-Bus system bus");
        Ok(Self { connection })
    }

    fn manager(&self) -> Result<Proxy<'_>, HotspotError> {
        Ok(Proxy::new(
            &self.connection,
            NM_DESTINATION,
            NM_PATH,
            NM_INTERFACE,
        )?)
    }

    fn devices(&self) -> Result<Vec<NetworkAdapter>, HotspotError> {
        let manager = self.manager()?;
        let paths: Vec<OwnedObjectPath> = manager.call("GetAllDevices", &())?;
        // Resolve which interfaces currently carry a default route once, from the
        // kernel, then stamp each adapter. NetworkManager's per-device D-Bus
        // properties do not expose this cheaply, and it is the single most
        // important fact for picking a hotspot radio safely (see
        // `default_route_interfaces`).
        let default_routes = default_route_interfaces();
        paths
            .into_iter()
            .map(|path| {
                let mut adapter = self.device(&path)?;
                adapter.has_default_route = default_routes.contains(&adapter.name);
                Ok(adapter)
            })
            .collect()
    }

    fn device(&self, path: &OwnedObjectPath) -> Result<NetworkAdapter, HotspotError> {
        let properties = Proxy::new(
            &self.connection,
            NM_DESTINATION,
            path.as_str(),
            PROPERTIES_INTERFACE,
        )?;
        let name: String = property(&properties, DEVICE_INTERFACE, "Interface")?;
        let device_type: u32 = property(&properties, DEVICE_INTERFACE, "DeviceType")?;
        let state: u32 = property(&properties, DEVICE_INTERFACE, "State")?;
        let ip4_config: OwnedObjectPath = property(&properties, DEVICE_INTERFACE, "Ip4Config")?;
        let kind = match device_type {
            1 => AdapterKind::Ethernet,
            WIFI_DEVICE_TYPE => AdapterKind::WiFi,
            TUN_DEVICE_TYPE | WIREGUARD_DEVICE_TYPE => AdapterKind::Tun,
            32 => AdapterKind::Loopback,
            _ if looks_like_tun(&name) => AdapterKind::Tun,
            _ => AdapterKind::Other,
        };
        let interface_exists = std::path::Path::new("/sys/class/net").join(&name).exists();

        // For Wi-Fi devices, find out whether they are associated as a station
        // and on which frequency. Both facts decide whether the device can host
        // an AP directly or needs a concurrent AP vif locked to this channel.
        let mut is_associated_station = false;
        let mut station_frequency_mhz = None;
        if kind == AdapterKind::WiFi
            && let Ok(active_ap) = property::<OwnedObjectPath>(
                &properties,
                WIRELESS_DEVICE_INTERFACE,
                "ActiveAccessPoint",
            )
            && active_ap.as_str() != "/"
        {
            is_associated_station = true;
            station_frequency_mhz = self.access_point_frequency(&active_ap);
        }
        let phy = (kind == AdapterKind::WiFi)
            .then(|| phy_for_interface(&name))
            .flatten();

        Ok(NetworkAdapter {
            id: path.to_string(),
            name,
            kind: kind.clone(),
            is_up: state == ACTIVATED_STATE || (kind == AdapterKind::Tun && interface_exists),
            has_ip_address: ip4_config.as_str() != "/",
            has_default_route: false,
            supports_hotspot: kind == AdapterKind::WiFi,
            is_associated_station,
            station_frequency_mhz,
            phy,
        })
    }

    /// Operating frequency (MHz) of a NetworkManager AccessPoint object.
    fn access_point_frequency(&self, access_point: &OwnedObjectPath) -> Option<u32> {
        let properties = Proxy::new(
            &self.connection,
            NM_DESTINATION,
            access_point.as_str(),
            PROPERTIES_INTERFACE,
        )
        .ok()?;
        property::<u32>(&properties, ACCESS_POINT_INTERFACE, "Frequency").ok()
    }

    /// Wait until a device is not merely *present* but actually usable for
    /// activation (NM state >= `disconnected`, i.e. 30).
    ///
    /// The previous version only waited for the interface to appear, which is why
    /// activation was attempted ~69 ms after the vif was created while the device
    /// was still `unavailable`, yielding "device is not available". Retained for
    /// the physical device path, where it is a cheap safety check.
    fn wait_for_device_available(&self, device_path: &str) -> Result<(), HotspotError> {
        let deadline = Instant::now() + AP_DEVICE_READY_TIMEOUT;
        let mut last_state = String::from("unknown");
        loop {
            let properties = Proxy::new(
                &self.connection,
                NM_DESTINATION,
                device_path,
                PROPERTIES_INTERFACE,
            )?;
            if let Ok(state) = property::<u32>(&properties, DEVICE_INTERFACE, "State") {
                if state >= NM_DEVICE_STATE_DISCONNECTED && state != NM_DEVICE_STATE_FAILED {
                    return Ok(());
                }
                last_state = format!("{} ({state})", describe_device_state_code(state));
            }
            if Instant::now() >= deadline {
                return Err(HotspotError::ApDeviceNotReady {
                    device: device_path.to_owned(),
                    state: last_state,
                    detail: self.describe_device_state(device_path),
                    seconds: AP_DEVICE_READY_TIMEOUT.as_secs(),
                });
            }
            std::thread::sleep(AP_DEVICE_POLL_INTERVAL);
        }
    }

    fn activate_hotspot(
        &self,
        wifi_device_path: &str,
        interface_name: &str,
        ssid: &str,
        passphrase: &str,
        channel: Option<WifiChannel>,
    ) -> Result<OwnedObjectPath, HotspotError> {
        let settings = hotspot_settings(ssid, passphrase, interface_name, channel);
        let manager = self.manager()?;
        let device = OwnedObjectPath::try_from(wifi_device_path)?;
        let specific = OwnedObjectPath::try_from("/")?;
        let options = HashMap::from([("persist", Value::from("volatile"))]);
        let (_connection, active, _result): (
            OwnedObjectPath,
            OwnedObjectPath,
            HashMap<String, OwnedValue>,
        ) = manager.call(
            "AddAndActivateConnection2",
            &(settings, device, specific, options),
        )?;
        info!(
            connection_path = %_connection,
            active_connection = %active,
            "NetworkManager accepted hotspot activation request"
        );
        Ok(active)
    }

    fn wait_for_activation(
        &self,
        active_connection: &OwnedObjectPath,
        wifi_interface: &str,
    ) -> Result<(), HotspotError> {
        let properties = Proxy::new(
            &self.connection,
            NM_DESTINATION,
            active_connection.as_str(),
            PROPERTIES_INTERFACE,
        )?;
        let deadline = Instant::now() + ACTIVATION_TIMEOUT;
        loop {
            let state: u32 = property(&properties, ACTIVE_CONNECTION_INTERFACE, "State")?;
            debug!(
                wifi_interface,
                state, "waiting for NetworkManager hotspot activation"
            );
            match state {
                ACTIVE_CONNECTION_ACTIVATED => return Ok(()),
                ACTIVE_CONNECTION_DEACTIVATED => {
                    return Err(HotspotError::ActivationFailed(wifi_interface.to_owned()));
                }
                _ if Instant::now() >= deadline => {
                    return Err(HotspotError::ActivationTimedOut {
                        interface: wifi_interface.to_owned(),
                        seconds: ACTIVATION_TIMEOUT.as_secs(),
                    });
                }
                _ => std::thread::sleep(ACTIVATION_POLL_INTERVAL),
            }
        }
    }

    fn deactivate(&self, active_connection: &OwnedObjectPath) -> Result<(), HotspotError> {
        self.manager()?
            .call::<_, _, ()>("DeactivateConnection", &(active_connection,))?;
        Ok(())
    }

    /// Human-readable device state plus NetworkManager's own StateReason, for
    /// diagnostics. NM's reason codes name the actual blocker (for example
    /// `supplicant-failed` when wpa_supplicant could not grab the interface), so
    /// this is what turns "device is not available" into something actionable.
    fn describe_device_state(&self, device_path: &str) -> String {
        let Ok(properties) = Proxy::new(
            &self.connection,
            NM_DESTINATION,
            device_path,
            PROPERTIES_INTERFACE,
        ) else {
            return "unavailable (could not query the device over D-Bus)".to_owned();
        };

        // StateReason is a (state, reason) tuple; fall back to plain State.
        if let Ok((state, reason)) =
            property::<(u32, u32)>(&properties, DEVICE_INTERFACE, "StateReason")
        {
            return format!(
                "{} ({state}), reason {} ({reason})",
                describe_device_state_code(state),
                describe_device_state_reason(reason)
            );
        }
        match property::<u32>(&properties, DEVICE_INTERFACE, "State") {
            Ok(state) => format!("{} ({state})", describe_device_state_code(state)),
            Err(error) => format!("unknown ({error})"),
        }
    }
}

/// The D-Bus layer could not reach NetworkManager at all (transport/name error),
/// as opposed to NetworkManager answering with a method error.
fn dbus_error_means_service_unreachable(error: &zbus::Error) -> bool {
    matches!(
        error,
        zbus::Error::InputOutput(_)
            | zbus::Error::Address(_)
            | zbus::Error::Handshake(_)
            | zbus::Error::NameTaken
    ) || matches!(error, zbus::Error::MethodError(name, _, _)
        if name.as_str().ends_with(".ServiceUnknown")
            || name.as_str().ends_with(".NameHasNoOwner"))
}

fn dbus_error_is_authorization(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _)
        if name.as_str().contains("AuthFailed")
            || name.as_str().contains("NotAuthorized")
            || name.as_str().ends_with(".AccessDenied")
            || name.as_str().contains("PermissionDenied"))
}

/// NetworkManager refused because the target device is not usable for the
/// requested connection (typically `UnknownConnection` with "device is not
/// available", which on Wi-Fi usually traces back to wpa_supplicant).
fn dbus_error_means_device_unavailable(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, message, _) => {
            let name = name.as_str();
            let message = message.as_deref().unwrap_or_default().to_ascii_lowercase();
            name.ends_with(".UnknownConnection")
                || name.ends_with(".UnknownDevice")
                || message.contains("not available")
                || message.contains("not managed")
        }
        _ => false,
    }
}

/// NM_DEVICE_STATE values, from the NetworkManager D-Bus API.
fn describe_device_state_code(state: u32) -> &'static str {
    match state {
        0 => "unknown",
        10 => "unmanaged",
        20 => "unavailable",
        30 => "disconnected",
        40 => "prepare",
        50 => "config",
        60 => "need-auth",
        70 => "ip-config",
        80 => "ip-check",
        90 => "secondaries",
        100 => "activated",
        110 => "deactivating",
        120 => "failed",
        _ => "unrecognized",
    }
}

/// The subset of NM_DEVICE_STATE_REASON codes worth naming for hotspot
/// diagnostics; anything else is reported numerically by the caller.
fn describe_device_state_reason(reason: u32) -> &'static str {
    match reason {
        0 => "none",
        1 => "unknown",
        2 => "now-managed",
        3 => "now-unmanaged",
        4 => "config-failed",
        5 => "ip-config-unavailable",
        6 => "ip-config-expired",
        7 => "no-secrets",
        8 => "supplicant-disconnect",
        9 => "supplicant-config-failed",
        10 => "supplicant-failed",
        11 => "supplicant-timeout",
        13 => "ppp-failed",
        14 => "dhcp-start-failed",
        15 => "dhcp-error",
        16 => "dhcp-failed",
        17 => "shared-start-failed",
        18 => "shared-failed",
        36 => "firmware-missing",
        38 => "carrier-changed",
        39 => "connection-assumed",
        40 => "supplicant-available",
        41 => "modem-not-found",
        50 => "unmanaged-link-not-init",
        61 => "device-handler-failed",
        _ => "other",
    }
}

fn property<T>(proxy: &Proxy<'_>, interface: &str, name: &str) -> Result<T, HotspotError>
where
    T: TryFrom<OwnedValue>,
    T::Error: std::fmt::Display,
{
    let value: OwnedValue = proxy.call("Get", &(interface, name))?;
    T::try_from(value).map_err(|error| HotspotError::InvalidDbusProperty {
        property: name.to_owned(),
        reason: error.to_string(),
    })
}

fn hotspot_settings<'a>(
    ssid: &'a str,
    passphrase: &'a str,
    interface_name: &'a str,
    channel: Option<WifiChannel>,
) -> HashMap<&'static str, HashMap<&'static str, Value<'a>>> {
    let mut connection = HashMap::new();
    connection.insert("id", Value::from(format!("VRG Hotspot {ssid}")));
    connection.insert("uuid", Value::from(Uuid::new_v4().to_string()));
    connection.insert("type", Value::from("802-11-wireless"));
    connection.insert("autoconnect", Value::from(false));
    // Bind the profile to the exact interface hosting the AP; with a concurrent
    // AP vif present, NetworkManager must not pick the station device instead.
    connection.insert("interface-name", Value::from(interface_name));
    // Fedora's firewalld provides this zone for NetworkManager shared links.
    connection.insert("zone", Value::from("nm-shared"));

    let mut wireless = HashMap::new();
    wireless.insert("mode", Value::from("ap"));
    wireless.insert("ssid", Value::from(ssid.as_bytes().to_vec()));
    // Lock the AP to the station's channel. A radio running AP+STA has
    // `#channels <= 1`, so an unpinned AP either fails to start or knocks the
    // station off. NetworkManager requires `band` whenever `channel` is set,
    // because channel numbers repeat across bands.
    if let Some(channel) = channel {
        wireless.insert("band", Value::from(channel.band));
        wireless.insert("channel", Value::from(channel.channel));
    }

    let mut security = HashMap::new();
    security.insert("key-mgmt", Value::from("wpa-psk"));
    security.insert("psk", Value::from(passphrase));

    let mut ipv4 = HashMap::new();
    ipv4.insert("method", Value::from("shared"));

    let mut ipv6 = HashMap::new();
    ipv6.insert("method", Value::from("disabled"));

    HashMap::from([
        ("connection", connection),
        ("802-11-wireless", wireless),
        ("802-11-wireless-security", security),
        ("ipv4", ipv4),
        ("ipv6", ipv6),
    ])
}

/// Build a hostapd configuration for the single-radio AP vif, pinned to the
/// station's channel. hostapd (not wpa_supplicant) owns this interface, which is
/// what lets the radio host an AP while staying associated as a station. The
/// SSID/passphrase are already validated by [`validate_credentials`].
fn build_hostapd_config(
    interface: &str,
    channel: WifiChannel,
    ssid: &str,
    passphrase: &str,
    country: Option<&str>,
) -> String {
    // NetworkManager band token "a" => 5/6 GHz (hostapd hw_mode a); "bg" => 2.4
    // GHz (hw_mode g). plan_ap_hosting already rejects channels the radio may not
    // beacon on (no-IR / DFS).
    let hw_mode = if channel.band == "a" { "a" } else { "g" };
    let mut config = format!(
        "interface={interface}\n\
         driver=nl80211\n\
         ssid={ssid}\n\
         hw_mode={hw_mode}\n\
         channel={channel}\n\
         auth_algs=1\n\
         wmm_enabled=1\n\
         ignore_broadcast_ssid=0\n\
         wpa=2\n\
         wpa_passphrase={passphrase}\n\
         wpa_key_mgmt=WPA-PSK\n\
         wpa_pairwise=CCMP\n\
         rsn_pairwise=CCMP\n",
        channel = channel.channel,
    );
    // 5 GHz needs an explicit regulatory country: without `country_code` hostapd
    // refuses to bring up an AP there at all, and a code that disagrees with the
    // kernel's domain makes channel setup fail. 802.11n/ac are enabled so clients
    // are not forced down to legacy rates.
    if let Some(country) = country {
        config.push_str(&format!("country_code={country}\nieee80211d=1\n"));
    }
    config.push_str("ieee80211n=1\n");
    if channel.band == "a" {
        config.push_str("ieee80211ac=1\n");
    }
    config
}

/// Current regulatory domain from `iw reg get`, as a two-letter country code.
///
/// Returns `None` for the world domain (`00`), which is not a usable
/// `country_code` for an access point, and when `iw` cannot be run.
fn detect_regulatory_country() -> Option<String> {
    for candidate in ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "iw"] {
        let Ok(output) = Command::new(candidate).args(["reg", "get"]).output() else {
            continue;
        };
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        // Lines look like `country RU: DFS-ETSI` or `country 00: DFS-UNSET`.
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("country ") else {
                continue;
            };
            let code: String = rest.chars().take(2).collect();
            if code.len() == 2
                && code
                    .chars()
                    .all(|character| character.is_ascii_alphabetic())
            {
                return Some(code.to_ascii_uppercase());
            }
        }
        return None;
    }
    None
}

struct Nftables;

impl Nftables {
    fn apply(wifi_interface: &str, tun_interface: &str) -> Result<(), HotspotError> {
        validate_interface_name(wifi_interface)?;
        validate_interface_name(tun_interface)?;
        run_network_helper(&["apply", wifi_interface, tun_interface])
    }

    fn remove() -> Result<(), HotspotError> {
        run_network_helper(&["remove"])
    }
}

fn run_network_helper(arguments: &[&str]) -> Result<(), HotspotError> {
    run_network_helper_input(arguments, None)
}

/// Run the privileged helper, optionally feeding `input` on its stdin. The stdin
/// channel is used to pass the hostapd configuration (which contains the WPA
/// passphrase) without exposing it in the process arguments.
fn run_network_helper_input(arguments: &[&str], input: Option<&str>) -> Result<(), HotspotError> {
    use std::io::Write;
    let executable = std::env::current_exe().map_err(HotspotError::CurrentExecutable)?;
    let mut command = if is_root() {
        // Avoid consulting the graphical/session D-Bus when the app was
        // explicitly started as root.
        let mut command = Command::new(&executable);
        command.arg("--nft-helper");
        command
    } else {
        let mut command = Command::new("pkexec");
        command.arg(&executable).arg("--nft-helper");
        command
    };
    debug!(
        ?arguments,
        running_as_root = is_root(),
        with_stdin = input.is_some(),
        "starting privileged network helper"
    );
    command.args(arguments);
    let output = match input {
        None => command
            .stdin(Stdio::null())
            .output()
            .map_err(HotspotError::PrivilegeHelper)?,
        Some(input) => {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(HotspotError::PrivilegeHelper)?;
            child
                .stdin
                .take()
                .ok_or_else(|| {
                    HotspotError::Nftables("failed to open privileged helper stdin".to_owned())
                })?
                .write_all(input.as_bytes())
                .map_err(HotspotError::PrivilegeHelper)?;
            child
                .wait_with_output()
                .map_err(HotspotError::PrivilegeHelper)?
        }
    };
    if output.status.success() {
        Ok(())
    } else {
        Err(HotspotError::Nftables(helper_failure_reason(
            &output.stderr,
        )))
    }
}

/// Extract the helper's real failure from its stderr.
///
/// The embedded Mihomo core prints a `core-bridge initialized: …` banner from a
/// Go library constructor whenever the binary starts — including in helper mode.
/// Leaving it in buried the actual cause (for example
/// "RTNETLINK answers: Device or resource busy") behind unrelated build details.
fn helper_failure_reason(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let reason = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("core-bridge initialized"))
        .collect::<Vec<_>>()
        .join("; ");
    if reason.is_empty() {
        text.trim().to_owned()
    } else {
        reason
    }
}

pub fn run_privileged_helper() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--nft-helper") {
        return None;
    }
    if !is_root() {
        eprintln!("the nftables helper must be started through pkexec");
        return Some(1);
    }
    let operation = args.next();
    let result = match operation.as_deref() {
        Some("prepare-tunnel") if args.next().is_none() => privileged_prepare_tunnel(),
        Some("cleanup-tunnel") if args.next().is_none() => privileged_cleanup_tunnel(),
        Some("apply") => match (args.next(), args.next(), args.next()) {
            (Some(wifi), Some(tun), None) => privileged_apply(&wifi, &tun),
            _ => Err("apply requires exactly two interface names".to_owned()),
        },
        Some("remove") if args.next().is_none() => privileged_remove(),
        // Put the Mihomo TUN into firewalld's trusted zone so the system-stack
        // redirect to Mihomo's internal listener is not ICMP-rejected by the
        // default `public` zone.
        Some("trust-interface") => match (args.next(), args.next()) {
            (Some(interface), None) => privileged_trust_interface(&interface),
            _ => Err("trust-interface requires exactly one interface name".to_owned()),
        },
        Some("untrust-interface") => match (args.next(), args.next()) {
            (Some(interface), None) => privileged_untrust_interface(&interface),
            _ => Err("untrust-interface requires exactly one interface name".to_owned()),
        },
        // Create/destroy the dedicated AP virtual interface used for concurrent
        // AP+STA sharing from a single radio.
        Some("create-ap-vif") => match (args.next(), args.next(), args.next()) {
            (Some(phy), Some(name), None) => privileged_create_ap_vif(&phy, &name),
            _ => Err("create-ap-vif requires a phy and an interface name".to_owned()),
        },
        Some("delete-ap-vif") => match (args.next(), args.next()) {
            (Some(name), None) => privileged_delete_ap_vif(&name),
            _ => Err("delete-ap-vif requires exactly one interface name".to_owned()),
        },
        // Start/stop the hostapd access point (and its DHCP/DNS) on the AP vif
        // used for single-radio AP+STA sharing. The hostapd configuration arrives
        // on stdin, so the WPA passphrase never appears in the process arguments.
        Some("start-ap") => match (args.next(), args.next()) {
            (Some(vif), None) => privileged_start_ap(&vif),
            _ => Err("start-ap requires exactly one interface name".to_owned()),
        },
        Some("stop-ap") => match (args.next(), args.next()) {
            (Some(vif), None) => privileged_stop_ap(&vif),
            _ => Err("stop-ap requires exactly one interface name".to_owned()),
        },
        _ => Err("unsupported nftables helper operation".to_owned()),
    };
    match result {
        Ok(()) => Some(0),
        Err(error) => {
            eprintln!("{error}");
            Some(1)
        }
    }
}

fn privileged_prepare_tunnel() -> Result<(), String> {
    privileged_cleanup_tunnel()?;
    let mark = format!("{MIHOMO_ROUTING_MARK:#x}/0xffffffff");
    run_ip(&[
        "-4",
        "rule",
        "add",
        "priority",
        ROUTING_RULE_PRIORITY,
        "fwmark",
        &mark,
        "lookup",
        "main",
    ])?;
    if let Err(error) = run_ip(&[
        "-6",
        "rule",
        "add",
        "priority",
        ROUTING_RULE_PRIORITY,
        "fwmark",
        &mark,
        "lookup",
        "main",
    ]) {
        let _ = privileged_cleanup_tunnel();
        return Err(error);
    }
    Ok(())
}

fn privileged_cleanup_tunnel() -> Result<(), String> {
    let mark = format!("{MIHOMO_ROUTING_MARK:#x}/0xffffffff");
    for family in ["-4", "-6"] {
        let output = Command::new("/usr/sbin/ip")
            .args([
                family,
                "rule",
                "delete",
                "priority",
                ROUTING_RULE_PRIORITY,
                "fwmark",
                &mark,
                "lookup",
                "main",
            ])
            .output()
            .map_err(|error| format!("failed to execute ip: {error}"))?;
        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
        {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such process") {
                return Err(stderr.trim().to_owned());
            }
        }
    }
    Ok(())
}

/// Is firewalld running? When it is not, interface zones are meaningless and the
/// trust operations become no-ops.
fn firewalld_is_active() -> bool {
    Command::new("firewall-cmd")
        .arg("--state")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Add `interface` to firewalld's trusted zone (runtime only — deliberately not
/// `--permanent`, so a reboot cannot leave the machine with a stale trusted
/// interface).
///
/// This cannot be solved by adding an accept rule to our own nftables table:
/// firewalld's chains run at the same netfilter hook, and a reject in ANY table
/// still drops the packet. The interface must actually leave the `public` zone.
fn privileged_trust_interface(interface: &str) -> Result<(), String> {
    validate_interface_name(interface).map_err(|error| error.to_string())?;
    if !firewalld_is_active() {
        return Ok(());
    }
    // `--change-interface` both adds and moves, so it is idempotent.
    let output = Command::new("firewall-cmd")
        .args([
            &format!("--zone={FIREWALLD_TRUSTED_ZONE}"),
            &format!("--change-interface={interface}"),
        ])
        .output()
        .map_err(|error| format!("failed to execute firewall-cmd: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to add {interface} to the firewalld {FIREWALLD_TRUSTED_ZONE} zone: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn privileged_untrust_interface(interface: &str) -> Result<(), String> {
    validate_interface_name(interface).map_err(|error| error.to_string())?;
    if !firewalld_is_active() {
        return Ok(());
    }
    let output = Command::new("firewall-cmd")
        .args([
            &format!("--zone={FIREWALLD_TRUSTED_ZONE}"),
            &format!("--remove-interface={interface}"),
        ])
        .output()
        .map_err(|error| format!("failed to execute firewall-cmd: {error}"))?;
    // Not being in the zone is a success for teardown purposes.
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("NOT_ENABLED") || stderr.contains("ZONE_CONFLICT") {
        return Ok(());
    }
    Err(stderr.trim().to_owned())
}

/// Create a second virtual interface in AP mode on the same physical radio
/// (`phy`) as the station. This is the only way to host an access point while
/// staying associated as a client: NetworkManager cannot create the vif itself,
/// and switching the existing station device into AP mode would tear down the
/// uplink.
fn privileged_create_ap_vif(phy: &str, name: &str) -> Result<(), String> {
    validate_interface_name(name).map_err(|error| error.to_string())?;
    validate_phy_name(phy)?;
    // Remove a leftover vif from a previous run so creation is idempotent.
    let _ = privileged_delete_ap_vif(name);
    // `type __ap` (double underscore) creates the interface directly in AP mode;
    // `type ap` is rejected by iw for this purpose.
    run_iw(&["phy", phy, "interface", "add", name, "type", "__ap"])?;

    // Some drivers refuse to bring up a second vif that shares the station's
    // MAC. Derive a distinct locally-administered address from the phy's own
    // address when we can; a failure here is not fatal.
    if let Some(mac) = derive_ap_mac(name) {
        let _ = run_ip(&["link", "set", "dev", name, "address", &mac]);
    }
    Ok(())
}

fn privileged_delete_ap_vif(name: &str) -> Result<(), String> {
    validate_interface_name(name).map_err(|error| error.to_string())?;
    if !std::path::Path::new("/sys/class/net").join(name).exists() {
        return Ok(());
    }
    run_iw(&["dev", name, "del"])
}

/// Start hostapd (WPA2 AP) plus a scoped dnsmasq (DHCP + in-tunnel DNS) on the AP
/// vif. The hostapd configuration is read from stdin. This is the single-radio
/// path: the AP shares the station's radio through a dedicated vif, so the
/// uplink stays up.
fn privileged_start_ap(vif: &str) -> Result<(), String> {
    use std::io::Read;
    validate_interface_name(vif).map_err(|error| error.to_string())?;

    let mut hostapd_config = String::new();
    std::io::stdin()
        .read_to_string(&mut hostapd_config)
        .map_err(|error| format!("failed to read the hostapd configuration: {error}"))?;
    if hostapd_config.trim().is_empty() {
        return Err("empty hostapd configuration".to_owned());
    }
    // The caller is unprivileged and this process is root, so the configuration
    // is untrusted input no matter who generated it. Accept only the directives
    // this application actually emits, and require that the interface named in
    // the file is the one whose name we just validated — otherwise a caller
    // could pass a legitimate `vif` argument while pointing hostapd somewhere
    // else entirely.
    validate_hostapd_config(&hostapd_config, vif)?;

    // Clear any previous run so starting is idempotent.
    let _ = privileged_stop_ap(vif);

    std::fs::create_dir_all(AP_RUN_DIR)
        .map_err(|error| format!("failed to create {AP_RUN_DIR}: {error}"))?;
    let config_path = format!("{AP_RUN_DIR}/hostapd-{vif}.conf");
    write_private_file(&config_path, hostapd_config.as_bytes())?;

    // Keep NetworkManager/wpa_supplicant off the vif so hostapd can own it.
    let _ = run_nmcli(&["device", "set", vif, "managed", "no"]);

    // Deliberately do NOT bring the interface up here. An AP-mode vif has no
    // channel configured yet, so `ip link set … up` is rejected with EBUSY
    // ("RTNETLINK answers: Device or resource busy"). hostapd selects the
    // channel and brings the interface up itself.
    let hostapd = resolve_binary(
        &["/usr/sbin/hostapd", "/sbin/hostapd", "/usr/bin/hostapd"],
        "hostapd",
    )?;
    spawn_daemon(
        &hostapd,
        &["-B", "-P", HOSTAPD_PID_FILE, config_path.as_str()],
        "hostapd",
    )?;

    // hostapd's `-B` forks before the radio is configured, so wait for the vif to
    // actually beacon rather than trusting the exit status.
    wait_for_ap_enabled(vif)?;

    // The interface is up and owned by hostapd now, so it can take the clients'
    // gateway address.
    let _ = run_ip(&["addr", "flush", "dev", vif]);
    if let Err(error) = run_ip(&["addr", "add", AP_GATEWAY_CIDR, "dev", vif]) {
        let _ = stop_pid_file(HOSTAPD_PID_FILE, "hostapd");
        return Err(error);
    }

    // dnsmasq: DHCP for clients + DNS forwarded into Mihomo's tunnel. Started
    // directly for the same SELinux reason as hostapd; it daemonizes itself.
    let dnsmasq = resolve_binary(&["/usr/sbin/dnsmasq", "/usr/bin/dnsmasq"], "dnsmasq")?;
    let interface_arg = format!("--interface={vif}");
    let dhcp_range_arg =
        format!("--dhcp-range={AP_DHCP_START},{AP_DHCP_END},{AP_DHCP_NETMASK},12h");
    let gateway_arg = format!("--dhcp-option=3,{AP_GATEWAY_ADDR}");
    let dns_arg = format!("--dhcp-option=6,{AP_GATEWAY_ADDR}");
    let server_arg = format!("--server={MIHOMO_DNS_UPSTREAM}");
    let pid_arg = format!("--pid-file={DNSMASQ_PID_FILE}");
    let lease_arg = format!("--dhcp-leasefile={DNSMASQ_LEASE_FILE}");
    // Start from a clean slate so leases from a previous run are not counted as
    // devices connected to this one.
    let _ = std::fs::remove_file(DNSMASQ_LEASE_FILE);
    if let Err(error) = spawn_daemon(
        &dnsmasq,
        &[
            interface_arg.as_str(),
            "--bind-dynamic",
            "--except-interface=lo",
            "--no-resolv",
            "--no-hosts",
            dhcp_range_arg.as_str(),
            gateway_arg.as_str(),
            dns_arg.as_str(),
            server_arg.as_str(),
            pid_arg.as_str(),
            lease_arg.as_str(),
        ],
        "dnsmasq",
    ) {
        // Never leave hostapd beaconing without a DHCP server behind it.
        let _ = stop_pid_file(HOSTAPD_PID_FILE, "hostapd");
        return Err(error);
    }
    Ok(())
}

/// Stop the AP daemons and release the vif address.
fn privileged_stop_ap(vif: &str) -> Result<(), String> {
    validate_interface_name(vif).map_err(|error| error.to_string())?;
    let _ = stop_pid_file(DNSMASQ_PID_FILE, "dnsmasq");
    let _ = stop_pid_file(HOSTAPD_PID_FILE, "hostapd");
    let _ = run_ip(&["addr", "flush", "dev", vif]);
    let _ = std::fs::remove_file(format!("{AP_RUN_DIR}/hostapd-{vif}.conf"));
    Ok(())
}

/// Launch a self-daemonizing program and surface its own error output on
/// failure. Started as a direct child so it inherits the helper's unconfined
/// SELinux domain (see [`HOSTAPD_PID_FILE`]).
fn spawn_daemon(program: &str, arguments: &[&str], name: &str) -> Result<(), String> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to execute {name}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(format!("{name} failed to start: {detail}"))
}

/// Terminate the process recorded in `pid_file` and remove the file.
///
/// The PID is confirmed against `/proc/<pid>/comm` before signalling. A pid file
/// left behind by a crash or a reboot can name a PID the kernel has since reused,
/// and this runs as root — without the check, teardown would SIGTERM an unrelated
/// process.
fn stop_pid_file(pid_file: &str, expected_process: &str) -> Result<(), String> {
    let Ok(contents) = std::fs::read_to_string(pid_file) else {
        return Ok(());
    };
    if let Ok(pid) = contents.trim().parse::<i32>()
        && pid > 1
        && process_is_named(pid, expected_process)
    {
        // SIGTERM lets hostapd deconfigure the radio before exiting.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let _ = std::fs::remove_file(pid_file);
    Ok(())
}

/// Is `pid` actually the daemon we started? `/proc/<pid>/comm` holds the
/// executable name truncated to 15 bytes, which is why this compares against a
/// similarly truncated expectation rather than requiring an exact match.
fn process_is_named(pid: i32, expected: &str) -> bool {
    let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
        return false;
    };
    let truncated: String = expected.chars().take(15).collect();
    comm.trim() == truncated
}

/// Is the process recorded in `pid_file` still alive?
fn pid_file_process_is_alive(pid_file: &str) -> bool {
    let Ok(contents) = std::fs::read_to_string(pid_file) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<i32>() else {
        return false;
    };
    pid > 1 && std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Resolve the first existing path from `candidates`, else fall back to a bare
/// name for `$PATH` lookup at exec time.
fn resolve_binary(candidates: &[&str], name: &str) -> Result<String, String> {
    for candidate in candidates {
        if std::path::Path::new(candidate).exists() {
            return Ok((*candidate).to_owned());
        }
    }
    if which_on_path(name) {
        return Ok(name.to_owned());
    }
    Err(format!("{name} is not installed"))
}

fn which_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).exists()))
        .unwrap_or(false)
}

/// Is `vif` actually operating as an access point on a concrete channel?
///
/// `iw dev <vif> info` reports `type AP` as soon as the vif exists, but only
/// prints a `channel` line once hostapd has configured the radio and started
/// beaconing, so the channel is the meaningful readiness signal.
fn interface_is_beaconing_ap(vif: &str) -> bool {
    for candidate in ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "iw"] {
        let Ok(output) = Command::new(candidate).args(["dev", vif, "info"]).output() else {
            continue;
        };
        if !output.status.success() {
            return false;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let is_ap = text.lines().any(|line| line.trim() == "type AP");
        let has_channel = text.lines().any(|line| line.trim().starts_with("channel "));
        return is_ap && has_channel;
    }
    false
}

/// Block until hostapd is beaconing on `vif`, or fail with hostapd's own reason.
/// On any failure the unit is stopped so a dead hostapd is never left behind.
fn wait_for_ap_enabled(vif: &str) -> Result<(), String> {
    let deadline = Instant::now() + AP_BEACON_TIMEOUT;
    // hostapd writes its PID file just after forking, so allow a brief grace
    // period before treating a missing PID file as a dead daemon.
    let liveness_grace = Instant::now() + Duration::from_secs(2);
    loop {
        if interface_is_beaconing_ap(vif) {
            return Ok(());
        }
        if Instant::now() >= liveness_grace && !pid_file_process_is_alive(HOSTAPD_PID_FILE) {
            let _ = stop_pid_file(HOSTAPD_PID_FILE, "hostapd");
            return Err(
                "hostapd exited immediately after start; the radio most likely refused to \
                 beacon on the station's channel"
                    .to_owned(),
            );
        }
        if Instant::now() >= deadline {
            let _ = stop_pid_file(HOSTAPD_PID_FILE, "hostapd");
            return Err(format!(
                "the access point on {vif} did not start beaconing within {} seconds",
                AP_BEACON_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(AP_BEACON_POLL_INTERVAL);
    }
}

/// Run `nmcli` (best-effort; used to mark the AP vif unmanaged so hostapd owns it).
fn run_nmcli(arguments: &[&str]) -> Result<(), String> {
    let nmcli = resolve_binary(&["/usr/bin/nmcli", "/bin/nmcli"], "nmcli")?;
    let output = Command::new(nmcli)
        .args(arguments)
        .output()
        .map_err(|error| format!("failed to execute nmcli: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

/// Flip the locally-administered bit of an interface's MAC so the AP vif does
/// not collide with the station's address.
fn derive_ap_mac(interface: &str) -> Option<String> {
    let path = std::path::Path::new("/sys/class/net")
        .join(interface)
        .join("address");
    let address = std::fs::read_to_string(path).ok()?;
    let mut octets: Vec<String> = address
        .trim()
        .split(':')
        .map(|octet| octet.to_owned())
        .collect();
    if octets.len() != 6 {
        return None;
    }
    let first = u8::from_str_radix(&octets[0], 16).ok()?;
    // Set the locally-administered bit, clear the multicast bit.
    let adjusted = (first | 0b0000_0010) & 0b1111_1110;
    octets[0] = format!("{adjusted:02x}");
    Some(octets.join(":"))
}

fn validate_phy_name(phy: &str) -> Result<(), String> {
    if phy.is_empty()
        || phy.len() > 32
        || !phy
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!("invalid wireless phy name: {phy}"));
    }
    Ok(())
}

fn privileged_apply(wifi_interface: &str, tun_interface: &str) -> Result<(), String> {
    validate_interface_name(wifi_interface).map_err(|error| error.to_string())?;
    validate_interface_name(tun_interface).map_err(|error| error.to_string())?;
    let _ = privileged_remove();
    enable_ipv4_forwarding()?;
    // The `input` chain is what keeps hotspot clients off the host's own
    // services. The vif has to sit in firewalld's `trusted` zone so firewalld
    // does not ICMP-reject client DHCP/DNS before it reaches dnsmasq — but
    // `trusted` accepts *everything*, which would expose every listening port on
    // this machine to anyone who joins the hotspot. A `drop` in our table is
    // final regardless of what any other table accepted, so the restriction
    // belongs here rather than in the zone assignment.
    //
    // ICMPv6 stays open because neighbour discovery needs it on any link that
    // has an IPv6 link-local address, which is every link.
    let ruleset = format!(
        "table inet {NFT_TABLE} {{\n  \
           chain input {{\n    \
             type filter hook input priority -10; policy accept;\n    \
             iifname \"{wifi_interface}\" udp dport 67 accept\n    \
             iifname \"{wifi_interface}\" udp dport 53 accept\n    \
             iifname \"{wifi_interface}\" tcp dport 53 accept\n    \
             iifname \"{wifi_interface}\" icmp type echo-request accept\n    \
             iifname \"{wifi_interface}\" meta l4proto ipv6-icmp accept\n    \
             iifname \"{wifi_interface}\" drop\n  \
           }}\n  \
           chain forward {{\n    \
             type filter hook forward priority -10; policy accept;\n    \
             iifname \"{wifi_interface}\" oifname \"{tun_interface}\" accept\n    \
             iifname \"{tun_interface}\" oifname \"{wifi_interface}\" ct state established,related accept\n    \
             iifname \"{wifi_interface}\" drop\n  \
           }}\n  \
           chain postrouting {{\n    \
             type nat hook postrouting priority srcnat; policy accept;\n    \
             iifname \"{wifi_interface}\" oifname \"{tun_interface}\" masquerade\n  \
           }}\n\
         }}\n"
    );
    run_nft(&["-f", "-"], Some(&ruleset))
}

/// Path holding the machine's own `ip_forward` setting from before we changed
/// it, so teardown can put it back.
const IP_FORWARD_SYSCTL: &str = "/proc/sys/net/ipv4/ip_forward";
const IP_FORWARD_SAVED: &str = "/run/vrghotspot/ip_forward.orig";

/// Turn on IPv4 forwarding, remembering what it was first.
///
/// Without this the setting is a one-way door: a single hotspot session would
/// leave the machine routing between all of its interfaces forever, including
/// long after the application is gone.
fn enable_ipv4_forwarding() -> Result<(), String> {
    let previous = std::fs::read_to_string(IP_FORWARD_SYSCTL).unwrap_or_default();
    let previous = previous.trim();
    // Only record the original value if we have not already done so during this
    // session; a second `apply` must not overwrite it with our own "1".
    if !std::path::Path::new(IP_FORWARD_SAVED).exists() && previous == "0" {
        let _ = std::fs::create_dir_all(AP_RUN_DIR);
        let _ = std::fs::write(IP_FORWARD_SAVED, "0\n");
    }
    std::fs::write(IP_FORWARD_SYSCTL, "1\n")
        .map_err(|error| format!("failed to enable IPv4 forwarding: {error}"))
}

/// Put `ip_forward` back the way we found it, if we were the ones who changed it.
fn restore_ipv4_forwarding() {
    if std::fs::read_to_string(IP_FORWARD_SAVED).is_ok() {
        let _ = std::fs::write(IP_FORWARD_SYSCTL, "0\n");
        let _ = std::fs::remove_file(IP_FORWARD_SAVED);
    }
}

fn privileged_remove() -> Result<(), String> {
    let output = Command::new("/usr/sbin/nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .output()
        .map_err(|error| format!("failed to execute nft: {error}"))?;
    // Restore forwarding whether or not the table existed: a previous run may
    // have been killed after enabling it but before installing the rules.
    restore_ipv4_forwarding();
    if output.status.success()
        || String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
    {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn run_ip(arguments: &[&str]) -> Result<(), String> {
    let output = Command::new("/usr/sbin/ip")
        .args(arguments)
        .output()
        .map_err(|error| format!("failed to execute ip: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

/// Run `iw`, searching both sbin and bin (distros disagree on its location).
fn run_iw(arguments: &[&str]) -> Result<(), String> {
    let mut last_error = String::new();
    for candidate in ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "iw"] {
        match Command::new(candidate).args(arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(format!(
                    "iw {} failed: {}",
                    arguments.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(format!(
        "failed to execute iw (install the `iw` package): {last_error}"
    ))
}

fn run_nft(arguments: &[&str], input: Option<&str>) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("/usr/sbin/nft")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to execute nft: {error}"))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| "failed to open nft stdin".to_owned())?
            .write_all(input.as_bytes())
            .map_err(|error| format!("failed to write nft rules: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for nft: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

/// Validate the credentials before they are interpolated into a hostapd
/// configuration that is written and executed as root.
///
/// Length alone is not enough. Both values are written verbatim into `key=value`
/// lines by [`build_hostapd_config`], and hostapd applies the LAST assignment of
/// a key it parses, so a value carrying a newline injects arbitrary directives:
/// a passphrase of `secret12\nwpa=0` produces an OPEN access point while the
/// interface still reports WPA2, and `\nbridge=br0` puts clients on a bridge
/// where the nftables forward-hook kill-switch never sees their traffic.
/// Rejecting control characters outright is safer than trying to escape them.
///
/// Each rejection returns its own variant. One `InvalidSsid` covering three
/// different problems meant a rejected control character was reported to the
/// person as a length problem, in a unit the check does not even use.
fn validate_interface_name(name: &str) -> Result<(), HotspotError> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(HotspotError::InvalidInterfaceName(name.to_owned()));
    }
    Ok(())
}

/// Every hostapd directive this application is allowed to emit.
///
/// The privileged helper refuses anything else. That closes the whole class of
/// problem rather than one instance of it: `bridge` would put clients on a
/// bridge the nftables kill-switch cannot police, `wpa_psk_file` and
/// `eap_user_file` make root read arbitrary paths, and `ctrl_interface` makes it
/// create a control socket wherever the caller likes.
const ALLOWED_HOSTAPD_KEYS: &[&str] = &[
    "interface",
    "driver",
    "ssid",
    "hw_mode",
    "channel",
    "auth_algs",
    "wmm_enabled",
    "ignore_broadcast_ssid",
    "wpa",
    "wpa_passphrase",
    "wpa_key_mgmt",
    "wpa_pairwise",
    "rsn_pairwise",
    "country_code",
    "ieee80211d",
    "ieee80211n",
    "ieee80211ac",
];

/// Check a hostapd configuration received on the helper's stdin.
///
/// This is defence in depth behind [`validate_credentials`]: the unprivileged
/// side is supposed to have rejected control characters already, but the root
/// side must not depend on that. Unknown keys are refused rather than dropped,
/// so a mistake shows up as a clear error instead of a silently different
/// network.
fn validate_hostapd_config(config: &str, expected_interface: &str) -> Result<(), String> {
    let mut declared_interface = None;
    for (number, line) in config.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "hostapd configuration line {} is not a key=value pair",
                number + 1
            ));
        };
        let key = key.trim();
        if !ALLOWED_HOSTAPD_KEYS.contains(&key) {
            return Err(format!("hostapd directive `{key}` is not permitted"));
        }
        if key == "interface" {
            declared_interface = Some(value.trim().to_owned());
        }
    }

    match declared_interface {
        Some(interface) if interface == expected_interface => Ok(()),
        Some(interface) => Err(format!(
            "hostapd configuration targets `{interface}` but the helper was asked \
             to start `{expected_interface}`"
        )),
        None => Err("hostapd configuration does not name an interface".to_owned()),
    }
}

/// Create a file that only root can read, without the world-readable window a
/// `write`-then-`chmod` sequence leaves open. Used for the hostapd
/// configuration, which carries the WPA passphrase.
fn write_private_file(path: &str, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to create {path}: {error}"))?;
    file.write_all(contents)
        .map_err(|error| format!("failed to write {path}: {error}"))
}

fn looks_like_tun(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("tun") || lower.contains("mihomo") || lower.contains("wireguard")
}

/// Resolve the mac80211 phy backing a wireless interface by reading
/// `/sys/class/net/<name>/phy80211/name`.
fn phy_for_interface(interface: &str) -> Option<String> {
    let path = std::path::Path::new("/sys/class/net")
        .join(interface)
        .join("phy80211")
        .join("name");
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Capture `iw phy <phy> info` once so both the interface-combination check and
/// the per-channel regulatory flags come from the same snapshot. `None` means
/// `iw` could not be run, so callers can distinguish "not supported" from "could
/// not determine".
fn probe_phy_info(phy: &str) -> Option<String> {
    for candidate in ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "iw"] {
        match Command::new(candidate).args(["phy", phy, "info"]).output() {
            Ok(output) if output.status.success() => {
                return Some(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Ok(_) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// A Wi-Fi band/channel pair as NetworkManager expects it in the
/// `802-11-wireless` setting. NetworkManager requires `band` whenever `channel`
/// is set, because channel numbers repeat across bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiChannel {
    /// NetworkManager band token: "bg" (2.4 GHz) or "a" (5/6 GHz).
    pub band: &'static str,
    pub channel: u32,
    pub frequency_mhz: u32,
}

/// Convert a station's operating frequency (MHz, as reported by NetworkManager's
/// AccessPoint.Frequency) into the band + channel pair an AP must use to stay on
/// the same channel. Returns `None` for frequencies outside the known plans.
pub fn channel_from_frequency(frequency_mhz: u32) -> Option<WifiChannel> {
    let (band, channel) = match frequency_mhz {
        // 2.4 GHz: channels 1-13 are 2412 + 5*(n-1).
        2412..=2472 if (frequency_mhz - 2412).is_multiple_of(5) => {
            ("bg", (frequency_mhz - 2412) / 5 + 1)
        }
        // Channel 14 is a Japan-only special case (not 5 MHz spaced).
        2484 => ("bg", 14),
        // 5 GHz: channel = (freq - 5000) / 5.
        5160..=5895 if (frequency_mhz - 5000).is_multiple_of(5) => {
            ("a", (frequency_mhz - 5000) / 5)
        }
        // 6 GHz (Wi-Fi 6E): channel = (freq - 5950) / 5. NetworkManager still
        // expects the "a" band token for the 5/6 GHz radio.
        5955..=7115 if (frequency_mhz - 5950).is_multiple_of(5) => {
            ("a", (frequency_mhz - 5950) / 5)
        }
        _ => return None,
    };
    Some(WifiChannel {
        band,
        channel,
        frequency_mhz,
    })
}

/// 5 GHz channels that are subject to radar detection (DFS). An access point
/// generally cannot be started on these, so a station sitting on a DFS channel
/// makes concurrent AP+STA impossible on that channel.
pub fn is_dfs_channel(channel: &WifiChannel) -> bool {
    channel.band == "a" && matches!(channel.frequency_mhz, 5260..=5720)
}

/// Whether the radio may host an access point on a given channel, according to
/// the per-frequency regulatory flags the kernel reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelApCapability {
    /// No blocking flags: the radio may beacon here.
    Allowed,
    /// `no IR` — initiating radiation is forbidden, so the radio may associate as
    /// a station but must never beacon. This is how Intel's LAR blocks 5 GHz AP.
    NoInitiatingRadiation,
    /// `radar detection` (DFS): an access point cannot be brought up here.
    RadarDetection,
}

/// Read the AP capability for `frequency_mhz` out of `iw phy <phy> info` output.
///
/// Frequency lines look like:
/// ```text
///     * 2442.0 MHz [7] (22.0 dBm)
///     * 5180.0 MHz [36] (22.0 dBm) (no IR)
///     * 5260.0 MHz [52] (22.0 dBm) (no IR, radar detection)
///     * 5700.0 MHz [140] (disabled)
/// ```
pub fn channel_ap_capability(iw_info: &str, frequency_mhz: u32) -> Option<ChannelApCapability> {
    for line in iw_info.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("* ") else {
            continue;
        };
        let Some((value, flags)) = rest.split_once(" MHz") else {
            continue;
        };
        // Frequencies are printed as "2442.0"; compare on the integer part.
        let matches = value
            .trim()
            .split('.')
            .next()
            .and_then(|whole| whole.parse::<u32>().ok())
            .is_some_and(|parsed| parsed == frequency_mhz);
        if !matches {
            continue;
        }
        let lowered = flags.to_ascii_lowercase();
        // "disabled" and "no IR" both mean we cannot beacon here.
        if lowered.contains("radar detection") {
            return Some(ChannelApCapability::RadarDetection);
        }
        if lowered.contains("no ir") || lowered.contains("disabled") {
            return Some(ChannelApCapability::NoInitiatingRadiation);
        }
        return Some(ChannelApCapability::Allowed);
    }
    None
}

/// Whether `iw`'s "valid interface combinations" output permits one managed
/// (station) interface and one AP interface at the same time on a single
/// channel — the requirement for sharing from a single adapter.
///
/// Combination lines look like:
/// ```text
/// valid interface combinations:
///  * #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1, total <= 3, #channels <= 2
/// ```
/// A driver that cannot do this prints "interface combinations are not
/// supported".
pub fn supports_concurrent_ap_sta(iw_info: &str) -> bool {
    let mut in_combinations = false;
    for line in iw_info.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("valid interface combinations") {
            in_combinations = true;
            continue;
        }
        if in_combinations {
            // A new unindented section ends the combinations block.
            if !trimmed.starts_with('*') && !line.starts_with(char::is_whitespace) {
                in_combinations = false;
                continue;
            }
            if trimmed.starts_with('*') && combination_allows_ap_and_sta(trimmed) {
                return true;
            }
        }
    }
    false
}

/// Does a single combination entry allow >=1 managed AND >=1 AP interface?
fn combination_allows_ap_and_sta(entry: &str) -> bool {
    let mut has_managed = false;
    let mut has_ap = false;
    // Each group looks like `#{ managed } <= 1` or `#{ AP, mesh point } <= 8`.
    for group in entry.split('#').filter(|part| part.contains('{')) {
        let Some(start) = group.find('{') else {
            continue;
        };
        let Some(end) = group.find('}') else { continue };
        let members = &group[start + 1..end];
        // The limit follows the closing brace, e.g. "} <= 1".
        let limit = group[end + 1..]
            .trim_start_matches([' ', '<', '=', ','])
            .split(|c: char| !c.is_ascii_digit())
            .find(|token| !token.is_empty())
            .and_then(|token| token.parse::<u32>().ok())
            .unwrap_or(0);
        if limit == 0 {
            continue;
        }
        for member in members.split(',') {
            match member.trim() {
                "managed" => has_managed = true,
                "AP" => has_ap = true,
                _ => {}
            }
        }
    }
    has_managed && has_ap
}

/// Names of the interfaces that currently carry a default route (IPv4 or IPv6),
/// read straight from the kernel via `/proc/net`. This is the ground truth for
/// "which interface is the machine's internet uplink". We must never turn such
/// an interface into an access point: switching a Wi-Fi radio from station to
/// AP mode tears down its upstream link and removes the default route, which is
/// exactly what leaves the Mihomo TUN with no egress ("default interface lost by
/// monitor" / "auto detect interface ... get empty name") and drops every
/// existing connection, including a remote VNC/SSH session.
fn default_route_interfaces() -> std::collections::HashSet<String> {
    let mut interfaces = std::collections::HashSet::new();
    collect_ipv4_default_routes(&mut interfaces);
    collect_ipv6_default_routes(&mut interfaces);
    interfaces
}

fn collect_ipv4_default_routes(interfaces: &mut std::collections::HashSet<String>) {
    if let Ok(contents) = std::fs::read_to_string("/proc/net/route") {
        parse_ipv4_default_routes(&contents, interfaces);
    }
}

fn parse_ipv4_default_routes(contents: &str, interfaces: &mut std::collections::HashSet<String>) {
    // `/proc/net/route` columns: Iface Destination Gateway Flags RefCnt Use
    // Metric Mask MTU Window IRTT. A default route has Destination `00000000`
    // and is flagged up (RTF_UP = 0x1). Destination/Flags are little-endian hex.
    for line in contents.lines().skip(1) {
        let mut columns = line.split_whitespace();
        let iface = columns.next();
        let destination = columns.next();
        let _gateway = columns.next();
        let flags = columns.next();
        if destination != Some("00000000") {
            continue;
        }
        // Treat unparseable flags leniently as "up"; the kernel only lists
        // active routes here anyway.
        let up = flags
            .and_then(|flags| u32::from_str_radix(flags, 16).ok())
            .map(|flags| flags & 0x1 != 0)
            .unwrap_or(true);
        if up && let Some(iface) = iface {
            interfaces.insert(iface.to_owned());
        }
    }
}

fn collect_ipv6_default_routes(interfaces: &mut std::collections::HashSet<String>) {
    if let Ok(contents) = std::fs::read_to_string("/proc/net/ipv6_route") {
        parse_ipv6_default_routes(&contents, interfaces);
    }
}

fn parse_ipv6_default_routes(contents: &str, interfaces: &mut std::collections::HashSet<String>) {
    // `/proc/net/ipv6_route` ends each row with the interface name; a default
    // route has an all-zero destination network and a zero prefix length.
    for line in contents.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 10 {
            continue;
        }
        let destination_network = columns[0];
        let destination_prefix = columns[1];
        let iface = columns[columns.len() - 1];
        if destination_network == "00000000000000000000000000000000"
            && destination_prefix == "00"
            && iface != "lo"
        {
            interfaces.insert(iface.to_owned());
        }
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[derive(Debug, Error)]
pub enum HotspotError {
    /// A D-Bus call to NetworkManager failed. The message deliberately carries
    /// the service's verbatim error text (including the D-Bus error name such as
    /// `org.freedesktop.NetworkManager.UnknownConnection`) — never a paraphrase,
    /// because guessing at causes is what made these failures hard to debug.
    #[error("NetworkManager D-Bus call failed: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("invalid NetworkManager object path: {0}")]
    ObjectPath(#[from] zbus::zvariant::Error),
    #[error("invalid NetworkManager property {property}: {reason}")]
    InvalidDbusProperty { property: String, reason: String },
    #[error("network adapter not found: {0}")]
    AdapterNotFound(String),
    #[error("no physical Wi-Fi adapter is managed by NetworkManager")]
    NoWifiAdapter,
    #[error(
        "Wi-Fi adapter {0} is currently providing this machine's internet connection; hosting the hotspot on it would drop all connectivity (including any remote VNC/SSH session). Provide internet through a different interface (Ethernet or a second Wi-Fi adapter), or choose another Wi-Fi adapter for the hotspot"
    )]
    UplinkInterfaceConflict(String),
    #[error(
        "cannot host an access point on {interface} while it is the only internet uplink: {reason}"
    )]
    ConcurrentApUnsupported { interface: String, reason: String },
    #[error(
        "the Wi-Fi uplink on {interface} is using DFS channel {channel}; an access point cannot be started on a radar-detection channel"
    )]
    DfsChannelUnsupported { interface: String, channel: u32 },
    /// The radio may not beacon on the station's current channel, so it cannot
    /// host an AP there while staying associated. `reason` quotes the actual
    /// regulatory flag reported by the kernel rather than assuming a band.
    #[error(
        "the Wi-Fi uplink on {interface} is on {band} channel {channel}, where this adapter cannot host an access point: {reason}"
    )]
    ApNotAllowedOnChannel {
        interface: String,
        channel: u32,
        band: &'static str,
        reason: String,
    },
    /// The Wi-Fi device never reached a state from which a connection can be
    /// activated. `detail` carries NetworkManager's own StateReason, which names
    /// the real blocker (e.g. `supplicant-failed`).
    #[error(
        "the Wi-Fi device {device} did not become ready for the access point within {seconds} seconds (last state: {state}; NetworkManager reports: {detail})"
    )]
    ApDeviceNotReady {
        device: String,
        state: String,
        detail: String,
        seconds: u64,
    },
    #[error("the Mihomo TUN interface is not ready")]
    NoTunInterface,
    #[error("NetworkManager deactivated the hotspot on {0} during startup")]
    ActivationFailed(String),
    /// Bringing up the single-radio AP knocked the station off its upstream
    /// network, so the AP was torn back down to keep the machine online.
    #[error(
        "hosting the access point on {station} dropped its upstream Wi-Fi association; the single radio could not sustain both roles at once, so the hotspot was stopped to keep this machine online"
    )]
    ConcurrentApDroppedStation { station: String },
    #[error("NetworkManager hotspot activation on {interface} timed out after {seconds} seconds")]
    ActivationTimedOut { interface: String, seconds: u64 },
    #[error(transparent)]
    Credentials(#[from] CredentialError),
    #[error("invalid Linux interface name: {0}")]
    InvalidInterfaceName(String),
    #[error("failed to locate the current executable: {0}")]
    CurrentExecutable(std::io::Error),
    #[error("failed to start pkexec: {0}")]
    PrivilegeHelper(std::io::Error),
    /// A privileged helper operation failed: nftables rules, firewalld zoning,
    /// policy routing, or AP virtual-interface management.
    #[error("privileged network configuration failed: {0}")]
    Nftables(String),
    #[error("network worker thread failed: {0}")]
    Worker(String),
}

impl HotspotError {
    /// An optional, ADDITIONAL suggestion. It never replaces the underlying
    /// error text: callers must always log the real message. A hint is only
    /// offered when this specific failure actually implies it — a blanket
    /// "check polkit / NetworkManager" on every D-Bus error previously buried the
    /// real cause (e.g. wpa_supplicant refusing an AP interface) under advice
    /// that had nothing to do with the problem.
    pub fn diagnostic_hint(&self) -> Option<&'static str> {
        match self {
            // Only a genuine connect/name-resolution failure implies the service
            // is missing. Method errors returned BY NetworkManager mean it is
            // running fine, so they must not produce polkit advice.
            Self::Dbus(error) if dbus_error_means_service_unreachable(error) => {
                Some("Ensure NetworkManager is running and reachable on the D-Bus system bus.")
            }
            Self::Dbus(error) if dbus_error_is_authorization(error) => Some(
                "Authorize the request when prompted; a graphical polkit authentication agent must be running.",
            ),
            Self::Dbus(error) if dbus_error_means_device_unavailable(error) => Some(
                "NetworkManager could not use the Wi-Fi device for the access point. Check `journalctl -u NetworkManager -u wpa_supplicant` around this timestamp: if wpa_supplicant reports \"couldn't grab this interface\", the radio cannot host an access point while associated on this channel — connect the uplink over Ethernet or move it to 2.4 GHz.",
            ),
            Self::Nftables(_) | Self::PrivilegeHelper(_) => Some(
                "Install nftables and polkit, then authorize the VRG Hotspot networking helper when prompted.",
            ),
            Self::UplinkInterfaceConflict(_) => Some(
                "Connect this machine to the internet through a different interface (Ethernet or a second Wi-Fi adapter) so the hotspot radio is free, or pick another Wi-Fi adapter for the hotspot, then start again.",
            ),
            Self::ConcurrentApUnsupported { .. } => Some(
                "This Wi-Fi adapter cannot host an access point while it is also the only internet connection. Connect an Ethernet cable (or a second Wi-Fi adapter) and start again; the hotspot will then use the Wi-Fi radio.",
            ),
            Self::ConcurrentApDroppedStation { .. } => Some(
                "This radio advertised AP+station support but could not keep the uplink while beaconing. Provide internet over Ethernet or a second Wi-Fi adapter, or reconnect the Wi-Fi uplink to a 2.4 GHz channel, then start again.",
            ),
            Self::ApNotAllowedOnChannel { .. } => Some(
                "Sharing from one radio requires the access point and the uplink to sit on the same channel. Reconnect the Wi-Fi uplink to a 2.4 GHz network and start again, or provide internet over Ethernet. (Many adapters, Intel included, may not beacon on 5 GHz: `iw phy phy0 info` marks those channels `no IR`.)",
            ),
            Self::DfsChannelUnsupported { .. } => Some(
                "Reconnect the Wi-Fi uplink to a 2.4 GHz network (or a non-DFS channel), or provide internet over Ethernet, then start again.",
            ),
            Self::ApDeviceNotReady { .. } => Some(
                "The Wi-Fi device never became usable for the access point. If NetworkManager reports `supplicant-failed` or `unmanaged`, check that wpa_supplicant is running and that the device is not set to unmanaged, then start again.",
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_interface_names() {
        assert!(validate_interface_name("wlan0").is_ok());
        assert!(validate_interface_name("tun;flush").is_err());
        assert!(validate_interface_name("interface-name-is-too-long").is_err());
    }

    #[test]
    fn validates_wpa_credentials() {
        assert!(validate_credentials("VPN-Hotspot", "password").is_ok());
        assert!(validate_credentials("", "password").is_err());
        assert!(validate_credentials("VPN-Hotspot", "short").is_err());
    }

    /// A newline in either field would inject directives into the hostapd
    /// configuration that `privileged_start_ap` executes as root. hostapd honours
    /// the last assignment of a key, so a passphrase carrying `wpa=0` overrides
    /// the `wpa=2` above it and the access point comes up completely open while
    /// the interface still claims WPA2.
    #[test]
    fn rejects_control_characters_that_would_inject_hostapd_directives() {
        assert!(validate_credentials("MyNet\nbridge=br0", "secret12").is_err());
        assert!(validate_credentials("MyNet\ninterface=wlan0", "secret12").is_err());
        assert!(validate_credentials("MyNet", "secret12\nwpa=0").is_err());
        assert!(validate_credentials("MyNet", "secret12\nbridge=br0").is_err());
        // A bare carriage return and a NUL are just as effective.
        assert!(validate_credentials("MyNet\rssid=Other", "secret12").is_err());
        assert!(validate_credentials("MyNet\0", "secret12").is_err());
    }

    /// The SSID limit is 32 octets, so a Cyrillic name runs out at 16 letters.
    /// The frontend must measure the same way; see `ssidProblem` in Settings.tsx.
    #[test]
    fn ssid_limit_counts_bytes_not_characters() {
        let sixteen_cyrillic = "СетьСетьСетьСеть"; // 16 chars, 32 bytes
        assert_eq!(sixteen_cyrillic.chars().count(), 16);
        assert_eq!(sixteen_cyrillic.len(), 32);
        assert!(validate_credentials(sixteen_cyrillic, "secret12").is_ok());

        let seventeen_cyrillic = "СетьСетьСетьСетьС"; // 17 chars, 34 bytes
        assert!(validate_credentials(seventeen_cyrillic, "secret12").is_err());
    }

    #[test]
    fn detects_ipv4_default_route_interface() {
        // Real-shape `/proc/net/route`: header + a default route (Destination
        // 00000000, RTF_UP|RTF_GATEWAY = 0003) on wlp0s20f3 plus an on-link
        // subnet route that must NOT be treated as a default route.
        let contents = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            wlp0s20f3\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            wlp0s20f3\t0002A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        let mut interfaces = std::collections::HashSet::new();
        parse_ipv4_default_routes(contents, &mut interfaces);
        assert!(interfaces.contains("wlp0s20f3"));
        assert_eq!(interfaces.len(), 1);
    }

    #[test]
    fn ignores_ipv4_route_without_up_flag() {
        // Destination 00000000 but flags 0000 (not up) must be ignored.
        let contents = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t00000000\t0000\t0\t0\t0\t00000000\t0\t0\t0\n";
        let mut interfaces = std::collections::HashSet::new();
        parse_ipv4_default_routes(contents, &mut interfaces);
        assert!(interfaces.is_empty());
    }

    #[test]
    fn detects_ipv6_default_route_interface() {
        // Default v6 route: all-zero dest network, prefix 00, iface last column.
        let default = "00000000000000000000000000000000 00 \
            00000000000000000000000000000000 00 \
            fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlp0s20f3";
        // A link-local /64 that is not a default route.
        let link_local = "fe800000000000000000000000000000 40 \
            00000000000000000000000000000000 00 \
            00000000000000000000000000000000 00000100 00000000 00000001 00000001 wlp0s20f3";
        let contents = format!("{default}\n{link_local}\n");
        let mut interfaces = std::collections::HashSet::new();
        parse_ipv6_default_routes(&contents, &mut interfaces);
        assert!(interfaces.contains("wlp0s20f3"));
    }

    #[test]
    fn uplink_conflict_is_reported_and_not_retryable() {
        let error = HotspotError::UplinkInterfaceConflict("wlp0s20f3".to_owned());
        // A clear, actionable hint is surfaced to the user.
        assert!(error.diagnostic_hint().is_some());
        // The message names the offending interface.
        assert!(error.to_string().contains("wlp0s20f3"));
    }

    #[test]
    fn maps_frequencies_to_bands_and_channels() {
        let ch1 = channel_from_frequency(2412).expect("2412 MHz is channel 1");
        assert_eq!((ch1.band, ch1.channel), ("bg", 1));
        let ch6 = channel_from_frequency(2437).expect("2437 MHz is channel 6");
        assert_eq!((ch6.band, ch6.channel), ("bg", 6));
        let ch13 = channel_from_frequency(2472).expect("2472 MHz is channel 13");
        assert_eq!((ch13.band, ch13.channel), ("bg", 13));
        // Japan-only channel 14 is not on the 5 MHz grid.
        let ch14 = channel_from_frequency(2484).expect("2484 MHz is channel 14");
        assert_eq!((ch14.band, ch14.channel), ("bg", 14));
        // 5 GHz
        let ch36 = channel_from_frequency(5180).expect("5180 MHz is channel 36");
        assert_eq!((ch36.band, ch36.channel), ("a", 36));
        let ch149 = channel_from_frequency(5745).expect("5745 MHz is channel 149");
        assert_eq!((ch149.band, ch149.channel), ("a", 149));
        // Nonsense frequencies are rejected rather than silently mapped.
        assert!(channel_from_frequency(1234).is_none());
        assert!(channel_from_frequency(2413).is_none());
    }

    #[test]
    fn identifies_dfs_channels() {
        let ch52 = channel_from_frequency(5260).expect("channel 52");
        assert!(is_dfs_channel(&ch52), "channel 52 is DFS");
        let ch100 = channel_from_frequency(5500).expect("channel 100");
        assert!(is_dfs_channel(&ch100), "channel 100 is DFS");
        let ch36 = channel_from_frequency(5180).expect("channel 36");
        assert!(!is_dfs_channel(&ch36), "channel 36 is not DFS");
        let ch6 = channel_from_frequency(2437).expect("channel 6");
        assert!(!is_dfs_channel(&ch6), "2.4 GHz is never DFS");
    }

    #[test]
    fn detects_concurrent_ap_sta_support() {
        // Real Intel AX201/AX211 output: managed and AP in separate groups on the
        // same combination line.
        let intel = "\
Wiphy phy0
	valid interface combinations:
		 * #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1, #{ P2P-device } <= 1,
		   total <= 3, #channels <= 2
";
        assert!(supports_concurrent_ap_sta(intel));

        // ath9k-style: shared pools, single channel.
        let ath9k = "\
	valid interface combinations:
		 * #{ managed } <= 2048, #{ AP, mesh point } <= 8, total <= 2048, #channels <= 1, STA/AP BI must match
";
        assert!(supports_concurrent_ap_sta(ath9k));

        // Drivers that cannot do it at all.
        let unsupported = "\
Wiphy phy0
	interface combinations are not supported
";
        assert!(!supports_concurrent_ap_sta(unsupported));

        // AP present but no station role in the same combination.
        let ap_only = "\
	valid interface combinations:
		 * #{ AP } <= 1, total <= 1, #channels <= 1
";
        assert!(!supports_concurrent_ap_sta(ap_only));
    }

    fn wifi_adapter(name: &str, associated: bool, frequency: Option<u32>) -> NetworkAdapter {
        NetworkAdapter {
            id: format!("/org/freedesktop/NetworkManager/Devices/{name}"),
            name: name.to_owned(),
            kind: AdapterKind::WiFi,
            is_up: true,
            has_ip_address: true,
            has_default_route: associated,
            supports_hotspot: true,
            is_associated_station: associated,
            station_frequency_mhz: frequency,
            phy: Some("phy0".to_owned()),
        }
    }

    fn ethernet_adapter(name: &str, has_default_route: bool) -> NetworkAdapter {
        NetworkAdapter {
            id: format!("/org/freedesktop/NetworkManager/Devices/{name}"),
            name: name.to_owned(),
            kind: AdapterKind::Ethernet,
            is_up: true,
            has_ip_address: true,
            has_default_route,
            supports_hotspot: false,
            is_associated_station: false,
            station_frequency_mhz: None,
            phy: None,
        }
    }

    #[test]
    fn counts_only_unexpired_dhcp_leases() {
        let now = 1_700_000_000;
        let leases = concat!(
            "1700000600 aa:bb:cc:dd:ee:01 10.42.0.10 quest-2 01:aa:bb:cc:dd:ee:01\n",
            "1699999400 aa:bb:cc:dd:ee:02 10.42.0.11 old-phone *\n",
            "0 aa:bb:cc:dd:ee:03 10.42.0.12 static-device *\n",
            "\n",
            "garbage line without an expiry\n",
        );
        // Two live devices: the unexpired lease and the infinite one.
        assert_eq!(count_active_leases(leases, now), 2);
    }

    #[test]
    fn counts_nothing_for_an_empty_lease_file() {
        assert_eq!(count_active_leases("", 1_700_000_000), 0);
    }

    #[test]
    fn detects_a_tethered_phone_as_a_wired_uplink() {
        // A phone in USB-modem mode is an ordinary Ethernet device to the kernel.
        let adapters = [
            wifi_adapter("wlp0s20f3", false, None),
            ethernet_adapter("enp0s20u1", true),
        ];
        let uplink = UplinkStatus::from_adapters(&adapters);
        assert!(uplink.wired_present);
        assert!(uplink.wired_has_internet);
        assert!(uplink.any_uplink);
        assert_eq!(uplink.wired_interface.as_deref(), Some("enp0s20u1"));
    }

    #[test]
    fn reports_no_wire_when_only_wifi_is_connected() {
        let adapters = [wifi_adapter("wlp0s20f3", true, Some(2412))];
        let uplink = UplinkStatus::from_adapters(&adapters);
        assert!(!uplink.wired_present);
        assert!(!uplink.wired_has_internet);
        // Wi-Fi still routes, so the machine is online — the wire simply is not.
        assert!(uplink.any_uplink);
    }

    #[test]
    fn prefers_the_wired_link_that_actually_routes() {
        // Two Ethernet devices: an idle dock port and the tethered phone.
        let adapters = [
            ethernet_adapter("enp0s31f6", false),
            ethernet_adapter("enp0s20u1", true),
        ];
        let uplink = UplinkStatus::from_adapters(&adapters);
        assert_eq!(uplink.wired_interface.as_deref(), Some("enp0s20u1"));
        assert!(uplink.wired_has_internet);
    }

    #[test]
    fn wire_without_internet_is_still_reported_as_present() {
        // Cable in, no address upstream yet: the UI says "connected, no internet"
        // rather than pretending nothing is plugged in.
        let adapters = [ethernet_adapter("enp0s20u1", false)];
        let uplink = UplinkStatus::from_adapters(&adapters);
        assert!(uplink.wired_present);
        assert!(!uplink.wired_has_internet);
        assert!(!uplink.any_uplink);
    }

    #[test]
    fn idle_wifi_is_used_directly() {
        let wifi = wifi_adapter("wlp0s20f3", false, None);
        let adapters = [wifi.clone()];
        assert_eq!(
            plan_ap_hosting(&wifi, &adapters, Some(true), None).expect("idle radio is usable"),
            ApHosting::DirectDevice
        );
    }

    #[test]
    fn ethernet_uplink_frees_the_associated_wifi_radio() {
        // The reported regression: with an Ethernet cable connected, the hotspot
        // must start on the Wi-Fi radio without disabling Wi-Fi by hand, even
        // though NetworkManager keeps a default route on both links.
        let wifi = wifi_adapter("wlp0s20f3", true, Some(5180));
        let adapters = [ethernet_adapter("enp0s31f6", true), wifi.clone()];
        assert_eq!(
            plan_ap_hosting(&wifi, &adapters, Some(true), None)
                .expect("ethernet keeps the machine online"),
            ApHosting::DirectDevice
        );
    }

    #[test]
    fn single_wifi_uplink_pins_the_station_channel_on_the_same_device() {
        // 2.4 GHz station on a driver that supports AP+STA: host the AP on the
        // SAME device pinned to the station's channel. No vif is pre-created,
        // because wpa_supplicant refuses to adopt one.
        let wifi = wifi_adapter("wlp0s20f3", true, Some(2437));
        let adapters = [wifi.clone()];
        let hosting = plan_ap_hosting(
            &wifi,
            &adapters,
            Some(true),
            Some(ChannelApCapability::Allowed),
        )
        .expect("concurrent AP+STA on one channel");
        match hosting {
            ApHosting::SameDevicePinnedChannel { channel } => {
                assert_eq!((channel.band, channel.channel), ("bg", 6));
            }
            other => panic!("expected a pinned-channel AP on the same device, got {other:?}"),
        }
    }

    #[test]
    fn station_channel_that_forbids_beaconing_is_rejected() {
        // Channel 36 is flagged `no IR` on this radio: it may associate there but
        // must not beacon, so the AP cannot follow the station.
        let wifi = wifi_adapter("wlp0s20f3", true, Some(5180));
        let adapters = [wifi.clone()];
        let error = plan_ap_hosting(
            &wifi,
            &adapters,
            Some(true),
            Some(ChannelApCapability::NoInitiatingRadiation),
        )
        .expect_err("cannot beacon on a no-IR channel");
        match &error {
            HotspotError::ApNotAllowedOnChannel {
                channel,
                band,
                reason,
                ..
            } => {
                assert_eq!(*channel, 36);
                assert_eq!(*band, "a");
                // The message must quote the real regulatory reason, not guess.
                assert!(reason.contains("no IR"), "reason was: {reason}");
            }
            other => panic!("expected ApNotAllowedOnChannel, got {other:?}"),
        }
        assert!(error.diagnostic_hint().is_some());
    }

    #[test]
    fn unknown_capability_on_5ghz_is_refused_rather_than_risked() {
        // The reported 5 GHz failure: associated on 5 GHz as the only uplink, and
        // the regulatory flags could not be read. Trying anyway is what cost the
        // machine its connection, so planning must refuse instead.
        let wifi = wifi_adapter("wlp0s20f3", true, Some(5180));
        let adapters = [wifi.clone()];
        let error = plan_ap_hosting(&wifi, &adapters, Some(true), None)
            .expect_err("unknown 5 GHz capability must not be gambled on");
        match &error {
            HotspotError::ApNotAllowedOnChannel { band, channel, .. } => {
                assert_eq!(*band, "a");
                assert_eq!(*channel, 36);
            }
            other => panic!("expected ApNotAllowedOnChannel, got {other:?}"),
        }
        assert!(error.diagnostic_hint().is_some());
    }

    #[test]
    fn unknown_capability_on_24ghz_still_proceeds() {
        // 2.4 GHz beaconing is near-universal, so an unreadable flag there must
        // not block sharing — only 5 GHz gets the conservative treatment.
        let wifi = wifi_adapter("wlp0s20f3", true, Some(2437));
        let adapters = [wifi.clone()];
        let hosting = plan_ap_hosting(&wifi, &adapters, Some(true), None)
            .expect("2.4 GHz stays permissive when flags are unknown");
        assert!(matches!(hosting, ApHosting::SameDevicePinnedChannel { .. }));
    }

    #[test]
    fn hostapd_config_sets_regulatory_country_for_5ghz() {
        // Without `country_code` hostapd refuses to bring up a 5 GHz AP at all.
        let channel = channel_from_frequency(5180).expect("channel 36");
        let config = build_hostapd_config("vrghotspot-ap", channel, "SSID", "secret12", Some("RU"));
        assert!(config.contains("hw_mode=a"), "config was: {config}");
        assert!(config.contains("country_code=RU"), "config was: {config}");
        assert!(config.contains("ieee80211d=1"), "config was: {config}");
        assert!(config.contains("ieee80211ac=1"), "config was: {config}");
        assert!(config.contains("channel=36"), "config was: {config}");

        // 2.4 GHz stays on hw_mode=g and must not claim 11ac.
        let channel = channel_from_frequency(2437).expect("channel 6");
        let config = build_hostapd_config("vrghotspot-ap", channel, "SSID", "secret12", None);
        assert!(config.contains("hw_mode=g"), "config was: {config}");
        assert!(!config.contains("ieee80211ac"), "config was: {config}");
        assert!(!config.contains("country_code"), "config was: {config}");
    }

    #[test]
    fn helper_failure_reason_drops_the_go_bridge_banner() {
        // Verbatim shape of a real failure: the Go core's startup banner arrived
        // on the helper's stderr ahead of the actual kernel error, and reporting
        // it verbatim hid the cause behind build details.
        let stderr =
            b"core-bridge initialized: go=go1.26.5, os=linux, arch=amd64, mihomo=v1.19.28\n\
                       RTNETLINK answers: Device or resource busy\n";
        let reason = helper_failure_reason(stderr);
        assert_eq!(reason, "RTNETLINK answers: Device or resource busy");

        // A banner on its own must not collapse to an empty, useless message.
        let only_banner = b"core-bridge initialized: go=go1.26.5\n";
        assert!(!helper_failure_reason(only_banner).is_empty());
    }

    #[test]
    fn radar_channel_is_reported_as_dfs() {
        let wifi = wifi_adapter("wlp0s20f3", true, Some(5260));
        let adapters = [wifi.clone()];
        let error = plan_ap_hosting(
            &wifi,
            &adapters,
            Some(true),
            Some(ChannelApCapability::RadarDetection),
        )
        .expect_err("cannot host an AP on a DFS channel");
        assert!(matches!(error, HotspotError::DfsChannelUnsupported { .. }));
    }

    #[test]
    fn parses_channel_flags_from_real_iw_output() {
        // Verbatim excerpt from the reporting machine's `iw list` (Intel 9560):
        // every 5 GHz channel is `no IR`, 2.4 GHz channels are clean.
        let info = "\
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (22.0 dBm)
			* 2442.0 MHz [7] (22.0 dBm)
	Band 2:
		Frequencies:
			* 5180.0 MHz [36] (22.0 dBm) (no IR)
			* 5260.0 MHz [52] (22.0 dBm) (no IR, radar detection)
			* 5700.0 MHz [140] (disabled)
";
        assert_eq!(
            channel_ap_capability(info, 2442),
            Some(ChannelApCapability::Allowed)
        );
        assert_eq!(
            channel_ap_capability(info, 5180),
            Some(ChannelApCapability::NoInitiatingRadiation)
        );
        // radar detection wins over the accompanying `no IR`.
        assert_eq!(
            channel_ap_capability(info, 5260),
            Some(ChannelApCapability::RadarDetection)
        );
        assert_eq!(
            channel_ap_capability(info, 5700),
            Some(ChannelApCapability::NoInitiatingRadiation)
        );
        // A frequency the radio does not list at all.
        assert_eq!(channel_ap_capability(info, 5955), None);
    }

    #[test]
    fn real_adapter_combinations_allow_ap_plus_station() {
        // Verbatim from the reporting machine: the first bullet has no AP, the
        // second does. The parser must find the AP-capable one.
        let info = "\
	valid interface combinations:
		 * #{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, #{ P2P-device } <= 1,
		   total <= 3, #channels <= 2
		 * #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1, #{ P2P-device } <= 1,
		   total <= 3, #channels <= 1
";
        assert!(supports_concurrent_ap_sta(info));
    }

    #[test]
    fn single_wifi_uplink_rejected_when_driver_lacks_support() {
        let wifi = wifi_adapter("wlp0s20f3", true, Some(2437));
        let adapters = [wifi.clone()];
        let error = plan_ap_hosting(
            &wifi,
            &adapters,
            Some(false),
            Some(ChannelApCapability::Allowed),
        )
        .expect_err("driver cannot do AP+STA");
        assert!(matches!(
            error,
            HotspotError::ConcurrentApUnsupported { .. }
        ));
        assert!(error.diagnostic_hint().is_some());
    }

    #[test]
    fn derived_ap_mac_sets_local_bit() {
        // Not a filesystem test: verify the bit math on a representative address.
        let first = u8::from_str_radix("a4", 16).expect("hex");
        let adjusted = (first | 0b0000_0010) & 0b1111_1110;
        assert_eq!(format!("{adjusted:02x}"), "a6");
    }
}
