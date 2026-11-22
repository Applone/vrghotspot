use crate::config::geodata::{GeoDataError, GeoDataSettings, ensure_geo_data, update_geo_data};
use crate::config::subscription::{
    StoredSubscription, StoredVpnProfile, SubscriptionError, SubscriptionInfo, sanitize_proxy,
};
use crate::core::config::{CoreConfig, CoreConfigError};
use crate::core::process::{CoreHandle, CoreManager, CoreProcessError};
use crate::os::hotspot::{
    AdapterKind, HotspotController as SystemHotspotController, HotspotError, NetworkAdapter,
    SharingSession, TunnelRoutingSession, UplinkStatus, tunnel_device_present,
};
use crate::os::{
    app_config_dir,
    conflicts::{ConflictError, ConflictScanner},
};
use crate::ui::events::{EventSink, UiEvent, UiEventSink};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Instant, sleep, sleep_until, timeout, timeout_at};
use tracing::{error, info, warn};

mod profiles;

use uuid::Uuid;

const SETTINGS_FILE: &str = "settings.json";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(80 + TUNNEL_PROBE_DEADLINE.as_secs());
const SHARING_READY_TIMEOUT: Duration = Duration::from_secs(30);
const SHARING_TUN_READY_POLL: Duration = Duration::from_millis(500);
/// How long to wait for the embedded core to bring up its TUN device before
/// declaring the start failed. The device appears within milliseconds when the
/// process has the required privileges.
const TUN_READY_TIMEOUT: Duration = Duration::from_secs(5);
const TUN_READY_POLL: Duration = Duration::from_millis(250);

/// After Mihomo starts, its TUN inbound hijacks the whole default route
/// (`autoSystemRoutingTable` splits it into `0.0.0.0/1` + `128.0.0.0/1`). If the
/// selected server is unreachable, every packet is then routed into a tunnel
/// that drops it. We therefore probe real egress after NetworkManager has had a
/// chance to activate the hotspot. Probe failure is diagnostic rather than a
/// startup gate because captive-portal endpoints can be blocked independently.
const TUNNEL_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
// Windows can take longer to establish the first outbound proxy connection.
const TUNNEL_PROBE_DEADLINE: Duration = Duration::from_secs(if cfg!(windows) { 60 } else { 25 });
const TUNNEL_PROBE_RETRY_DELAY: Duration = Duration::from_secs(2);
/// Plain-HTTP captive-portal probes that answer with a tiny success body. HTTP
/// (not HTTPS) keeps the check cheap and avoids TLS failures masking a working
/// tunnel; two independent hosts guard against one endpoint being down.
const TUNNEL_PROBE_URLS: &[&str] = &[
    "http://cp.cloudflare.com/",
    "http://www.gstatic.com/generate_204",
];
const TUNNEL_HEALTHCHECK_DISABLE_ENV: &str = "VRG_SKIP_TUNNEL_HEALTHCHECK";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppSettings {
    pub user_agent_override: Option<String>,
    pub profiles: Vec<StoredVpnProfile>,
    pub selected_profile_id: Option<String>,
    #[serde(default)]
    pub hotspot_wifi_interface: Option<String>,
    #[serde(default = "default_enable_sharing")]
    pub enable_sharing: bool,
    #[serde(default = "default_hotspot_ssid")]
    pub hotspot_ssid: String,
    #[serde(default)]
    pub hotspot_passphrase: String,
    #[serde(default)]
    pub subscriptions: Vec<StoredSubscription>,
    #[serde(default)]
    installation_id: Option<Uuid>,
    #[serde(default, skip_serializing)]
    subscription_url: String,
    #[serde(default, skip_serializing)]
    subscription_info: SubscriptionInfo,
    /// Cleared once the welcome screen has been completed.
    #[serde(default)]
    pub onboarding_complete: bool,
    pub geo_data: GeoDataSettings,
}

const DEFAULT_HOTSPOT_SSID: &str = "VPN-Hotspot";

fn default_hotspot_ssid() -> String {
    DEFAULT_HOTSPOT_SSID.to_owned()
}

fn default_enable_sharing() -> bool {
    true
}

impl AppSettings {
    pub fn from_env() -> Self {
        Self {
            user_agent_override: std::env::var("VRG_USER_AGENT").ok(),
            profiles: Vec::new(),
            selected_profile_id: None,
            hotspot_wifi_interface: std::env::var("VRG_WIFI_INTERFACE").ok(),
            enable_sharing: std::env::var("VRG_ENABLE_SHARING")
                .map(|value| {
                    !matches!(
                        value.to_ascii_lowercase().as_str(),
                        "0" | "false" | "no" | "off" | "n"
                    )
                })
                .unwrap_or(true),
            hotspot_ssid: std::env::var("VRG_HOTSPOT_SSID")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_HOTSPOT_SSID.to_owned()),
            hotspot_passphrase: std::env::var("VRG_HOTSPOT_PASSPHRASE").unwrap_or_default(),
            subscriptions: profiles::seeded_subscriptions(),
            installation_id: None,
            subscription_url: String::new(),
            subscription_info: SubscriptionInfo::default(),
            onboarding_complete: false,
            geo_data: GeoDataSettings::default(),
        }
    }

    pub fn load_or_env() -> Self {
        match Self::load_from_disk() {
            Ok(settings) => settings,
            Err(err) => {
                // Falling back to defaults means the profile list is about to be
                // replaced by an empty one, and the next save would overwrite the
                // only copy. Keep the unreadable file so it can be recovered.
                let path = settings_path();
                if path.exists() {
                    let salvaged = path.with_extension("json.corrupt");
                    match fs::rename(&path, &salvaged) {
                        Ok(()) => error!(
                            error = %err,
                            salvaged = %salvaged.display(),
                            "settings could not be read; kept a copy and started from defaults"
                        ),
                        Err(rename_error) => error!(
                            error = %err,
                            rename_error = %rename_error,
                            "settings could not be read and could not be preserved"
                        ),
                    }
                } else {
                    warn!(error = %err, "failed to load settings, using environment defaults");
                }
                Self::from_env()
            }
        }
    }

    pub fn load_from_disk() -> Result<Self, SettingsPersistenceError> {
        let path = settings_path();
        if !path.exists() {
            return Ok(Self::from_env());
        }

        let content = fs::read_to_string(path)?;
        let mut settings: Self = serde_json::from_str(&content)?;
        settings.migrate_subscriptions();
        Ok(settings)
    }

    /// Persist the settings atomically, readable only by their owner.
    ///
    /// This file holds the Wi-Fi passphrase and the subscription URL (which
    /// normally carries a per-user token), so it should not be world-readable. It
    /// is also the only record of the user's profiles: a plain `write` that is
    /// interrupted leaves a truncated file behind, and the recovery path above
    /// then has to deal with it. Write to a temporary file, flush it, and rename
    /// it into place.
    pub fn save_to_disk(&self) -> Result<(), SettingsPersistenceError> {
        use std::io::Write;
        let path = settings_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;

        let temporary = path.with_extension("json.tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        {
            let mut file = options.open(&temporary)?;
            file.write_all(content.as_bytes())?;
            // Durable before it becomes the real file, so a crash cannot leave a
            // renamed-but-empty settings.json behind.
            file.sync_all()?;
        }
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    pub fn selected_profile(&self) -> Option<&StoredVpnProfile> {
        let selected_id = self.selected_profile_id.as_deref()?;
        self.profiles
            .iter()
            .find(|profile| profile.id == selected_id)
    }

    pub fn describe_for_logs(&self) -> String {
        format!(
            "user_agent_override_configured={}, profiles={}, selected_profile_configured={}, core_backend=embedded-mihomo, sharing_private_adapter_configured={}, enable_internet_sharing={}, hotspot_ssid_length={}, hotspot_passphrase_configured={}, {}",
            self.user_agent_override.is_some(),
            self.profiles.len(),
            self.selected_profile_id.is_some(),
            self.hotspot_wifi_interface.is_some(),
            self.enable_sharing,
            self.hotspot_ssid.len(),
            !self.hotspot_passphrase.is_empty(),
            self.geo_data.describe_for_logs()
        )
    }

    pub fn with_resolved_geo_data(&self) -> Self {
        let mut settings = self.clone();
        settings.geo_data = self.geo_data.with_resolved_defaults();
        settings
    }
}

pub type RuntimeSettings = AppSettings;

fn settings_path() -> PathBuf {
    app_config_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join(SETTINGS_FILE)
}

#[derive(Debug, Error)]
pub enum SettingsPersistenceError {
    #[error("failed to read or write settings: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse settings JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HotspotStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
}

pub struct HotspotController<S = UiEventSink> {
    settings: Arc<RwLock<AppSettings>>,
    running: Arc<Mutex<Option<RunningApp>>>,
    lifecycle: Mutex<()>,
    subscription_refresh: Mutex<()>,
    status: Arc<RwLock<HotspotStatus>>,
    #[cfg(windows)]
    last_hotspot_adapters: std::sync::Mutex<Vec<NetworkAdapter>>,
    ui: S,
}

pub type AppRuntime<S = UiEventSink> = HotspotController<S>;

pub struct RunningApp {
    sharing_session: Option<SharingSession>,
    #[cfg(windows)]
    ics_signature_mismatch: Option<crate::os::hotspot::IcsSignatureMismatch>,
    core: CoreHandle,
    tunnel_routing: Arc<TunnelRoutingSession>,
}

impl RunningApp {
    pub fn process_id(&self) -> Option<u32> {
        self.core.process_id()
    }

    pub async fn wait(self) -> Result<(), AppError> {
        let signal = tokio::signal::ctrl_c()
            .await
            .map_err(CoreProcessError::ShutdownSignal);
        let result = self.stop().await;
        signal?;
        result
    }

    pub async fn stop(self) -> Result<(), AppError> {
        let Self {
            core,
            sharing_session,
            tunnel_routing,
            ..
        } = self;
        let sharing_result = match sharing_session {
            Some(session) => disable_sharing(session).await,
            None => Ok(()),
        };
        let core_result = core.stop().await;
        drop(tunnel_routing);
        sharing_result?;
        Ok(core_result?)
    }
}

impl HotspotController<UiEventSink> {
    pub fn new(settings: AppSettings) -> Self {
        Self::with_event_sink(settings, UiEventSink::default())
    }
}

impl<S> HotspotController<S>
where
    S: Clone + Send + Sync + 'static + EventSink,
{
    pub fn with_event_sink(settings: AppSettings, ui: S) -> Self {
        Self {
            settings: Arc::new(RwLock::new(settings.with_resolved_geo_data())),
            running: Arc::new(Mutex::new(None)),
            lifecycle: Mutex::new(()),
            subscription_refresh: Mutex::new(()),
            status: Arc::new(RwLock::new(HotspotStatus::Stopped)),
            #[cfg(windows)]
            last_hotspot_adapters: std::sync::Mutex::default(),
            ui,
        }
    }

    pub async fn settings(&self) -> AppSettings {
        self.settings.read().await.clone()
    }

    async fn observe<T>(
        &self,
        operation: &'static str,
        future: impl std::future::Future<Output = Result<T, AppError>>,
    ) -> Result<T, AppError> {
        let result = future.await;
        if let Err(error) = &result {
            error!(operation, error = %error, "application operation failed");
        }
        result
    }

    #[tracing::instrument(skip_all)]
    pub async fn update_settings(&self, settings: AppSettings) -> Result<(), AppError> {
        self.observe("settings_save", self.update_settings_inner(settings))
            .await
    }

    async fn update_settings_inner(&self, settings: AppSettings) -> Result<(), AppError> {
        let running = self.running.lock().await;
        if running.is_some() {
            return Err(AppError::SettingsLockedWhileRunning);
        }

        let mut stored = self.settings.write().await;
        let mut settings = settings.with_resolved_geo_data();
        settings.profiles.clone_from(&stored.profiles);
        settings.subscriptions.clone_from(&stored.subscriptions);
        settings
            .selected_profile_id
            .clone_from(&stored.selected_profile_id);
        settings.installation_id = stored.installation_id;
        settings.onboarding_complete = stored.onboarding_complete;
        info!(settings = %settings.describe_for_logs(), "updating application settings");
        settings.save_to_disk()?;
        *stored = settings;
        drop(stored);
        drop(running);
        self.ui.emit(UiEvent::SettingsChanged);
        Ok(())
    }

    pub async fn status(&self) -> HotspotStatus {
        *self.status.read().await
    }

    pub fn discover_wifi_adapters(&self) -> Result<Vec<NetworkAdapter>, AppError> {
        Ok(SystemHotspotController::system().eligible_wifi_adapters()?)
    }

    #[cfg(windows)]
    pub fn discover_hotspot_adapters(&self, selected: Option<&str>) -> Vec<NetworkAdapter> {
        let adapters = SystemHotspotController::system()
            .hotspot_adapters()
            .unwrap_or_default();
        let last_seen = self.last_hotspot_adapters.lock().ok();
        hotspot_adapter_choices(
            adapters,
            last_seen.as_deref().map(Vec::as_slice).unwrap_or_default(),
            selected,
        )
    }

    pub fn has_physical_wifi_adapter(&self) -> Result<bool, AppError> {
        Ok(SystemHotspotController::system().has_physical_wifi_adapter()?)
    }

    /// What the machine currently has to share. Polled by the interface so a
    /// phone switched into USB-modem mode is noticed without the user acting.
    pub fn uplink_status(&self) -> Result<UplinkStatus, AppError> {
        Ok(SystemHotspotController::system().uplink_status()?)
    }

    /// How many devices hold a lease on the hotspot, or `None` when it is not
    /// running. Never blocks the caller: a start or stop in progress holds the
    /// runtime lock, and a status poll must not wait behind it.
    pub fn connected_clients(&self) -> Option<u32> {
        let running = self.running.try_lock().ok()?;
        let session = running.as_ref()?.sharing_session.as_ref()?;
        session.connected_clients()
    }

    pub async fn sharing_active(&self) -> bool {
        self.running
            .lock()
            .await
            .as_ref()
            .is_some_and(|running| running.sharing_session.is_some())
    }

    #[cfg(windows)]
    pub(crate) async fn ics_signature_mismatch(
        &self,
    ) -> Option<crate::os::hotspot::IcsSignatureMismatch> {
        self.running
            .lock()
            .await
            .as_ref()?
            .ics_signature_mismatch
            .clone()
    }

    pub async fn complete_onboarding(&self) -> Result<(), AppError> {
        self.change_profiles(|settings| {
            settings.onboarding_complete = true;
            Ok(())
        })
        .await
    }

    #[tracing::instrument(skip_all)]
    pub async fn update_geo_data(&self) -> Result<(), AppError> {
        self.observe("geodata_update", self.update_geo_data_inner())
            .await
    }

    async fn update_geo_data_inner(&self) -> Result<(), AppError> {
        let settings = self.settings().await;
        info!(geo_data = %settings.geo_data.describe_for_logs(), "updating Mihomo geo data");
        let asset_dir = update_geo_data(&settings.geo_data).await?;
        self.ui.emit(UiEvent::SettingsChanged);
        info!(asset_dir = %asset_dir.display(), "updated Mihomo geo data from settings");
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn start_hotspot(&self) -> Result<(), AppError> {
        let _lifecycle = self.lifecycle.lock().await;

        // Stop any existing instance first: the embedded core owns the TUN
        // device and the outbound policy-routing rule, so a second start must
        // not race a still-running one.
        {
            let existing = self.running.lock().await.take();
            if let Some(running) = existing {
                info!("stopping existing Mihomo instance before restart");
                if let Err(err) = running.stop().await {
                    warn!(error = %err, "failed to stop previous Mihomo instance");
                }
                // Brief delay to let the OS release the socket
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
        }

        self.set_status(HotspotStatus::Starting).await;
        let settings = self.settings().await;

        match timeout(STARTUP_TIMEOUT, self.start_inner(settings)).await {
            Ok(Ok(running)) => {
                let pid = running.process_id();
                *self.running.lock().await = Some(running);
                self.set_status(HotspotStatus::Running).await;
                self.ui.emit(UiEvent::ConnectionStarted { pid });
                Ok(())
            }
            Ok(Err(err)) => {
                self.set_status(HotspotStatus::Stopped).await;
                error!(error = %err, "failed to start hotspot");
                self.ui.emit(UiEvent::Error(err.to_string()));
                Err(err)
            }
            Err(_) => {
                self.set_status(HotspotStatus::Stopped).await;
                let err = AppError::StartupTimedOut(STARTUP_TIMEOUT.as_secs());
                error!(error = %err, "hotspot startup timed out");
                self.ui.emit(UiEvent::Error(err.to_string()));
                Err(err)
            }
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn stop_hotspot(&self) -> Result<(), AppError> {
        let _lifecycle = self.lifecycle.lock().await;
        let running = self.running.lock().await.take();
        let Some(running) = running else {
            info!("hotspot stop requested while already stopped");
            self.set_status(HotspotStatus::Stopped).await;
            return Ok(());
        };

        self.set_status(HotspotStatus::Stopping).await;
        let stop_result = running.stop().await;

        match stop_result {
            Ok(()) => {
                self.set_status(HotspotStatus::Stopped).await;
                self.ui.emit(UiEvent::ConnectionStopped);
                Ok(())
            }
            Err(err) => {
                self.set_status(HotspotStatus::Stopped).await;
                error!(error = %err, "failed to stop hotspot cleanly");
                self.ui.emit(UiEvent::Error(err.to_string()));
                Err(err)
            }
        }
    }

    pub async fn run_once(&self) -> Result<(), AppError> {
        self.start_hotspot().await?;
        let running = self.running.lock().await.take();
        if let Some(running) = running {
            running.wait().await?;
        }
        self.set_status(HotspotStatus::Stopped).await;
        Ok(())
    }

    async fn start_inner(&self, settings: AppSettings) -> Result<RunningApp, AppError> {
        info!(settings = %settings.describe_for_logs(), "starting hotspot");
        if settings.enable_sharing
            && let Some(error) = sharing_unavailable_reason()?
        {
            return Err(error.into());
        }

        info!("scanning for network and process conflicts");
        let conflicts = ConflictScanner::default().scan().await?;
        if conflicts.has_conflicts() {
            warn!(?conflicts, "conflicts detected before startup");
            self.ui.emit(UiEvent::ConflictWarning(conflicts.clone()));
        } else {
            info!("no startup conflicts detected");
        }

        let mut config = CoreConfig::default_client_tun();
        if let Some(profile) = settings.selected_profile() {
            info!(profile_name = %profile.display_name(), "applying selected VPN profile");
            config.apply_proxy(&sanitize_proxy(profile.effective_proxy()))?;
        } else {
            info!("no selected profile configured, using default direct Mihomo configuration");
        }

        info!("ensuring Mihomo geo data is available");
        let asset_dir = ensure_geo_data(&settings.geo_data).await?;

        info!("preparing system networking for Mihomo");
        let tunnel_routing = tokio::task::spawn_blocking(|| {
            SystemHotspotController::system().prepare_tunnel_routing()
        })
        .await
        .map_err(|err| HotspotError::Worker(err.to_string()))??;

        let tunnel_routing = Arc::new(tunnel_routing);
        let mut core = CoreManager::with_home_dir(asset_dir);
        info!("launching Mihomo runtime");
        let handle = core.start(config).await?;

        // The embedded core runs IN-PROCESS, so it creates the TUN with this
        // process's privileges. Without CAP_NET_ADMIN it fails with
        // "configure tun interface: operation not permitted" and there is simply
        // no tunnel — previously that was only a core log line, and startup
        // carried on to report "verified internet egress" (which had really gone
        // out via the untouched host route) before spending 30 s retrying the
        // hotspot. Fail loudly and specifically instead.
        wait_for_tun_device().await?;

        #[cfg(target_os = "linux")]
        {
            // firewalld puts unassigned interfaces in the `public` zone, which
            // rejects inbound traffic. The Mihomo TUN needs the system-stack
            // redirect to its internal listener to be accepted, so move the
            // interface into the trusted zone before probing egress. Best-effort:
            // machines without firewalld are unaffected.
            let tun_device = crate::core::config::TUN_DEVICE_NAME.to_owned();
            match tokio::task::spawn_blocking({
                let tun_device = tun_device.clone();
                move || SystemHotspotController::system().trust_tunnel_interface(&tun_device)
            })
            .await
            {
                Ok(Ok(())) => info!(
                    tun_interface = %tun_device,
                    "tunnel interface assigned to the firewalld trusted zone"
                ),
                Ok(Err(err)) => warn!(
                    error = %err,
                    tun_interface = %tun_device,
                    "could not assign the tunnel interface to the firewalld trusted zone; \
                     firewalld may reject tunnel traffic"
                ),
                Err(err) => warn!(error = %err, "firewalld trust task failed"),
            }
        }

        // Start sharing independently of the external HTTP health check.
        let mut sharing_session = None;
        #[cfg(windows)]
        let mut ics_signature_mismatch = None;
        if settings.enable_sharing {
            match enable_sharing_when_tun_is_ready(
                &tunnel_routing,
                settings.hotspot_wifi_interface.as_deref(),
                &settings.hotspot_ssid,
                &settings.hotspot_passphrase,
            )
            .await
            {
                Ok(session) => {
                    let wifi_interface = session.wifi_interface.name.clone();
                    info!(
                        tun_interface = %session.tun_interface.name,
                        wifi_interface = %wifi_interface,
                        "enabled hotspot and tunnel forwarding"
                    );
                    self.ui.emit(UiEvent::SharingEnabled { wifi_interface });
                    #[cfg(windows)]
                    if let Ok(mut previous) = self.last_hotspot_adapters.lock() {
                        previous.clear();
                    }
                    sharing_session = Some(session);
                }
                Err(err) => {
                    #[cfg(windows)]
                    if let HotspotError::AmbiguousHotspotAdapters(adapters)
                    | HotspotError::InactiveHotspotAdapter { adapters, .. } = &err
                        && let Ok(mut last_seen) = self.last_hotspot_adapters.lock()
                    {
                        last_seen.clone_from(adapters);
                    }
                    #[cfg(windows)]
                    if let HotspotError::Windows(cause) = &err {
                        ics_signature_mismatch = cause
                            .downcast_ref::<crate::os::hotspot::IcsSignatureMismatch>()
                            .cloned();
                    }
                    if let Some(hint) = err.diagnostic_hint() {
                        warn!(
                            error = %err,
                            sharing_diagnostic_hint = hint,
                            "internet sharing could not be enabled; VPN will still work locally without hotspot sharing"
                        );
                        self.ui.emit(UiEvent::SharingFailed(format!(
                            "Internet sharing could not be enabled: {hint}"
                        )));
                    } else {
                        warn!(error = %err, "internet sharing could not be enabled; VPN will still work locally without hotspot sharing");
                        self.ui.emit(UiEvent::SharingFailed(format!(
                            "Internet sharing could not be enabled: {err}"
                        )));
                    }
                }
            }
        } else {
            info!("internet sharing is disabled in settings");
        }

        if settings.selected_profile().is_some() {
            info!("probing internet egress through the active tunnel");
            if let Err(err) = verify_tunnel_connectivity().await {
                warn!(
                    error = %err,
                    hotspot_active = sharing_session.is_some(),
                    "tunnel health probe failed; keeping Mihomo and hotspot running"
                );
                let state = if sharing_session.is_some() {
                    "The tunnel and hotspot remain active."
                } else {
                    "The tunnel remains active."
                };
                self.ui.emit(UiEvent::Warning(format!(
                    "The tunnel health probe failed ({err}). {state}"
                )));
            } else {
                // Reachable only because `wait_for_tun_device` already confirmed
                // the TUN exists; otherwise this probe would happily succeed over
                // the untouched host route and report a working tunnel that was
                // never created.
                info!(
                    tun_interface = crate::core::config::TUN_DEVICE_NAME,
                    "verified internet egress with the tunnel device present"
                );
            }
        } else {
            info!("no VPN profile selected; skipping tunnel health check (direct routing)");
        }

        Ok(RunningApp {
            core: handle,
            sharing_session,
            #[cfg(windows)]
            ics_signature_mismatch,
            tunnel_routing,
        })
    }

    async fn set_status(&self, status: HotspotStatus) {
        *self.status.write().await = status;
        info!(?status, "hotspot status changed");
        self.ui.emit(UiEvent::StatusChanged(status));
    }
}

/// Wait for the Mihomo TUN device to actually exist after the core starts.
///
/// The embedded core cannot create a TUN without `CAP_NET_ADMIN`; when it fails
/// there is no tunnel at all, so every later step is meaningless. Distinguish the
/// privilege case explicitly, because that is by far the most common cause and
/// the fix is a concrete user action.
async fn wait_for_tun_device() -> Result<(), AppError> {
    let device = crate::core::config::TUN_DEVICE_NAME;
    let deadline = Instant::now() + TUN_READY_TIMEOUT;

    loop {
        if tunnel_device_present() {
            info!(tun_interface = device, "Mihomo TUN device is present");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AppError::TunDeviceUnavailable {
                device: device.to_owned(),
                #[cfg(target_os = "linux")]
                running_as_root: unsafe { libc::geteuid() } == 0,
            });
        }
        sleep(TUN_READY_POLL).await;
    }
}

/// Polls the internet through the freshly-established tunnel until a probe
/// succeeds or [`TUNNEL_PROBE_DEADLINE`] elapses. Returns `Ok(())` on the first
/// successful HTTP response so a healthy tunnel is confirmed quickly; returns
/// [`AppError::TunnelUnreachable`] if nothing gets through in time.
async fn verify_tunnel_connectivity() -> Result<(), AppError> {
    // Escape hatch for automated tests / offline diagnostics where reaching the
    // public internet is neither possible nor the thing under test.
    if std::env::var(TUNNEL_HEALTHCHECK_DISABLE_ENV)
        .map(|value| !matches!(value.as_str(), "0" | "false" | "no" | ""))
        .unwrap_or(false)
    {
        warn!(
            env = TUNNEL_HEALTHCHECK_DISABLE_ENV,
            "skipping tunnel health check because the override env var is set"
        );
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(TUNNEL_PROBE_TIMEOUT)
        // No proxy: we want these requests to ride the TUN default route, which
        // is exactly the path hotspot clients will use.
        .no_proxy()
        .build()
        .map_err(|err| AppError::TunnelUnreachable(format!("probe client init failed: {err}")))?;

    probe_tunnel(
        &client,
        TUNNEL_PROBE_URLS,
        Instant::now() + TUNNEL_PROBE_DEADLINE,
    )
    .await
}

async fn probe_tunnel(
    client: &reqwest::Client,
    urls: &[&str],
    deadline: Instant,
) -> Result<(), AppError> {
    let mut last_error = "no probe attempt completed".to_owned();

    while Instant::now() < deadline {
        for url in urls {
            match timeout_at(deadline, client.get(*url).send()).await {
                Ok(Ok(response)) if response.status().is_success() => return Ok(()),
                Ok(Ok(response)) => {
                    last_error = format!("{url} returned HTTP {}", response.status());
                }
                Ok(Err(err)) => {
                    last_error = format!("{url}: {:#}", anyhow::Error::new(err.without_url()));
                }
                Err(_) => return Err(AppError::TunnelUnreachable(last_error)),
            }
        }

        if Instant::now() < deadline {
            warn!(error = %last_error, "tunnel not reachable yet, retrying probe");
            sleep_until((Instant::now() + TUNNEL_PROBE_RETRY_DELAY).min(deadline)).await;
        }
    }
    Err(AppError::TunnelUnreachable(last_error))
}

async fn enable_sharing_when_tun_is_ready(
    routing: &Arc<TunnelRoutingSession>,
    selected_wifi_interface: Option<&str>,
    ssid: &str,
    passphrase: &str,
) -> Result<SharingSession, HotspotError> {
    let deadline = Instant::now() + SHARING_READY_TIMEOUT;
    let selected_wifi_interface = selected_wifi_interface.map(str::to_owned);
    let ssid = ssid.to_owned();
    let passphrase = passphrase.to_owned();

    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        info!(attempt, "attempting hotspot and forwarding setup");
        let selected = selected_wifi_interface.clone();
        let ssid = ssid.clone();
        let passphrase = passphrase.clone();
        let routing = Arc::clone(routing);
        let result = tokio::task::spawn_blocking(move || {
            routing.enable_sharing(selected.as_deref(), &ssid, &passphrase)
        })
        .await
        .map_err(|err| HotspotError::Worker(err.to_string()))?;

        match result {
            Ok(plan) => {
                info!(attempt, "hotspot and forwarding setup completed");
                return Ok(plan);
            }
            Err(err) if should_retry_sharing_enable(&err) && Instant::now() < deadline => {
                warn!(error = %err, "sharing adapter is not ready yet, retrying");
                sleep(SHARING_TUN_READY_POLL).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(windows)]
fn hotspot_adapter_choices(
    mut adapters: Vec<NetworkAdapter>,
    previous: &[NetworkAdapter],
    selected: Option<&str>,
) -> Vec<NetworkAdapter> {
    adapters.retain(|adapter| {
        adapter.kind == AdapterKind::WiFi
            || adapter.is_up
            || selected == Some(adapter.id.as_str())
            || previous.iter().any(|seen| seen.id == adapter.id)
    });
    // Windows may hide the candidates again when a failed start rolls back.
    for seen in previous {
        if !adapters.iter().any(|current| current.id == seen.id) {
            let mut inactive = seen.clone();
            inactive.is_up = false;
            inactive.ipv4_addresses.clear();
            adapters.push(inactive);
        }
    }
    adapters.sort_by(|left, right| left.name.cmp(&right.name));
    adapters
}

fn should_retry_sharing_enable(err: &HotspotError) -> bool {
    matches!(
        err,
        HotspotError::NoTunInterface | HotspotError::AdapterNotFound(_)
    )
}

async fn disable_sharing(session: SharingSession) -> Result<(), HotspotError> {
    tokio::task::spawn_blocking(move || session.stop())
        .await
        .map_err(|err| HotspotError::Worker(err.to_string()))?
}

fn sharing_unavailable_reason() -> Result<Option<HotspotError>, AppError> {
    let controller = SystemHotspotController::system();
    let adapters = controller.enumerate_all()?;
    reason_sharing_unavailable(&adapters)
}

/// Decide whether internet sharing can run given the current adapters.
///
/// Sharing only needs a Wi-Fi radio to exist. Whether the AP can be hosted on
/// the device directly or needs a concurrent AP virtual interface is decided at
/// start time by [`plan_ap_hosting`], which knows the driver's capabilities and
/// the station's channel. This preflight must therefore NOT reject a Wi-Fi radio
/// merely because it currently holds a default route: with Ethernet also
/// connected, NetworkManager keeps default routes on both links, and the old
/// check then refused to start the hotspot until Wi-Fi was switched off by hand.
fn reason_sharing_unavailable(
    adapters: &[NetworkAdapter],
) -> Result<Option<HotspotError>, AppError> {
    let has_wifi = adapters
        .iter()
        .any(|adapter| adapter.kind == AdapterKind::WiFi);
    if !has_wifi {
        return Ok(Some(HotspotError::NoWifiAdapter));
    }
    Ok(None)
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("settings cannot be changed while the hotspot is running")]
    SettingsLockedWhileRunning,
    #[error("VPN profile not found: {0}")]
    ProfileNotFound(String),
    #[error("subscription not found")]
    SubscriptionNotFound,
    #[error("a subscription with this address already exists")]
    DuplicateSubscription,
    #[error("the subscription request settings changed during refresh")]
    SubscriptionChanged,
    #[error("hotspot startup timed out after {0} seconds")]
    StartupTimedOut(u64),
    #[error("could not verify internet access through the VPN tunnel: {0}")]
    TunnelUnreachable(String),
    #[cfg(target_os = "linux")]
    #[error(
        "the embedded Mihomo core could not create the {device} tunnel device (running as root: {running_as_root}). \
The core needs CAP_NET_ADMIN to configure a TUN interface. Either start the application with root privileges \
(for example `pkexec vrghotspot`), or grant the binary the capability once with \
`sudo setcap cap_net_admin,cap_net_raw+eip $(command -v vrghotspot)`. \
Escalating only the nftables helper is not sufficient, because the core runs inside this process."
    )]
    TunDeviceUnavailable {
        device: String,
        running_as_root: bool,
    },
    #[cfg(windows)]
    #[error(
        "the embedded Mihomo core could not create the {device} Windows TUN device. Check the Mihomo log for Wintun or driver errors"
    )]
    TunDeviceUnavailable { device: String },
    #[error(transparent)]
    Subscription(#[from] SubscriptionError),
    #[error(transparent)]
    CoreConfig(#[from] CoreConfigError),
    #[error(transparent)]
    CoreProcess(#[from] CoreProcessError),
    #[error(transparent)]
    Conflict(#[from] ConflictError),
    #[error(transparent)]
    Hotspot(#[from] HotspotError),
    #[error(transparent)]
    GeoData(#[from] GeoDataError),
    #[error(transparent)]
    SettingsPersistence(#[from] SettingsPersistenceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_settings_with_the_legacy_telemetry_field() {
        let settings = AppSettings::default();
        let mut legacy = serde_json::to_value(&settings).unwrap();
        legacy["telemetry_enabled"] = serde_json::Value::Bool(false);

        let restored: AppSettings = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored, settings);
        assert!(
            serde_json::to_value(restored)
                .unwrap()
                .get("telemetry_enabled")
                .is_none()
        );
    }

    #[test]
    fn retries_only_adapter_readiness_errors_for_sharing() {
        assert!(should_retry_sharing_enable(&HotspotError::NoTunInterface));
        assert!(should_retry_sharing_enable(&HotspotError::AdapterNotFound(
            "adapter".to_owned()
        )));
        assert!(!should_retry_sharing_enable(&HotspotError::NoWifiAdapter));
        // The uplink conflict is terminal: retrying cannot free the radio, so it
        // must not be treated as a transient readiness error.
        #[cfg(target_os = "linux")]
        assert!(!should_retry_sharing_enable(
            &HotspotError::UplinkInterfaceConflict("wlp0s20f3".to_owned())
        ));
    }

    fn adapter(name: &str, kind: AdapterKind, has_default_route: bool) -> NetworkAdapter {
        NetworkAdapter {
            id: format!("/org/freedesktop/NetworkManager/Devices/{name}"),
            name: name.to_owned(),
            #[cfg(windows)]
            description: String::new(),
            #[cfg(windows)]
            ipv4_addresses: Vec::new(),
            kind: kind.clone(),
            is_up: true,
            has_ip_address: true,
            has_default_route,
            supports_hotspot: kind == AdapterKind::WiFi,
            is_associated_station: kind == AdapterKind::WiFi && has_default_route,
            station_frequency_mhz: None,
            phy: (kind == AdapterKind::WiFi).then(|| "phy0".to_owned()),
        }
    }

    #[cfg(windows)]
    #[test]
    fn picker_keeps_radios_active_interfaces_and_inactive_saved_choices() {
        let radio = adapter("Wi-Fi", AdapterKind::WiFi, false);
        let live = adapter("Direct 1", AdapterKind::Other, false);
        let mut saved = adapter("Direct 2", AdapterKind::Other, false);
        saved.is_up = false;
        let mut stale = adapter("Direct 3", AdapterKind::Other, false);
        stale.is_up = false;
        let current = vec![stale, live.clone(), saved.clone(), radio.clone()];
        assert_eq!(
            hotspot_adapter_choices(current, &[], Some(&saved.id)),
            [live, saved.clone(), radio]
        );
    }

    #[cfg(windows)]
    #[test]
    fn picker_recovers_rollback_candidates_without_stale_status_or_duplicates() {
        let live = adapter("Direct 1", AdapterKind::Other, false);
        let mut gone = adapter("Direct 2", AdapterKind::Other, false);
        gone.ipv4_addresses.push([192, 168, 137, 1].into());
        let previous = [live.clone(), gone.clone()];
        gone.is_up = false;
        gone.ipv4_addresses.clear();
        assert_eq!(
            hotspot_adapter_choices(vec![live.clone()], &previous, None),
            [live, gone]
        );
    }

    #[test]
    fn sharing_not_pre_disabled_when_wifi_is_the_only_uplink() {
        // Regression: the preflight used to disable sharing whenever every Wi-Fi
        // radio held a default route, which blocked the hotspot outright. Whether
        // a concurrent AP interface is needed is decided later, at start time.
        let adapters = [
            adapter("lo", AdapterKind::Loopback, false),
            adapter("wlp0s20f3", AdapterKind::WiFi, true),
            adapter("vrghotspot-tun", AdapterKind::Tun, false),
        ];
        assert!(
            reason_sharing_unavailable(&adapters)
                .expect("no NM error")
                .is_none()
        );
    }

    #[test]
    fn sharing_not_pre_disabled_with_ethernet_and_associated_wifi() {
        // The reported UPD: an Ethernet cable plus an associated Wi-Fi radio.
        // NetworkManager keeps default routes on both, which previously tripped
        // the guard and forced the user to switch Wi-Fi off by hand.
        let adapters = [
            adapter("enp0s31f6", AdapterKind::Ethernet, true),
            adapter("wlp0s20f3", AdapterKind::WiFi, true),
        ];
        assert!(
            reason_sharing_unavailable(&adapters)
                .expect("no NM error")
                .is_none()
        );
    }

    #[test]
    fn sharing_allowed_with_ethernet_uplink_and_free_wifi() {
        let adapters = [
            adapter("eth0", AdapterKind::Ethernet, true),
            adapter("wlp0s20f3", AdapterKind::WiFi, false),
        ];
        assert!(
            reason_sharing_unavailable(&adapters)
                .expect("no NM error")
                .is_none()
        );
    }

    #[test]
    fn sharing_blocked_without_any_wifi() {
        let adapters = [adapter("eth0", AdapterKind::Ethernet, true)];
        assert!(matches!(
            reason_sharing_unavailable(&adapters).expect("no NM error"),
            Some(HotspotError::NoWifiAdapter)
        ));
    }

    #[tokio::test]
    async fn tunnel_health_check_can_be_disabled_via_env() {
        // SAFETY: single-threaded test; no other thread reads this env var here.
        unsafe { std::env::set_var(TUNNEL_HEALTHCHECK_DISABLE_ENV, "1") };
        let result = verify_tunnel_connectivity().await;
        unsafe { std::env::remove_var(TUNNEL_HEALTHCHECK_DISABLE_ENV) };
        assert!(
            result.is_ok(),
            "override env should short-circuit the probe"
        );
    }

    #[tokio::test]
    async fn tunnel_probe_retries_after_a_temporary_failure() {
        use axum::{Router, http::StatusCode, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let attempts = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/",
            get(move || {
                let previous = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if previous == 0 {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let result = probe_tunnel(
            &client,
            &[&url],
            Instant::now() + TUNNEL_PROBE_RETRY_DELAY + Duration::from_secs(3),
        )
        .await;
        server.abort();

        assert!(result.is_ok(), "{result:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn does_not_retry_nftables_errors() {
        let error = HotspotError::Nftables("permission denied".to_owned());
        assert!(!should_retry_sharing_enable(&error));
        assert!(error.diagnostic_hint().is_some());
    }
}
