use crate::config::geodata::{GeoDataError, GeoDataSettings, ensure_geo_data, update_geo_data};
use crate::config::subscription::{
    DEFAULT_SUBSCRIPTION_URL, StoredVpnProfile, SubscriptionClient, SubscriptionError,
    SubscriptionInfo, parse_subscription_response, sanitize_proxy, stored_profiles_from_document,
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
use crate::telemetry::redaction::Redactor;
use crate::telemetry::{ErrorKind, Operation, Telemetry};
use crate::ui::events::{EventSink, UiEvent, UiEventSink};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Instant, sleep, sleep_until, timeout, timeout_at};
use tracing::{error, info, warn};

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
    /// Subscription the profile list is seeded and refreshed from. Defaults to
    /// the one compiled into this build, which is empty unless the build was
    /// given one; replacing it is how a user brings their own.
    #[serde(default = "default_subscription_url")]
    pub subscription_url: String,
    /// What the provider says about that subscription, cached from the last
    /// successful fetch so the UI has something to show while offline.
    #[serde(default)]
    pub subscription_info: SubscriptionInfo,
    /// Cleared once the welcome screen has been completed.
    #[serde(default)]
    pub onboarding_complete: bool,
    /// Anonymous usage statistics are on unless the user turns them off.
    /// Reports to support stay strictly opt-in either way.
    #[serde(default = "default_telemetry_enabled")]
    pub telemetry_enabled: bool,
    pub geo_data: GeoDataSettings,
}

const DEFAULT_HOTSPOT_SSID: &str = "VPN-Hotspot";

fn default_subscription_url() -> String {
    DEFAULT_SUBSCRIPTION_URL.to_owned()
}

fn default_hotspot_ssid() -> String {
    DEFAULT_HOTSPOT_SSID.to_owned()
}

fn default_enable_sharing() -> bool {
    true
}

fn default_telemetry_enabled() -> bool {
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
            subscription_url: std::env::var("VRG_SUBSCRIPTION_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(default_subscription_url),
            subscription_info: SubscriptionInfo::default(),
            onboarding_complete: false,
            telemetry_enabled: true,
            geo_data: GeoDataSettings::default(),
        }
    }

    pub fn load_or_env() -> Self {
        let mut settings = match Self::load_from_disk() {
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
        };
        // Both branches above can produce `telemetry_enabled: true` (defaults on
        // fresh installs and after settings recovery), so the separately stored
        // opt-out is re-applied on top of whatever they chose.
        if persisted_telemetry_opt_out(&telemetry_preference_path()) {
            settings.telemetry_enabled = false;
        }
        settings
    }

    pub fn load_from_disk() -> Result<Self, SettingsPersistenceError> {
        let path = settings_path();
        if !path.exists() {
            return Ok(Self::from_env());
        }

        let content = fs::read_to_string(path)?;
        let mut settings: Self = serde_json::from_str(&content)?;
        // Profile identifiers used to be derived from the node's position in the
        // subscription, so a reordered list silently pointed the selection at a
        // different server. Rewrite them to the content-derived form once, on the
        // way in, preserving which profile was selected.
        settings.migrate_profile_ids();
        Ok(settings)
    }

    /// Recompute stored profile identifiers with the current scheme.
    ///
    /// Old identifiers looked like `vless-<slug>-<index>`; every all-Cyrillic name
    /// slugged to the same string, which left the index as the only distinguishing
    /// part. Migrating in place keeps existing installations working across the
    /// change instead of orphaning their selection.
    fn migrate_profile_ids(&mut self) {
        let mut selected = None;
        for profile in &mut self.profiles {
            let refreshed = StoredVpnProfile::identifier(&profile.proxy);
            if self.selected_profile_id.as_deref() == Some(profile.id.as_str()) {
                selected = Some(refreshed.clone());
            }
            profile.id = refreshed;
        }
        if let Some(selected) = selected {
            self.selected_profile_id = Some(selected);
        }
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

pub fn telemetry_identity_path() -> PathBuf {
    settings_path().with_file_name("telemetry-installation-id")
}

#[derive(Serialize, Deserialize)]
struct TelemetryPreference {
    /// Written only once the user has touched the toggle; an absent file keeps
    /// the build default (collection on, reports opt-in).
    #[serde(default = "default_telemetry_enabled")]
    enabled: bool,
}

fn telemetry_preference_path() -> PathBuf {
    settings_path().with_file_name("telemetry-preference.json")
}

/// The opt-out lives apart from `settings.json`: when the main file becomes
/// unreadable the recovery path rebuilds it from defaults, and `true` is one of
/// those defaults. A preference that exists but cannot be read fails closed, so
/// a damaged or unreadable file never silently re-enables collection.
fn persisted_telemetry_opt_out(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<TelemetryPreference>(&content) {
            Ok(preference) => !preference.enabled,
            Err(error) => {
                warn!(error = %error, "telemetry preference file is unreadable; keeping collection off");
                true
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            warn!(error = %error, "telemetry preference file cannot be read; keeping collection off");
            true
        }
    }
}

fn persist_telemetry_preference(path: &Path, enabled: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(&TelemetryPreference { enabled })
        .expect("telemetry preference serialization cannot fail");
    // Unique temporary name: two toggles racing a fixed `*.tmp` would corrupt
    // each other's file, and this is the only record of the user's opt-out.
    let temporary = path.with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn settings_path() -> PathBuf {
    app_config_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join(SETTINGS_FILE)
}

/// The host part of a subscription URL, for logging.
///
/// The full URL usually carries a per-user token in its path or query, and these
/// records are written to disk and handed to the interface, so the token must not
/// travel with them.
fn subscription_host(url: &str) -> String {
    url.split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .filter(|host| !host.is_empty())
        .unwrap_or("unknown")
        .to_owned()
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
    status: Arc<RwLock<HotspotStatus>>,
    #[cfg(windows)]
    last_hotspot_adapters: std::sync::Mutex<Vec<NetworkAdapter>>,
    telemetry: Telemetry,
    redactor: std::sync::Mutex<Redactor>,
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
        Self::with_telemetry(settings, ui, Telemetry::default())
    }

    pub fn with_telemetry(settings: AppSettings, ui: S, telemetry: Telemetry) -> Self {
        let mut redactor = Redactor::default();
        if let Ok(value) = serde_json::to_value(&settings) {
            redactor.remember_json(&value);
        }
        for name in [
            "HOME",
            "USER",
            "USERPROFILE",
            "USERNAME",
            "VRG_TELEMETRY_TOKEN",
        ] {
            if let Ok(value) = std::env::var(name) {
                redactor.remember(&value);
            }
        }
        let running: Arc<Mutex<Option<RunningApp>>> = Arc::new(Mutex::new(None));
        // Lease counting runs in the telemetry worker via this weak handle, so
        // client metrics keep updating in headless/CLI mode and stop when the
        // controller is gone instead of holding it alive.
        let sampler_source = Arc::downgrade(&running);
        telemetry.set_client_sampler(move || {
            let running = sampler_source.upgrade()?;
            let running = running.try_lock().ok()?;
            let session = running.as_ref()?.sharing_session.as_ref()?;
            session.connected_clients()
        });
        Self {
            settings: Arc::new(RwLock::new(settings.with_resolved_geo_data())),
            running,
            lifecycle: Mutex::new(()),
            status: Arc::new(RwLock::new(HotspotStatus::Stopped)),
            #[cfg(windows)]
            last_hotspot_adapters: std::sync::Mutex::default(),
            telemetry,
            redactor: std::sync::Mutex::new(redactor),
            ui,
        }
    }

    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    pub async fn initialize_telemetry(&self) -> Result<(), String> {
        let settings = self.settings.read().await;
        self.telemetry.set_enabled(settings.telemetry_enabled).await
    }

    pub fn report_redactor(&self) -> Result<Redactor, String> {
        self.redactor
            .lock()
            .map(|redactor| redactor.clone())
            .map_err(|_| "support report privacy filter is unavailable".to_owned())
    }

    fn remember_private_values(&self, value: &impl Serialize) {
        if let Ok(value) = serde_json::to_value(value)
            && let Ok(mut redactor) = self.redactor.lock()
        {
            redactor.remember_json(&value);
        }
    }

    pub async fn set_telemetry_enabled(&self, enabled: bool) -> Result<AppSettings, AppError> {
        let mut stored = self.settings.write().await;
        if !enabled {
            // Cut the network side before persisting anything, so collection
            // actually stops even if the preference write below fails.
            self.telemetry
                .set_enabled(false)
                .await
                .map_err(AppError::Telemetry)?;
            stored.telemetry_enabled = false;
        }
        // Persist the preference in its own file first: it, not settings.json,
        // is what protects the opt-out from the settings-recovery defaults.
        persist_telemetry_preference(&telemetry_preference_path(), enabled)
            .map_err(SettingsPersistenceError::from)?;
        let mut next = stored.clone();
        next.telemetry_enabled = enabled;
        next.save_to_disk()?;
        *stored = next.clone();
        if enabled && let Err(error) = self.telemetry.set_enabled(true).await {
            // Activation failed; roll every store back to the safe state.
            next.telemetry_enabled = false;
            *stored = next.clone();
            let _ = persist_telemetry_preference(&telemetry_preference_path(), false);
            let _ = next.save_to_disk();
            self.ui.emit(UiEvent::SettingsChanged);
            return Err(AppError::Telemetry(error));
        }
        drop(stored);
        if enabled {
            self.telemetry
                .hotspot_state(self.status().await == HotspotStatus::Running);
        }
        self.ui.emit(UiEvent::SettingsChanged);
        Ok(next)
    }

    pub async fn settings(&self) -> AppSettings {
        self.settings.read().await.clone()
    }

    async fn observe<T>(
        &self,
        operation: Operation,
        future: impl std::future::Future<Output = Result<T, AppError>>,
    ) -> Result<T, AppError> {
        let measurement = self.telemetry.operation(operation);
        let result = future.await;
        if let Err(error) = &result {
            error!(operation = operation.as_str(), error = %error, "application operation failed");
        }
        measurement.finish(result.as_ref().err().map(AppError::telemetry_kind));
        result
    }

    #[tracing::instrument(skip_all)]
    pub async fn update_settings(&self, settings: AppSettings) -> Result<(), AppError> {
        self.observe(
            Operation::SettingsSave,
            self.update_settings_inner(settings),
        )
        .await
    }

    async fn update_settings_inner(&self, settings: AppSettings) -> Result<(), AppError> {
        let running = self.running.lock().await;
        if running.is_some() {
            return Err(AppError::SettingsLockedWhileRunning);
        }

        let mut settings = settings.with_resolved_geo_data();
        let mut stored = self.settings.write().await;
        settings.telemetry_enabled = stored.telemetry_enabled;
        self.remember_private_values(&settings);
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

    /// Import from the configured subscription. Used to seed the profile list on
    /// first run and to refresh it on demand.
    pub async fn import_configured_subscription(&self) -> Result<Vec<StoredVpnProfile>, AppError> {
        let url = self.settings.read().await.subscription_url.clone();
        let url = if url.trim().is_empty() {
            DEFAULT_SUBSCRIPTION_URL.to_owned()
        } else {
            url
        };
        // A build without a compiled-in subscription has nothing to seed from;
        // say so plainly instead of fetching an empty address.
        if url.trim().is_empty() {
            return Err(AppError::NoSubscriptionConfigured);
        }
        // A subscription URL normally embeds a per-user token, and these records
        // reach both the on-disk log and the interface's log view. Log enough to
        // correlate a failure with an endpoint, not enough to reuse it.
        info!(
            subscription_host = %subscription_host(&url),
            "importing the configured subscription"
        );
        self.import_subscription(&url).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn complete_onboarding(&self) -> Result<(), AppError> {
        self.observe(Operation::Onboarding, self.complete_onboarding_inner())
            .await
    }

    async fn complete_onboarding_inner(&self) -> Result<(), AppError> {
        let mut settings = self.settings.write().await;
        if settings.onboarding_complete {
            return Ok(());
        }
        settings.onboarding_complete = true;
        settings.save_to_disk()?;
        drop(settings);
        self.ui.emit(UiEvent::SettingsChanged);
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn import_subscription(
        &self,
        source: &str,
    ) -> Result<Vec<StoredVpnProfile>, AppError> {
        self.observe(
            Operation::SubscriptionImport,
            self.import_subscription_inner(source),
        )
        .await
    }

    async fn import_subscription_inner(
        &self,
        source: &str,
    ) -> Result<Vec<StoredVpnProfile>, AppError> {
        self.remember_private_values(&source);
        let trimmed = source.trim();
        let is_literal =
            trimmed.starts_with("vless://") || trimmed.starts_with('{') || trimmed.starts_with('[');
        let mut fetched_info = None;
        let document = if is_literal {
            parse_subscription_response(trimmed)?
        } else {
            let user_agent = self.settings.read().await.user_agent_override.clone();
            let client = SubscriptionClient::new(user_agent)?;
            let fetched = client.fetch(trimmed).await?;
            fetched_info = Some(fetched.info);
            fetched.document
        };
        // Remember the remote endpoint so the profile can be refreshed on start;
        // literal URIs/JSON have no endpoint to re-fetch.
        let source_url = (!is_literal).then_some(trimmed);
        let imported = stored_profiles_from_document(document, source_url);
        self.remember_private_values(&imported);

        let mut settings = self.settings.write().await;
        if let Some(info) = fetched_info {
            settings.subscription_info = info;
            settings.subscription_url = trimmed.to_owned();
        }
        let select_first = settings.selected_profile_id.is_none();
        // Reconcile rather than only appending. Skipping anything whose id already
        // existed meant a provider that changed a server's details could never
        // update it, while a provider that reordered its list produced duplicates.
        let mut added = Vec::new();
        for profile in &imported {
            match settings
                .profiles
                .iter_mut()
                .find(|existing| existing.id == profile.id)
            {
                Some(existing) => {
                    // Same endpoint: take the provider's current details, but keep
                    // a literal profile's `None` source_url from being overwritten
                    // by a refresh that did not come from a subscription.
                    if existing.proxy != profile.proxy || existing.name != profile.name {
                        info!(profile_name = %profile.name, "updated VPN profile from subscription");
                    }
                    existing.name = profile.name.clone();
                    existing.proxy = profile.proxy.clone();
                    if profile.source_url.is_some() {
                        existing.source_url = profile.source_url.clone();
                    }
                }
                None => {
                    info!(profile_name = %profile.name, "imported VPN profile from subscription");
                    settings.profiles.push(profile.clone());
                    added.push(profile.clone());
                }
            }
        }

        // Drop profiles this subscription used to provide and no longer lists, so
        // the list cannot accumulate servers that stopped existing. Profiles from
        // a different source — or pasted literally — are left alone.
        if let Some(source_url) = source_url {
            let still_offered = imported
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<std::collections::HashSet<_>>();
            settings.profiles.retain(|profile| {
                profile.source_url.as_deref() != Some(source_url)
                    || still_offered.contains(profile.id.as_str())
            });
            // The selection may have just been removed with it.
            let selection_survives = settings
                .selected_profile_id
                .as_deref()
                .is_some_and(|id| settings.profiles.iter().any(|profile| profile.id == id));
            if !selection_survives {
                settings.selected_profile_id =
                    settings.profiles.first().map(|profile| profile.id.clone());
            }
        }

        if select_first {
            settings.selected_profile_id = added.first().map(|profile| profile.id.clone());
        }
        settings.save_to_disk()?;
        self.ui.emit(UiEvent::ProfilesChanged);
        Ok(added)
    }

    #[tracing::instrument(skip_all)]
    pub async fn update_geo_data(&self) -> Result<(), AppError> {
        self.observe(Operation::GeoDataUpdate, self.update_geo_data_inner())
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

    pub async fn select_profile(&self, profile_id: impl Into<String>) -> Result<(), AppError> {
        let profile_id = profile_id.into();
        let mut settings = self.settings.write().await;
        if settings
            .profiles
            .iter()
            .any(|profile| profile.id == profile_id)
        {
            settings.selected_profile_id = Some(profile_id);
            settings.save_to_disk()?;
            self.ui.emit(UiEvent::ProfilesChanged);
            Ok(())
        } else {
            Err(AppError::ProfileNotFound(profile_id))
        }
    }

    pub async fn delete_profile(&self, profile_id: impl Into<String>) -> Result<(), AppError> {
        let profile_id = profile_id.into();
        let mut settings = self.settings.write().await;
        let original_len = settings.profiles.len();
        settings.profiles.retain(|profile| profile.id != profile_id);

        if settings.profiles.len() == original_len {
            return Err(AppError::ProfileNotFound(profile_id));
        }

        if settings.selected_profile_id.as_deref() == Some(profile_id.as_str()) {
            settings.selected_profile_id =
                settings.profiles.first().map(|profile| profile.id.clone());
        }

        settings.save_to_disk()?;
        self.ui.emit(UiEvent::ProfilesChanged);
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn start_hotspot(&self) -> Result<(), AppError> {
        let _lifecycle = self.lifecycle.lock().await;
        let operation = self.telemetry.operation(Operation::HotspotStart);
        self.telemetry.hotspot_state(false);
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
        self.refresh_selected_profile().await;
        let settings = self.settings().await;

        match timeout(STARTUP_TIMEOUT, self.start_inner(settings)).await {
            Ok(Ok(running)) => {
                let pid = running.process_id();
                *self.running.lock().await = Some(running);
                self.set_status(HotspotStatus::Running).await;
                self.ui.emit(UiEvent::ConnectionStarted { pid });
                operation.finish(None);
                Ok(())
            }
            Ok(Err(err)) => {
                self.set_status(HotspotStatus::Stopped).await;
                error!(error = %err, "failed to start hotspot");
                self.ui.emit(UiEvent::Error(err.to_string()));
                operation.finish(Some(err.telemetry_kind()));
                Err(err)
            }
            Err(_) => {
                self.set_status(HotspotStatus::Stopped).await;
                let err = AppError::StartupTimedOut(STARTUP_TIMEOUT.as_secs());
                error!(error = %err, "hotspot startup timed out");
                self.ui.emit(UiEvent::Error(err.to_string()));
                operation.finish(Some(ErrorKind::Timeout));
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

        let operation = self.telemetry.operation(Operation::HotspotStop);
        self.set_status(HotspotStatus::Stopping).await;
        let stop_result = running.stop().await;
        operation.finish(stop_result.as_ref().err().map(AppError::telemetry_kind));

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
        let operation = self.telemetry.operation(Operation::ConflictScan);
        let conflicts = ConflictScanner::default().scan().await;
        operation.finish(conflicts.as_ref().err().map(|_| ErrorKind::Conflict));
        let conflicts = conflicts?;
        if conflicts.has_conflicts() {
            warn!(?conflicts, "conflicts detected before startup");
            self.ui.emit(UiEvent::ConflictWarning(conflicts.clone()));
        } else {
            info!("no startup conflicts detected");
        }

        let mut config = CoreConfig::default_client_tun();
        if let Some(profile) = settings.selected_profile() {
            info!(profile_name = %profile.name, "applying selected VPN profile");
            config.apply_proxy(&sanitize_proxy(&profile.proxy))?;
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
        let operation = self.telemetry.operation(Operation::CoreStart);
        let handle = core.start(config).await;
        operation.finish(handle.as_ref().err().map(|_| ErrorKind::Core));
        let handle = handle?;

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
            let operation = self.telemetry.operation(Operation::SharingStart);
            match enable_sharing_when_tun_is_ready(
                &tunnel_routing,
                settings.hotspot_wifi_interface.as_deref(),
                &settings.hotspot_ssid,
                &settings.hotspot_passphrase,
            )
            .await
            {
                Ok(session) => {
                    operation.finish(None);
                    self.telemetry.availability("hotspot", true);
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
                    operation.finish(Some(ErrorKind::Network));
                    self.telemetry.availability("hotspot", false);
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
            let operation = self.telemetry.operation(Operation::TunnelProbe);
            let probe = verify_tunnel_connectivity().await;
            operation.finish(probe.as_ref().err().map(AppError::telemetry_kind));
            self.telemetry.availability("internet", probe.is_ok());
            if let Err(err) = probe {
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
        self.telemetry
            .hotspot_state(status == HotspotStatus::Running);
        if status == HotspotStatus::Running {
            self.telemetry.availability("vpn", true);
        }
        *self.status.write().await = status;
        info!(?status, "hotspot status changed");
        self.ui.emit(UiEvent::StatusChanged(status));
    }

    /// Re-fetches the selected profile from its subscription endpoint so a start
    /// uses the current server config rather than whatever was cached at import.
    /// Best-effort: a fetch failure (offline, endpoint down) leaves the existing
    /// profile in place so the user can still connect with the last-known config.
    async fn refresh_selected_profile(&self) {
        let (profile_id, source_url, user_agent) = {
            let settings = self.settings.read().await;
            let Some(profile) = settings.selected_profile() else {
                return;
            };
            let Some(source_url) = profile.source_url.clone() else {
                // Literal URI/JSON profiles have no endpoint to refresh from.
                return;
            };
            (
                profile.id.clone(),
                source_url,
                settings.user_agent_override.clone(),
            )
        };

        let operation = self.telemetry.operation(Operation::SubscriptionRefresh);
        info!(profile_id = %profile_id, "refreshing selected profile from subscription before start");
        let client = match SubscriptionClient::new(user_agent) {
            Ok(client) => client,
            Err(err) => {
                warn!(error = %err, "failed to build subscription client for refresh");
                operation.finish(Some(ErrorKind::Configuration));
                return;
            }
        };
        let fetched = match client.fetch(&source_url).await {
            Ok(fetched) => fetched,
            Err(err) => {
                warn!(error = %err, "failed to refresh profile from subscription, using cached config");
                operation.finish(Some(ErrorKind::Subscription));
                return;
            }
        };

        operation.finish(None);
        let refreshed = stored_profiles_from_document(fetched.document, Some(&source_url));
        self.remember_private_values(&refreshed);
        let mut settings = self.settings.write().await;
        settings.subscription_info = fetched.info;
        let Some(existing) = settings
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
        else {
            return;
        };
        // Match on the identifier. It is derived from the endpoint's connection
        // details, so it survives both reordering and the provider relabelling a
        // node — which matching on the display name did not.
        let Some(updated) = refreshed
            .into_iter()
            .find(|candidate| candidate.id == existing.id)
        else {
            warn!(
                profile_name = %existing.name,
                "subscription no longer contains the selected profile, using cached config"
            );
            return;
        };
        if let Some(slot) = settings
            .profiles
            .iter_mut()
            .find(|profile| profile.id == profile_id)
        {
            slot.proxy = updated.proxy;
            slot.source_url = updated.source_url;
        }
        if let Err(err) = settings.save_to_disk() {
            warn!(error = %err, "failed to persist refreshed profile");
        }
        self.ui.emit(UiEvent::ProfilesChanged);
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
    #[error("no subscription is configured")]
    NoSubscriptionConfigured,
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
    #[error("telemetry configuration failed: {0}")]
    Telemetry(String),
}

impl AppError {
    pub fn telemetry_kind(&self) -> ErrorKind {
        match self {
            Self::SettingsLockedWhileRunning | Self::SettingsPersistence(_) => ErrorKind::Settings,
            Self::ProfileNotFound(_) | Self::NoSubscriptionConfigured => ErrorKind::Selection,
            Self::StartupTimedOut(_) => ErrorKind::Timeout,
            Self::TunnelUnreachable(_) | Self::Hotspot(_) => ErrorKind::Network,
            Self::TunDeviceUnavailable { .. } => ErrorKind::Permission,
            Self::Subscription(_) => ErrorKind::Subscription,
            Self::CoreConfig(_) | Self::Telemetry(_) => ErrorKind::Configuration,
            Self::CoreProcess(_) => ErrorKind::Core,
            Self::Conflict(_) => ErrorKind::Conflict,
            Self::GeoData(_) => ErrorKind::GeoData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_to_telemetry_unless_the_user_turned_it_off() {
        let mut legacy = serde_json::to_value(AppSettings::default()).unwrap();
        legacy.as_object_mut().unwrap().remove("telemetry_enabled");
        let settings: AppSettings = serde_json::from_value(legacy).unwrap();
        assert!(settings.telemetry_enabled);
        let disabled = AppSettings {
            telemetry_enabled: false,
            ..settings
        };
        let restored: AppSettings =
            serde_json::from_str(&serde_json::to_string(&disabled).unwrap()).unwrap();
        assert!(!restored.telemetry_enabled);
    }

    #[test]
    fn telemetry_opt_out_is_separate_and_fails_closed() {
        let directory =
            std::env::temp_dir().join(format!("vrghotspot-pref-test-{}", uuid::Uuid::new_v4()));
        let preference = directory.join("telemetry-preference.json");
        // No file means the user never touched the toggle: default stays on.
        assert!(!persisted_telemetry_opt_out(&preference));
        persist_telemetry_preference(&preference, false).unwrap();
        assert!(persisted_telemetry_opt_out(&preference));
        persist_telemetry_preference(&preference, true).unwrap();
        assert!(!persisted_telemetry_opt_out(&preference));
        // A corrupted preference file must never re-enable collection.
        std::fs::write(&preference, "{ not json").unwrap();
        assert!(persisted_telemetry_opt_out(&preference));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn disabling_telemetry_persists_the_standalone_opt_out() {
        // XDG_CONFIG_HOME is process-global; lock only around the synchronous
        // env swap so no guard is held across an await.
        static CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let config_home =
            std::env::temp_dir().join(format!("vrghotspot-config-test-{}", uuid::Uuid::new_v4()));
        let previous = {
            let _guard = CONFIG_LOCK.lock().unwrap();
            let previous = std::env::var_os("XDG_CONFIG_HOME");
            unsafe { std::env::set_var("XDG_CONFIG_HOME", &config_home) };
            previous
        };
        let result = async {
            let controller = HotspotController::new(AppSettings::default());
            controller.set_telemetry_enabled(false).await.unwrap();
            assert!(persisted_telemetry_opt_out(&telemetry_preference_path()));
            assert!(!controller.settings().await.telemetry_enabled);
            // Fresh defaults after the settings file vanished must still honor
            // the stored opt-out.
            let settings_file = config_home.join("vrghotspot").join("settings.json");
            std::fs::write(&settings_file, "{ unreadable settings").unwrap();
            let recovered = AppSettings::load_or_env();
            assert!(!recovered.telemetry_enabled);
            assert_eq!(
                std::fs::read_to_string(settings_file.with_extension("json.corrupt")).unwrap(),
                "{ unreadable settings"
            );
            assert!(!settings_file.exists());

            controller.set_telemetry_enabled(false).await.unwrap();
            std::fs::remove_file(&settings_file).unwrap();
            let recovered = AppSettings::load_or_env();
            assert!(!recovered.telemetry_enabled);
        }
        .await;
        {
            let _guard = CONFIG_LOCK.lock().unwrap();
            match previous {
                Some(value) => unsafe { std::env::set_var("XDG_CONFIG_HOME", value) },
                None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
            }
        }
        let _ = std::fs::remove_dir_all(&config_home);
        result
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
