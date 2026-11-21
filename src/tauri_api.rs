use crate::app::{AppError, AppSettings, HotspotController, HotspotStatus};
use crate::os::conflicts::ConflictScanner;
use crate::os::hotspot::{NetworkAdapter, UplinkStatus};
use crate::telemetry::ReportReceipt;
use crate::telemetry::reports::{ReportManager, ReportPreview};
use crate::telemetry::{ErrorKind, Operation, TelemetryStatus};
use crate::ui::events::TauriEventSink;
use crate::ui::logs::{AppLogLevel, InMemoryLogStore};
use serde::Serialize;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tauri::State;
use uuid::Uuid;

#[derive(Clone)]
pub struct TauriState {
    pub controller: Arc<HotspotController<TauriEventSink>>,
    pub logs: InMemoryLogStore,
    pub reports: ReportManager,
}

impl TauriState {
    pub fn new(controller: Arc<HotspotController<TauriEventSink>>, logs: InMemoryLogStore) -> Self {
        Self {
            controller,
            logs,
            reports: ReportManager::from_env(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AppSnapshot {
    pub settings: AppSettings,
    pub status: HotspotStatus,
    pub adapters: Vec<NetworkAdapter>,
    #[cfg(windows)]
    pub hotspot_adapters: Vec<NetworkAdapter>,
    pub has_physical_wifi_adapter: bool,
    pub wifi_adapter_error: Option<String>,
    pub uplink: UplinkStatus,
    /// Devices currently connected to the hotspot; `None` when it is not running.
    pub connected_clients: Option<u32>,
    pub sharing_active: bool,
    pub ics_signature_mismatch: bool,
    pub logs: Vec<LogEntryDto>,
    pub telemetry: TelemetryStatus,
    pub reports_configured: bool,
}

#[derive(Debug, Serialize)]
pub struct LogEntryDto {
    pub timestamp: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[tauri::command]
pub async fn get_snapshot(state: State<'_, TauriState>) -> Result<AppSnapshot, String> {
    let settings = state.controller.settings().await;
    let status = state.controller.status().await;
    let adapters = state
        .controller
        .discover_wifi_adapters()
        .unwrap_or_default();
    let (has_physical_wifi_adapter, wifi_adapter_error) =
        match state.controller.has_physical_wifi_adapter() {
            Ok(present) => (present, None),
            Err(error) => (false, Some(error.to_string())),
        };
    let uplink = state.controller.uplink_status().unwrap_or_default();
    let connected_clients = state.controller.connected_clients();
    #[cfg(windows)]
    let hotspot_adapters = state
        .controller
        .discover_hotspot_adapters(settings.hotspot_wifi_interface.as_deref());

    Ok(AppSnapshot {
        settings,
        status,
        adapters,
        #[cfg(windows)]
        hotspot_adapters,
        has_physical_wifi_adapter,
        wifi_adapter_error,
        uplink,
        connected_clients,
        sharing_active: state.controller.sharing_active().await,
        #[cfg(windows)]
        ics_signature_mismatch: state.controller.ics_signature_mismatch().await.is_some(),
        #[cfg(not(windows))]
        ics_signature_mismatch: false,
        logs: log_entries(&state.logs, AppLogLevel::Debug),
        telemetry: state.controller.telemetry().status(),
        reports_configured: state.reports.configured(),
    })
}

#[tauri::command]
pub async fn get_settings(state: State<'_, TauriState>) -> Result<AppSettings, String> {
    Ok(state.controller.settings().await)
}

#[tauri::command]
pub async fn save_settings(
    state: State<'_, TauriState>,
    settings: AppSettings,
) -> Result<AppSettings, String> {
    state
        .controller
        .update_settings(settings)
        .await
        .map_err(app_error)?;
    Ok(state.controller.settings().await)
}

#[tauri::command]
pub async fn set_telemetry_enabled(
    state: State<'_, TauriState>,
    enabled: bool,
) -> Result<AppSettings, String> {
    state
        .controller
        .set_telemetry_enabled(enabled)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn prepare_support_report(
    state: State<'_, TauriState>,
    error: String,
) -> Result<ReportPreview, String> {
    let settings = state.controller.settings().await;
    let status = state.controller.status().await;
    let logs = state.logs.entries();
    let mut redactor = state.controller.report_redactor()?;
    let settings_value =
        serde_json::to_value(&settings).map_err(|_| "support report privacy filter failed")?;
    redactor.remember_json(&settings_value);
    let manager = state.reports.clone();
    tokio::task::spawn_blocking(move || {
        manager.prepare(&error, &settings, status, &logs, &redactor)
    })
    .await
    .map_err(|_| "support report preparation failed".to_owned())?
}

#[cfg(windows)]
#[tauri::command]
pub async fn prepare_ics_report(state: State<'_, TauriState>) -> Result<ReportPreview, String> {
    let mismatch = state
        .controller
        .ics_signature_mismatch()
        .await
        .ok_or("no Windows ICS signature mismatch is available")?;
    let settings = state.controller.settings().await;
    let status = state.controller.status().await;
    let manager = state.reports.clone();
    tokio::task::spawn_blocking(move || {
        let directory = crate::native::system_directory().map_err(|error| error.to_string())?;
        let dll = std::fs::File::open(directory.join(crate::os::hotspot::ICS_CLIENT_DLL))
            .map_err(|_| "could not open the system DLL")?;
        let build = crate::native::windows_build().unwrap_or_else(|| "unknown".to_owned());
        manager.prepare_ics_report(mismatch, dll, build, &settings, status)
    })
    .await
    .map_err(|_| "support report preparation failed".to_owned())?
}

#[tauri::command]
pub async fn send_support_report(
    state: State<'_, TauriState>,
    report_id: Uuid,
    consent: bool,
) -> Result<ReportReceipt, String> {
    let operation = state
        .controller
        .telemetry()
        .operation(Operation::ReportUpload);
    let result = state.reports.send(report_id, consent).await;
    operation.finish(result.as_ref().err().map(|_| ErrorKind::Network));
    result
}

#[tauri::command]
pub async fn discard_support_report(
    state: State<'_, TauriState>,
    report_id: Uuid,
) -> Result<(), String> {
    state.reports.discard(report_id);
    Ok(())
}

#[tauri::command]
pub async fn import_subscription(
    state: State<'_, TauriState>,
    source: String,
) -> Result<AppSettings, String> {
    state
        .controller
        .import_subscription(&source)
        .await
        .map_err(app_error)?;
    Ok(state.controller.settings().await)
}

/// Import from the subscription stored in settings — whichever one this build
/// was given, until the user replaces it. Seeds the profile list on first run.
#[tauri::command]
pub async fn refresh_subscription(state: State<'_, TauriState>) -> Result<AppSettings, String> {
    state
        .controller
        .import_configured_subscription()
        .await
        .map_err(app_error)?;
    Ok(state.controller.settings().await)
}

#[tauri::command]
pub async fn complete_onboarding(state: State<'_, TauriState>) -> Result<AppSettings, String> {
    state
        .controller
        .complete_onboarding()
        .await
        .map_err(app_error)?;
    Ok(state.controller.settings().await)
}

#[tauri::command]
pub async fn select_profile(
    state: State<'_, TauriState>,
    profile_id: String,
) -> Result<AppSettings, String> {
    state
        .controller
        .select_profile(profile_id)
        .await
        .map_err(app_error)?;
    Ok(state.controller.settings().await)
}

#[tauri::command]
pub async fn delete_profile(
    state: State<'_, TauriState>,
    profile_id: String,
) -> Result<AppSettings, String> {
    state
        .controller
        .delete_profile(profile_id)
        .await
        .map_err(app_error)?;
    Ok(state.controller.settings().await)
}

#[tauri::command]
pub async fn start_hotspot(state: State<'_, TauriState>) -> Result<HotspotStatus, String> {
    state.controller.start_hotspot().await.map_err(app_error)?;
    Ok(state.controller.status().await)
}

#[tauri::command]
pub async fn stop_hotspot(state: State<'_, TauriState>) -> Result<HotspotStatus, String> {
    state.controller.stop_hotspot().await.map_err(app_error)?;
    Ok(state.controller.status().await)
}

#[tauri::command]
pub async fn update_geo_data(state: State<'_, TauriState>) -> Result<(), String> {
    state.controller.update_geo_data().await.map_err(app_error)
}

#[tauri::command]
pub async fn discover_adapters(
    state: State<'_, TauriState>,
) -> Result<Vec<NetworkAdapter>, String> {
    state.controller.discover_wifi_adapters().map_err(app_error)
}

#[tauri::command]
pub async fn scan_conflicts() -> Result<crate::os::conflicts::ConflictReport, String> {
    ConflictScanner::default()
        .scan()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn get_logs(
    state: State<'_, TauriState>,
    minimum_level: Option<String>,
) -> Result<Vec<LogEntryDto>, String> {
    let level = minimum_level
        .as_deref()
        .and_then(parse_log_level)
        .unwrap_or(AppLogLevel::Debug);
    Ok(log_entries(&state.logs, level))
}

#[tauri::command]
pub async fn clear_logs(state: State<'_, TauriState>) -> Result<(), String> {
    state.logs.clear();
    state.reports.clear();
    Ok(())
}

fn log_entries(logs: &InMemoryLogStore, minimum_level: AppLogLevel) -> Vec<LogEntryDto> {
    logs.entries()
        .into_iter()
        .filter(|entry| minimum_level.allows(entry))
        .map(|entry| LogEntryDto {
            timestamp: entry
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: entry.effective_level().to_string(),
            target: entry.target,
            message: entry.message,
        })
        .collect()
}

fn parse_log_level(value: &str) -> Option<AppLogLevel> {
    match value.to_ascii_lowercase().as_str() {
        "debug" => Some(AppLogLevel::Debug),
        "info" => Some(AppLogLevel::Info),
        "warn" => Some(AppLogLevel::Warn),
        "error" => Some(AppLogLevel::Error),
        _ => None,
    }
}

fn app_error(error: AppError) -> String {
    error.to_string()
}
