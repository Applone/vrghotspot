use crate::app::{AppError, AppSettings, HotspotController, HotspotStatus};
use crate::config::subscription::SubscriptionOptions;
use crate::os::conflicts::ConflictScanner;
use crate::os::hotspot::{NetworkAdapter, UplinkStatus};
#[cfg(windows)]
use crate::telemetry::reports::{ReportManager, ReportPreview, ReportReceipt};
use crate::ui::events::TauriEventSink;
use crate::ui::logs::{AppLogLevel, InMemoryLogStore};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tauri::State;
use uuid::Uuid;

#[derive(Clone)]
pub struct TauriState {
    pub controller: Arc<HotspotController<TauriEventSink>>,
    pub logs: InMemoryLogStore,
    #[cfg(windows)]
    reports: ReportManager,
}

impl TauriState {
    pub fn new(controller: Arc<HotspotController<TauriEventSink>>, logs: InMemoryLogStore) -> Self {
        Self {
            controller,
            logs,
            #[cfg(windows)]
            reports: ReportManager::from_build(),
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
        #[cfg(windows)]
        reports_configured: state.reports.configured(),
        #[cfg(not(windows))]
        reports_configured: false,
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

#[cfg(windows)]
#[tauri::command]
pub async fn prepare_ics_report(state: State<'_, TauriState>) -> Result<ReportPreview, String> {
    let mismatch = state
        .controller
        .ics_signature_mismatch()
        .await
        .ok_or("no Windows ICS signature mismatch is available")?;
    let manager = state.reports.clone();
    tokio::task::spawn_blocking(move || {
        let directory = crate::native::system_directory().map_err(|error| error.to_string())?;
        let dll = std::fs::File::open(directory.join(crate::os::hotspot::ICS_CLIENT_DLL))
            .map_err(|_| "could not open the system DLL")?;
        let build = crate::native::windows_build().unwrap_or_else(|| "unknown".to_owned());
        manager.prepare_ics_report(mismatch, dll, build)
    })
    .await
    .map_err(|_| "support report preparation failed".to_owned())?
}

#[cfg(windows)]
#[tauri::command]
pub async fn send_ics_report(
    state: State<'_, TauriState>,
    report_id: Uuid,
    consent: bool,
) -> Result<ReportReceipt, String> {
    state.reports.send(report_id, consent).await
}

#[cfg(windows)]
#[tauri::command]
pub async fn discard_ics_report(
    state: State<'_, TauriState>,
    report_id: Uuid,
) -> Result<(), String> {
    state.reports.discard(report_id);
    Ok(())
}

#[tauri::command]
pub async fn import_profiles(state: State<'_, TauriState>, source: String) -> Result<(), String> {
    state
        .controller
        .import_profiles(&source)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn get_profile_yaml(
    state: State<'_, TauriState>,
    profile_id: String,
) -> Result<String, String> {
    state
        .controller
        .profile_yaml(&profile_id)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn save_profile_yaml(
    state: State<'_, TauriState>,
    profile_id: Option<String>,
    yaml: String,
) -> Result<(), String> {
    state
        .controller
        .save_profile_yaml(profile_id, &yaml)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn add_subscription(
    state: State<'_, TauriState>,
    options: SubscriptionOptions,
) -> Result<(), String> {
    state
        .controller
        .add_subscription(options)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn update_subscription(
    state: State<'_, TauriState>,
    subscription_id: Uuid,
    options: SubscriptionOptions,
) -> Result<(), String> {
    state
        .controller
        .update_subscription(subscription_id, options)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn refresh_subscription(
    state: State<'_, TauriState>,
    subscription_id: Uuid,
) -> Result<(), String> {
    state
        .controller
        .refresh_subscription(subscription_id)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn delete_subscription(
    state: State<'_, TauriState>,
    subscription_id: Uuid,
) -> Result<(), String> {
    state
        .controller
        .delete_subscription(subscription_id)
        .await
        .map_err(app_error)
}

#[tauri::command]
pub async fn ping_subscription(
    state: State<'_, TauriState>,
    subscription_id: Uuid,
) -> Result<HashMap<String, Option<u64>>, String> {
    state
        .controller
        .ping_subscription(subscription_id)
        .await
        .map_err(app_error)
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub async fn read_clipboard(window: tauri::WebviewWindow) -> Result<String, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    window
        .run_on_main_thread(move || {
            let clipboard =
                gtk::gdk::Display::default().and_then(|display| gtk::Clipboard::default(&display));
            match clipboard {
                Some(clipboard) => clipboard.request_text(|_, text| {
                    let _ = send.send(text.map(str::to_owned));
                }),
                None => {
                    let _ = send.send(None);
                }
            }
        })
        .map_err(|error| error.to_string())?;
    receive
        .await
        .ok()
        .flatten()
        .ok_or_else(|| "clipboard does not contain text".to_owned())
}

#[cfg(windows)]
#[tauri::command]
pub fn read_clipboard() -> Result<String, String> {
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::{
        DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard},
        Memory::{GlobalLock, GlobalSize, GlobalUnlock},
        Ole::CF_UNICODETEXT,
    };

    // CF_UNICODETEXT is a NUL-terminated UTF-16 string in a global allocation.
    // Borrow it only while the clipboard is open and the block is locked.
    unsafe {
        OpenClipboard(None).map_err(|error| error.to_string())?;
        let text = (|| {
            let format = u32::from(CF_UNICODETEXT.0);
            let handle = HGLOBAL(GetClipboardData(format).ok()?.0);
            let len = GlobalSize(handle) / size_of::<u16>();
            let pointer = GlobalLock(handle).cast::<u16>();
            if pointer.is_null() {
                return None;
            }
            let units = std::slice::from_raw_parts(pointer, len);
            let end = units.iter().position(|unit| *unit == 0);
            let text = end.map(|end| String::from_utf16_lossy(&units[..end]));
            let _ = GlobalUnlock(handle);
            text
        })();
        let _ = CloseClipboard();
        text.ok_or_else(|| "clipboard does not contain text".to_owned())
    }
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
    profile_id: Option<String>,
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
        .delete_profile(&profile_id)
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
