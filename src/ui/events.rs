use crate::app::HotspotStatus;
use crate::os::conflicts::ConflictReport;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::Emitter;
use tokio::sync::broadcast;

pub const RUNTIME_EVENT: &str = "vrg://runtime-event";

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum UiEvent {
    ConflictWarning(ConflictReport),
    StatusChanged(HotspotStatus),
    SettingsChanged,
    ProfilesChanged,
    ConnectionStarted { pid: Option<u32> },
    ConnectionStopped,
    SharingEnabled { wifi_interface: String },
    SharingFailed(String),
    Warning(String),
    Error(String),
}

pub trait EventSink {
    fn emit(&self, event: UiEvent);
}

#[derive(Clone)]
pub struct UiEventSink {
    sender: broadcast::Sender<UiEvent>,
}

impl UiEventSink {
    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.sender.subscribe()
    }
}

impl Default for UiEventSink {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(128);
        Self { sender }
    }
}

impl EventSink for UiEventSink {
    fn emit(&self, event: UiEvent) {
        let _ = self.sender.send(event);
    }
}

#[derive(Clone, Default)]
pub struct TauriEventSink {
    app_handle: Arc<Mutex<Option<tauri::AppHandle>>>,
}

impl TauriEventSink {
    pub fn attach(&self, app_handle: tauri::AppHandle) {
        if let Ok(mut current) = self.app_handle.lock() {
            *current = Some(app_handle);
        }
    }
}

impl EventSink for TauriEventSink {
    fn emit(&self, event: UiEvent) {
        let app_handle = self
            .app_handle
            .lock()
            .ok()
            .and_then(|current| current.as_ref().cloned());

        if let Some(app_handle) = app_handle
            && let Err(err) = app_handle.emit(RUNTIME_EVENT, event)
        {
            tracing::warn!(error = %err, "failed to emit runtime event to frontend");
        }
    }
}
