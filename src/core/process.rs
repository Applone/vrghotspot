use crate::core::config::{CoreConfig, CoreConfigError};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, info, warn};

pub struct CoreManager {
    home_dir: Option<PathBuf>,
}

impl CoreManager {
    pub fn new() -> Self {
        Self { home_dir: None }
    }

    pub fn with_home_dir(home_dir: PathBuf) -> Self {
        Self {
            home_dir: Some(home_dir),
        }
    }

    pub async fn start(&mut self, config: CoreConfig) -> Result<CoreHandle, CoreProcessError> {
        let config_yaml = config.to_yaml()?;
        debug!(
            config_size = config_yaml.len(),
            "serialized Mihomo configuration"
        );
        if let Err(err) = save_final_config(&config_yaml) {
            warn!(error = %err, "failed to save final Mihomo configuration YAML");
        }

        info!(backend = "embedded", "using embedded Mihomo core");

        if let Some(home_dir) = &self.home_dir {
            info!(
                home_dir = %home_dir.display(),
                "configuring embedded Mihomo home directory"
            );
            if !home_dir.exists() {
                warn!(
                    home_dir = %home_dir.display(),
                    "home directory does not exist"
                );
            }
            embedded::set_home_dir(home_dir)?;
            info!(
                home_dir = %home_dir.display(),
                "embedded Mihomo home directory configured"
            );
        } else {
            warn!("no home directory specified for embedded Mihomo core");
        }

        info!(
            backend = "embedded",
            config_size = config_yaml.len(),
            "starting embedded Mihomo instance"
        );
        let inner = embedded::start_yaml(&config_yaml).await?;
        info!(
            backend = "embedded",
            "embedded Mihomo instance started successfully"
        );
        Ok(CoreHandle {
            inner: CoreHandleInner::Embedded(inner),
        })
    }
}

fn save_final_config(config_yaml: &str) -> Result<(), CoreProcessError> {
    let dir = core_config_dir();
    fs::create_dir_all(&dir).map_err(CoreProcessError::ConfigDump)?;

    // Overwrite a single file rather than accumulating one timestamped
    // snapshot per start — those piled up unbounded in the app data dir and
    // only the most recent one is ever useful for diagnosis.
    let latest = dir.join("mihomo-final-latest.yaml");
    fs::write(&latest, config_yaml).map_err(CoreProcessError::ConfigDump)?;

    info!(
        latest = %latest.display(),
        "saved final Mihomo configuration YAML"
    );
    Ok(())
}

fn core_config_dir() -> PathBuf {
    app_data_dir().join("core-configs")
}

/// Directory that receives rolling core log files. Exposed so the logging
/// setup in `main` uses the same XDG location as the rest of the application.
pub fn core_logs_dir() -> PathBuf {
    app_data_dir().join("core-logs")
}

/// Version string reported by the embedded Mihomo core (injected at build time
/// via ldflags). Returns `None` if the core does not report a version.
pub fn core_version() -> Option<String> {
    embedded::core_version()
}

fn app_data_dir() -> PathBuf {
    crate::os::app_config_dir().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("vrghotspot")
    })
}

impl Default for CoreManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CoreHandle {
    inner: CoreHandleInner,
}

enum CoreHandleInner {
    Embedded(embedded::EmbeddedCoreHandle),
}

impl CoreHandle {
    pub fn process_id(&self) -> Option<u32> {
        match &self.inner {
            CoreHandleInner::Embedded(_) => None,
        }
    }

    pub async fn wait(self) -> Result<(), CoreProcessError> {
        match self.inner {
            CoreHandleInner::Embedded(handle) => handle.wait().await,
        }
    }

    pub async fn stop(self) -> Result<(), CoreProcessError> {
        match self.inner {
            CoreHandleInner::Embedded(handle) => handle.stop().await,
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreProcessError {
    #[error(transparent)]
    Config(#[from] CoreConfigError),
    #[error("failed to start embedded Mihomo core: {0}")]
    EmbeddedStart(String),
    #[error(
        "timed out after {seconds} seconds while starting embedded Mihomo core. Recent core bridge logs: {diagnostics}"
    )]
    EmbeddedStartTimedOut { seconds: u64, diagnostics: String },
    #[error("failed to configure embedded Mihomo core: {0}")]
    EmbeddedConfigure(String),
    #[error("failed to save final Mihomo configuration YAML: {0}")]
    ConfigDump(std::io::Error),
    #[error("failed to stop embedded Mihomo core: {0}")]
    EmbeddedStop(String),
    #[error("failed to wait for shutdown signal: {0}")]
    ShutdownSignal(std::io::Error),
    #[error("Mihomo configuration contains an interior NUL byte")]
    InvalidConfigCString,
    #[error("failed to join embedded Mihomo blocking task: {0}")]
    BlockingTaskJoin(tokio::task::JoinError),
}

mod embedded {
    use super::CoreProcessError;
    use std::collections::VecDeque;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_ulonglong};
    use std::sync::{Mutex, Once, OnceLock};
    use std::time::Duration;
    use tracing::{debug, error, info, warn};

    const EMBEDDED_START_TIMEOUT: Duration = Duration::from_secs(40);
    const BRIDGE_LOG_CAPACITY: usize = 80;
    const BRIDGE_LOG_DIAGNOSTIC_LINES: usize = 20;

    #[link(name = "vrg_core_bridge", kind = "static")]
    unsafe extern "C" {
        fn VrgCoreSetLogCallback(
            callback: Option<unsafe extern "C" fn(c_int, *const c_char, c_int)>,
        );
        fn VrgCoreSetHomeDir(
            path: *const c_char,
            path_len: c_int,
            err_buf: *mut c_char,
            err_buf_len: c_int,
        ) -> c_int;
        fn VrgCoreStartYAML(
            config: *const c_char,
            config_len: c_int,
            err_buf: *mut c_char,
            err_buf_len: c_int,
        ) -> c_ulonglong;
        fn VrgCoreStop(handle: c_ulonglong, err_buf: *mut c_char, err_buf_len: c_int) -> c_int;
        fn VrgCoreVersion(buf: *mut c_char, buf_len: c_int);
    }

    /// Version string reported by the embedded Mihomo core, injected at link
    /// time (see `build.rs`). Returns `None` if the buffer comes back empty.
    pub fn core_version() -> Option<String> {
        let mut buf = ErrorBuffer::new();
        unsafe {
            VrgCoreVersion(buf.as_mut_ptr(), buf.len());
        }
        let version = buf.message();
        if version.is_empty() {
            None
        } else {
            Some(version)
        }
    }

    static INSTALL_LOG_CALLBACK: Once = Once::new();
    static BRIDGE_LOGS: OnceLock<Mutex<VecDeque<BridgeLogEntry>>> = OnceLock::new();

    pub struct EmbeddedCoreHandle {
        handle: Option<c_ulonglong>,
    }

    #[derive(Clone)]
    struct BridgeLogEntry {
        level: &'static str,
        message: String,
    }

    pub fn set_home_dir(path: &std::path::Path) -> Result<(), CoreProcessError> {
        install_log_callback();
        let path_string = path.to_string_lossy().into_owned();
        info!(path = %path_string, "setting embedded Mihomo home directory via bridge FFI");

        let path = CString::new(path_string.as_bytes()).map_err(|_| {
            CoreProcessError::EmbeddedConfigure(
                "home directory contains an interior NUL byte".into(),
            )
        })?;

        let mut err_buf = ErrorBuffer::new();
        let result = unsafe {
            VrgCoreSetHomeDir(
                path.as_ptr(),
                path.as_bytes().len() as c_int,
                err_buf.as_mut_ptr(),
                err_buf.len(),
            )
        };

        if result == 0 {
            info!("embedded Mihomo home directory configured successfully");
            Ok(())
        } else {
            let message = err_buf.message();
            error!(error = %message, "failed to configure embedded Mihomo home directory");
            Err(CoreProcessError::EmbeddedConfigure(message))
        }
    }

    pub async fn start_yaml(config_yaml: &str) -> Result<EmbeddedCoreHandle, CoreProcessError> {
        install_log_callback();

        info!(
            config_size = config_yaml.len(),
            "preparing embedded Mihomo startup"
        );
        debug!(
            config_preview = %if config_yaml.len() > 500 {
                format!("{}...(truncated)", &config_yaml[..500])
            } else {
                config_yaml.to_string()
            },
            "Mihomo configuration YAML"
        );

        let config =
            CString::new(config_yaml).map_err(|_| CoreProcessError::InvalidConfigCString)?;
        let config_len = config_yaml.len() as c_int;

        info!("calling VrgCoreStartYAML via FFI bridge");
        let start_task = tokio::task::spawn_blocking(move || {
            let mut err_buf = ErrorBuffer::new();
            let handle = unsafe {
                VrgCoreStartYAML(
                    config.as_ptr(),
                    config_len,
                    err_buf.as_mut_ptr(),
                    err_buf.len(),
                )
            };
            // The blocking call can outlive the awaiting task. Keep a guard in
            // its result so abandoning the task still shuts down the instance.
            (
                (handle != 0)
                    .then_some(handle)
                    .map(|handle| EmbeddedCoreHandle {
                        handle: Some(handle),
                    }),
                err_buf,
            )
        });

        let (handle, err_buf) = match tokio::time::timeout(EMBEDDED_START_TIMEOUT, start_task).await
        {
            Ok(result) => result.map_err(CoreProcessError::BlockingTaskJoin)?,
            Err(_) => {
                let diagnostics = recent_bridge_logs();
                error!(
                    timeout_seconds = EMBEDDED_START_TIMEOUT.as_secs(),
                    diagnostics = %diagnostics,
                    "embedded Mihomo startup timed out"
                );
                return Err(CoreProcessError::EmbeddedStartTimedOut {
                    seconds: EMBEDDED_START_TIMEOUT.as_secs(),
                    diagnostics,
                });
            }
        };

        let Some(handle) = handle else {
            let message = append_bridge_diagnostics(err_buf.message());
            error!(
                error = %message,
                "embedded Mihomo failed to start (handle=0)"
            );
            return Err(CoreProcessError::EmbeddedStart(message));
        };

        info!(
            handle = handle.handle,
            "embedded Mihomo started with bridge handle"
        );
        Ok(handle)
    }

    impl EmbeddedCoreHandle {
        pub async fn wait(self) -> Result<(), CoreProcessError> {
            info!("waiting for shutdown signal (Ctrl+C)");
            tokio::signal::ctrl_c()
                .await
                .map_err(CoreProcessError::ShutdownSignal)?;
            info!("shutdown signal received, stopping embedded Mihomo");
            self.stop().await
        }

        pub async fn stop(mut self) -> Result<(), CoreProcessError> {
            info!("stopping embedded Mihomo instance");
            self.stop_blocking()
        }

        fn stop_blocking(&mut self) -> Result<(), CoreProcessError> {
            let Some(handle) = self.handle.take() else {
                debug!("embedded Mihomo handle already consumed, nothing to stop");
                return Ok(());
            };

            info!(handle = handle, "calling VrgCoreStop via FFI bridge");
            let mut err_buf = ErrorBuffer::new();
            let result = unsafe { VrgCoreStop(handle, err_buf.as_mut_ptr(), err_buf.len()) };

            if result == 0 {
                info!(handle = handle, "embedded Mihomo stopped successfully");
                Ok(())
            } else {
                let message = err_buf.message();
                error!(
                    handle = handle,
                    error = %message,
                    "failed to stop embedded Mihomo"
                );
                Err(CoreProcessError::EmbeddedStop(message))
            }
        }
    }

    impl Drop for EmbeddedCoreHandle {
        fn drop(&mut self) {
            if self.handle.is_some() {
                warn!("embedded Mihomo handle dropped without explicit stop");
            }
            if let Err(err) = self.stop_blocking() {
                warn!(error = %err, "failed to stop embedded Mihomo while dropping handle");
            }
        }
    }

    fn install_log_callback() {
        INSTALL_LOG_CALLBACK.call_once(|| {
            if std::env::var("VRG_CORE_BRIDGE_LOG_CALLBACK")
                .map(|value| matches!(value.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
                .unwrap_or(false)
            {
                warn!("core-bridge Rust log callback disabled by VRG_CORE_BRIDGE_LOG_CALLBACK");
                return;
            }

            info!("installing Rust log callback for core-bridge FFI");
            unsafe {
                VrgCoreSetLogCallback(Some(core_bridge_log_callback));
            }
            info!("Rust log callback installed for core-bridge");
        });
    }

    unsafe extern "C" fn core_bridge_log_callback(
        level: c_int,
        message: *const c_char,
        message_len: c_int,
    ) {
        if message.is_null() || message_len <= 0 {
            return;
        }

        let bytes =
            unsafe { std::slice::from_raw_parts(message.cast::<u8>(), message_len as usize) };
        let message = String::from_utf8_lossy(bytes).trim().to_owned();
        if message.is_empty() {
            return;
        }

        // Emit straight into the tracing pipeline so core logs reach the
        // console, the in-memory UI store and the on-disk core-logs file for
        // the whole lifetime of the core -- not just around startup. The ring
        // buffer below is kept solely to build the start-timeout diagnostic.
        emit_bridge_log_to_tracing(level, &message);
        remember_bridge_log(level, &message);
    }

    fn emit_bridge_log_to_tracing(level: c_int, message: &str) {
        match level {
            1 => tracing::error!(target: "core_bridge", "{message}"),
            2 => tracing::warn!(target: "core_bridge", "{message}"),
            4 => tracing::debug!(target: "core_bridge", "{message}"),
            _ => tracing::info!(target: "core_bridge", "{message}"),
        }
    }

    fn bridge_logs() -> &'static Mutex<VecDeque<BridgeLogEntry>> {
        BRIDGE_LOGS.get_or_init(|| Mutex::new(VecDeque::with_capacity(BRIDGE_LOG_CAPACITY)))
    }

    fn remember_bridge_log(level: c_int, message: &str) {
        let level = match level {
            1 => "error",
            2 => "warn",
            4 => "debug",
            _ => "info",
        };
        let entry = BridgeLogEntry {
            level,
            message: message.to_owned(),
        };

        if let Ok(mut logs) = bridge_logs().lock() {
            while logs.len() >= BRIDGE_LOG_CAPACITY {
                logs.pop_front();
            }
            logs.push_back(entry);
        }
    }

    fn recent_bridge_logs() -> String {
        let logs = bridge_logs()
            .lock()
            .map(|logs| {
                logs.iter()
                    .rev()
                    .take(BRIDGE_LOG_DIAGNOSTIC_LINES)
                    .map(|entry| format!("{}: {}", entry.level, entry.message))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if logs.is_empty() {
            return "no bridge logs were captured".to_owned();
        }

        logs.into_iter().rev().collect::<Vec<_>>().join(" | ")
    }

    fn append_bridge_diagnostics(message: String) -> String {
        let diagnostics = recent_bridge_logs();
        if diagnostics == "no bridge logs were captured" {
            return message;
        }
        format!("{message}. Recent core bridge logs: {diagnostics}")
    }

    struct ErrorBuffer {
        bytes: Vec<c_char>,
    }

    impl ErrorBuffer {
        fn new() -> Self {
            Self {
                bytes: vec![0; 4096],
            }
        }

        fn as_mut_ptr(&mut self) -> *mut c_char {
            self.bytes.as_mut_ptr()
        }

        fn len(&self) -> c_int {
            self.bytes.len() as c_int
        }

        fn message(&self) -> String {
            let bytes = self
                .bytes
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>();
            CStr::from_bytes_until_nul(&bytes)
                .unwrap_or(c"unknown core bridge error")
                .to_string_lossy()
                .trim()
                .to_owned()
        }
    }
}
