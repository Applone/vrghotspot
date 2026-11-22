#![cfg_attr(
    all(windows, not(debug_assertions), not(feature = "cli")),
    windows_subsystem = "windows"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::Manager;
use tracing::{error, info};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use vrghotspot::app::{AppSettings, HotspotController};
use vrghotspot::tauri_api::{self, TauriState};
use vrghotspot::ui::events::TauriEventSink;
use vrghotspot::ui::logs::{InMemoryLogLayer, InMemoryLogStore};

/// Set once the close handler has begun tearing down, so a second close request
/// (an impatient click, or the one we issue ourselves via `destroy`) is not
/// treated as a fresh shutdown.
static SHUTDOWN_STARTED: AtomicBool = AtomicBool::new(false);

fn main() {
    #[cfg(target_os = "linux")]
    {
        if let Some(code) = vrghotspot::os::hotspot::run_privileged_helper() {
            std::process::exit(code);
        }
        configure_root_gui_environment();
        apply_nvidia_workaround();
    }
    #[cfg(windows)]
    let elevation = if std::env::args_os().len() == 1 {
        match vrghotspot::os::hotspot::launch_elevated() {
            Ok(true) => return,
            Ok(false) => None,
            Err(error) => Some(error),
        }
    } else {
        None
    };
    // `_core_log_guard` flushes the non-blocking file writer on drop; keep it
    // alive for the whole process so buffered core logs are not lost on exit.
    let (logs, _core_log_guard) = init_logging();
    install_panic_logging();
    #[cfg(windows)]
    if let Some(error) = elevation {
        tracing::warn!(%error, "Administrator access is required to start the Windows tunnel");
    }
    #[cfg(target_os = "linux")]
    if running_as_root() {
        tracing::warn!(
            "GUI is running as root; NetworkManager still uses only the D-Bus system bus, but an unprivileged desktop launch is recommended"
        );
    }

    #[cfg(feature = "cli")]
    if let Some(code) = vrghotspot::cli::maybe_run() {
        drop(_core_log_guard);
        std::process::exit(code);
    }

    match vrghotspot::core::process::core_version() {
        Some(version) => info!(core_version = %version, "embedded Mihomo core version"),
        None => info!("embedded Mihomo core did not report a version"),
    }

    let settings = AppSettings::load_or_env();
    let startup_message = format!("vrghotspot starting with {}", settings.describe_for_logs());
    info!(message = startup_message, "application startup");

    let event_bridge = TauriEventSink::default();
    let app = Arc::new(HotspotController::with_event_sink(
        settings,
        event_bridge.clone(),
    ));

    if autostart_enabled() {
        info!("VRG_AUTOSTART is enabled, starting hotspot from CLI compatibility path");
        let runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");
        runtime.block_on(async {
            if let Err(err) = app.run_once().await {
                error!(error = %err, "autostart failed");
            }
        });
    } else {
        run_interactive(app.clone(), logs.clone(), event_bridge);
    }
    info!("application stopped cleanly");
}

fn run_interactive(
    app: Arc<HotspotController<TauriEventSink>>,
    logs: InMemoryLogStore,
    event_bridge: TauriEventSink,
) {
    info!(
        retained_log_entries = logs.entries().len(),
        "starting Tauri GUI"
    );

    let shutdown_app = app.clone();
    let subscriptions = app.clone();
    let result = tauri::Builder::default()
        .manage(TauriState::new(app, logs))
        .invoke_handler(tauri::generate_handler![
            tauri_api::get_snapshot,
            tauri_api::get_settings,
            tauri_api::save_settings,
            #[cfg(windows)]
            tauri_api::prepare_ics_report,
            #[cfg(windows)]
            tauri_api::send_ics_report,
            #[cfg(windows)]
            tauri_api::discard_ics_report,
            tauri_api::read_clipboard,
            tauri_api::import_profiles,
            tauri_api::get_profile_yaml,
            tauri_api::save_profile_yaml,
            tauri_api::add_subscription,
            tauri_api::update_subscription,
            tauri_api::delete_subscription,
            tauri_api::ping_subscription,
            tauri_api::refresh_subscription,
            tauri_api::complete_onboarding,
            tauri_api::select_profile,
            tauri_api::delete_profile,
            tauri_api::start_hotspot,
            tauri_api::stop_hotspot,
            tauri_api::update_geo_data,
            tauri_api::discover_adapters,
            tauri_api::scan_conflicts,
            tauri_api::get_logs,
            tauri_api::clear_logs,
        ])
        .setup(move |tauri_app| {
            event_bridge.attach(tauri_app.handle().clone());
            let subscriptions = subscriptions.clone();
            tauri::async_runtime::spawn(async move {
                subscriptions.run_subscription_updates().await;
            });
            if let Some(window) = tauri_app.get_webview_window("main") {
                let _ = window.set_title("VRG Hotspot");
            }
            Ok(())
        })
        .on_window_event(move |window, event| {
            // Keep the process alive until networking teardown finishes.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                if SHUTDOWN_STARTED.swap(true, Ordering::SeqCst) {
                    return;
                }
                let app = shutdown_app.clone();
                let window = window.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = app.stop_hotspot().await {
                        error!(error = %err, "failed to stop hotspot during shutdown");
                    }
                    if let Err(err) = window.destroy() {
                        error!(error = %err, "failed to close the window after shutdown");
                    }
                });
            }
        })
        .run(tauri::generate_context!());

    if let Err(err) = result {
        error!(error = %err, "Tauri GUI exited with an error");
    }
}

fn init_logging() -> (InMemoryLogStore, Option<WorkerGuard>) {
    let logs = InMemoryLogStore::default();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Persist Rust and Mihomo logs under the application's XDG configuration
    // directory so failed core starts can be diagnosed after the fact.
    let (file_layer, file_guard) = match build_core_log_file_layer() {
        Some((layer, guard)) => (Some(layer), Some(guard)),
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(InMemoryLogLayer::new(logs.clone()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_thread_ids(true),
        )
        .with(file_layer)
        .init();

    (logs, file_guard)
}

const CORE_LOG_PREFIX: &str = "vrghotspot-core.log";

/// A run started as root (`pkexec vrghotspot`) leaves root-owned daily log
/// files behind. The next ordinary launch cannot append to them, and
/// `tracing_appender` answers that by panicking before the window ever opens —
/// the application became unstartable until the file was removed by hand.
///
/// Renaming the unwritable file out of the way keeps its contents and lets the
/// appender create a fresh one; the directory itself belongs to the user, so
/// renaming is allowed even when the file is not. Returns `false` only when
/// file logging has to be skipped entirely — never a reason to abort startup.
fn clear_unwritable_log_files(dir: &std::path::Path, prefix: &str) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!(
                "failed to read core-logs directory {}: {err}",
                dir.display()
            );
            return false;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(prefix) || name.ends_with(FOREIGN_LOG_SUFFIX) {
            continue;
        }
        match std::fs::OpenOptions::new().append(true).open(&path) {
            Ok(_) => continue,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                let moved = path.with_file_name(format!("{name}{FOREIGN_LOG_SUFFIX}"));
                match std::fs::rename(&path, &moved) {
                    Ok(()) => eprintln!(
                        "core log {} belongs to another user; kept it as {} and started a new one",
                        path.display(),
                        moved.display()
                    ),
                    Err(rename_err) => {
                        eprintln!(
                            "core log {} is not writable and could not be moved aside ({rename_err}); continuing without a log file",
                            path.display()
                        );
                        return false;
                    }
                }
            }
            // Anything else (a directory, a vanished file) is not our business:
            // the appender only ever opens its own daily file.
            Err(_) => continue,
        }
    }

    true
}

const FOREIGN_LOG_SUFFIX: &str = ".other-user";

fn build_core_log_file_layer<S>() -> Option<(
    tracing_subscriber::fmt::Layer<
        S,
        tracing_subscriber::fmt::format::DefaultFields,
        tracing_subscriber::fmt::format::Format,
        NonBlocking,
    >,
    WorkerGuard,
)>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let dir = vrghotspot::core::process::core_logs_dir();
    if let Err(err) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "failed to create core-logs directory {}: {err}",
            dir.display()
        );
        return None;
    }
    if !clear_unwritable_log_files(&dir, CORE_LOG_PREFIX) {
        return None;
    }

    let file_appender = tracing_appender::rolling::daily(&dir, CORE_LOG_PREFIX);
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_writer(writer);
    Some((layer, guard))
}

#[cfg(target_os = "linux")]
fn configure_root_gui_environment() {
    if running_as_root() && std::env::var_os("NO_AT_BRIDGE").is_none() {
        // Root GUI processes usually cannot access the desktop accessibility bus.
        unsafe { std::env::set_var("NO_AT_BRIDGE", "1") };
    }
}

/// WebKitGTK's DMA-BUF renderer crashes under Wayland on the proprietary
/// NVIDIA driver (wl_surface protocol error 71 kills the whole application
/// before the window appears, a known Tauri/WebKitGTK issue). Falling back to
/// the plain GL renderer by setting `WEBKIT_DISABLE_DMABUF_RENDERER=1` avoids
/// the crash. It must be set before the webview is created, so this runs at
/// the very start of `main`.
///
/// An explicit `WEBKIT_DISABLE_DMABUF_RENDERER` value from the environment
/// always wins, so users can force the setting off if a driver update fixes
/// the upstream bug.
#[cfg(target_os = "linux")]
fn apply_nvidia_workaround() {
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some() {
        return;
    }
    let wayland_session = std::env::var_os("XDG_SESSION_TYPE")
        .map(|value| value.eq_ignore_ascii_case("wayland"))
        .unwrap_or_else(|| std::env::var_os("WAYLAND_DISPLAY").is_some());
    if !wayland_session {
        return;
    }
    // The proprietary driver registers the `nvidia` kernel module; the open
    // driver and nouveau do not exhibit the crash.
    let nvidia_present = std::path::Path::new("/sys/module/nvidia").exists()
        || std::path::Path::new("/proc/driver/nvidia").exists();
    if !nvidia_present {
        return;
    }
    unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Route panics through `tracing` as well as stderr.
///
/// Everything else in the application is diagnosed from the rolling log file and
/// the in-memory buffer the settings screen renders. A panic that only reaches
/// stderr is invisible in both — which is precisely the failure a user needs to
/// be able to report.
fn install_panic_logging() {
    std::panic::set_hook(Box::new(|panic_info| {
        let message = format!("vrghotspot panicked: {panic_info}");
        eprintln!("{message}");
        error!(panic = %panic_info, "vrghotspot panicked");
    }));
}

fn autostart_enabled() -> bool {
    std::env::var("VRG_AUTOSTART")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}
