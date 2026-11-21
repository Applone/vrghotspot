//! Headless diagnostic CLI, compiled only under the `cli` feature.
//!
//! This exists so the hotspot/TUN machinery can be exercised over SSH without
//! the Tauri GUI. It uses the same controllers as the desktop application.
//!
//! Usage: `vrghotspot cli <command>`
//!   adapters       List system network adapters.
//!   hotspot-status Report Wi-Fi hardware and TUN readiness.
//!   net            Show adapters and the current routes and addresses.
//!   tun-only       Start Mihomo TUN only, probe internet, then stop.
//!   start          Start Mihomo, the hotspot, and tunnel forwarding.
//!   stop           Best-effort teardown of application-owned state.

use std::sync::Arc;
use std::time::Duration;

use crate::app::{AppSettings, HotspotController};
use crate::os::hotspot::{
    AdapterKind, HotspotController as SystemHotspotController, NetworkAdapter,
};
use crate::telemetry::Telemetry;
use crate::ui::events::{UiEvent, UiEventSink};

type CliResult = Result<(), String>;

/// Returns `Some(exit_code)` when invoked as `cli ...`, otherwise `None` so the
/// caller falls through to the normal GUI path.
pub fn maybe_run(telemetry: Telemetry) -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("cli") {
        return None;
    }
    let command = args.next().unwrap_or_else(|| "help".to_owned());
    let runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");
    Some(runtime.block_on(async {
        if let Err(error) = telemetry
            .set_enabled(AppSettings::load_or_env().telemetry_enabled)
            .await
        {
            tracing::warn!(error = %error, "telemetry is unavailable; continuing locally");
        }
        let result = dispatch(&command, &telemetry).await;
        telemetry.shutdown().await;
        result
    }))
}

async fn dispatch(command: &str, telemetry: &Telemetry) -> i32 {
    let result = match command {
        "adapters" => cmd_adapters(),
        "hotspot-status" => cmd_hotspot_status(),
        "net" => cmd_net().await,
        "tun-only" => cmd_tun_only(telemetry).await,
        "start" => cmd_start(telemetry).await,
        "stop" => cmd_stop(telemetry).await,
        other => {
            eprintln!("unknown cli command: {other}");
            print_help();
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn print_help() {
    eprintln!("commands: adapters | hotspot-status | net | tun-only | start | stop");
}

fn kind_label(kind: &AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Ethernet => "ethernet",
        AdapterKind::WiFi => "wifi",
        AdapterKind::Tun => "tun",
        AdapterKind::Loopback => "loopback",
        AdapterKind::Other => "other",
    }
}

fn dump_adapter(adapter: &NetworkAdapter) {
    println!(
        "  [{kind:<9}] up={up:<5} ip={ip:<5} default_route={dr:<5} hotspot={hotspot:<5} public_ok={pub_ok:<5} wifi_ok={wifi_ok:<5}",
        kind = kind_label(&adapter.kind),
        up = adapter.is_up,
        ip = adapter.has_ip_address,
        dr = adapter.has_default_route,
        hotspot = adapter.supports_hotspot,
        pub_ok = adapter.eligible_public_adapter(),
        wifi_ok = adapter.eligible_private_adapter(),
    );
    println!("     id={}", adapter.id);
    println!("     name={}", adapter.name);
}

fn cmd_adapters() -> CliResult {
    let controller = SystemHotspotController::system();
    let adapters = controller
        .enumerate_all()
        .map_err(|err| format!("enumerate adapters: {err}"))?;
    println!("{} adapter(s):", adapters.len());
    for adapter in &adapters {
        dump_adapter(adapter);
    }
    let has_wifi = controller
        .has_physical_wifi_adapter()
        .map_err(|err| format!("wifi check: {err}"))?;
    println!("\nphysical wifi present: {has_wifi}");
    Ok(())
}

fn cmd_hotspot_status() -> CliResult {
    let controller = SystemHotspotController::system();
    let has_wifi = controller
        .has_physical_wifi_adapter()
        .map_err(|err| format!("wifi check: {err}"))?;
    println!("physical wifi present: {has_wifi}");

    let candidates = controller
        .eligible_wifi_adapters()
        .map_err(|err| format!("Wi-Fi devices: {err}"))?;
    println!("Wi-Fi devices: {}", candidates.len());
    for adapter in &candidates {
        dump_adapter(adapter);
    }

    Ok(())
}

async fn cmd_net() -> CliResult {
    cmd_adapters()?;
    #[cfg(target_os = "linux")]
    {
        println!("\n--- IPv4 routes ---");
        run_and_print("ip", &["-4", "route", "show"]).await;
        println!("\n--- addresses ---");
        run_and_print("ip", &["address", "show"]).await;
    }
    #[cfg(windows)]
    {
        println!("\n--- IPv4 routes ---");
        run_and_print("route", &["print", "-4"]).await;
        println!("\n--- addresses ---");
        run_and_print("ipconfig", &[]).await;
    }
    Ok(())
}

async fn cmd_tun_only(telemetry: &Telemetry) -> CliResult {
    let mut settings = AppSettings::load_or_env();
    settings.enable_sharing = false;
    println!(
        "starting Mihomo TUN only (sharing disabled): {}",
        settings.describe_for_logs()
    );

    let controller = spawn_controller(settings, telemetry.clone());
    controller
        .start_hotspot()
        .await
        .map_err(|err| format!("start: {err}"))?;
    println!("\nTUN started. Probing internet through the tunnel...");

    tokio::time::sleep(Duration::from_secs(3)).await;
    probe_internet().await;

    println!("\nstopping...");
    controller
        .stop_hotspot()
        .await
        .map_err(|err| format!("stop: {err}"))?;
    println!("stopped. Verifying host connectivity restored...");
    probe_internet().await;
    Ok(())
}

async fn cmd_start(telemetry: &Telemetry) -> CliResult {
    let settings = AppSettings::load_or_env();
    println!("full start: {}", settings.describe_for_logs());
    let controller = spawn_controller(settings, telemetry.clone());
    controller
        .start_hotspot()
        .await
        .map_err(|err| format!("start: {err}"))?;
    println!("\nstarted. Probing internet through the tunnel...");
    tokio::time::sleep(Duration::from_secs(3)).await;
    probe_internet().await;

    println!("\nHotspot sharing is running. Press Enter to stop.");
    wait_for_enter().await;

    controller
        .stop_hotspot()
        .await
        .map_err(|err| format!("stop: {err}"))?;
    println!("stopped. Verifying host connectivity restored...");
    probe_internet().await;
    Ok(())
}

async fn cmd_stop(telemetry: &Telemetry) -> CliResult {
    println!("best-effort teardown of hotspot state...");
    let controller = spawn_controller(AppSettings::load_or_env(), telemetry.clone());
    controller
        .stop_hotspot()
        .await
        .map_err(|err| format!("stop: {err}"))?;
    println!("done.");
    Ok(())
}

fn spawn_controller(
    settings: AppSettings,
    telemetry: Telemetry,
) -> Arc<HotspotController<UiEventSink>> {
    let sink = UiEventSink::default();
    let mut receiver = sink.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = receiver.recv().await {
            print_event(&event);
        }
    });
    Arc::new(HotspotController::with_telemetry(settings, sink, telemetry))
}

fn print_event(event: &UiEvent) {
    match event {
        UiEvent::StatusChanged(status) => println!("[event] status -> {status:?}"),
        UiEvent::ConnectionStarted { pid } => println!("[event] connection started (pid={pid:?})"),
        UiEvent::ConnectionStopped => println!("[event] connection stopped"),
        UiEvent::SharingEnabled { wifi_interface } => {
            println!("[event] sharing enabled on {wifi_interface}")
        }
        UiEvent::Warning(message) | UiEvent::SharingFailed(message) => {
            println!("[event] warning: {message}")
        }
        UiEvent::Error(message) => println!("[event] error: {message}"),
        UiEvent::ConflictWarning(report) => println!("[event] conflicts: {report:?}"),
        UiEvent::SettingsChanged => println!("[event] settings changed"),
        UiEvent::ProfilesChanged => println!("[event] profiles changed"),
    }
}

async fn probe_internet() {
    // A DNS-independent probe (IP literal) plus a DNS-dependent one, so a broken
    // tunnel can be told apart from broken DNS.
    run_and_print("ping", &["-c", "2", "1.1.1.1"]).await;
    run_and_print("ping", &["-c", "2", "cloudflare.com"]).await;
}

async fn run_and_print(program: &str, args: &[&str]) {
    let program = program.to_owned();
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(&program).args(&args).output()
    })
    .await;

    match output {
        Ok(Ok(output)) => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.trim().is_empty() {
                eprint!("{stderr}");
            }
        }
        Ok(Err(err)) => eprintln!("failed to run command: {err}"),
        Err(err) => eprintln!("probe task join error: {err}"),
    }
}

async fn wait_for_enter() {
    let _ = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    })
    .await;
}
