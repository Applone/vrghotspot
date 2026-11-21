mod metrics;
pub mod protocol;
pub mod redaction;
pub mod reports;
#[cfg(test)]
mod test_server;
mod transport;

use metrics::Session;
pub use metrics::{DeliveryState, ErrorKind, Operation, OperationGuard};
pub use protocol::*;
use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use transport::{Endpoint, configured_value};
use uuid::Uuid;

const EXPORT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_EXPORT_BACKOFF: Duration = Duration::from_secs(900);

type ClientSampler = Arc<dyn Fn() -> Option<u32> + Send + Sync>;

#[derive(Clone)]
struct Config {
    otlp: Option<Endpoint>,
    support: Option<Endpoint>,
    token: Option<String>,
}

impl Config {
    /// Endpoints are baked in at build time; a running binary cannot be
    /// pointed at another telemetry server, so a tampered environment cannot
    /// redirect the data somewhere else.
    fn from_build() -> Result<Self, String> {
        Ok(Self {
            otlp: transport::build_value(option_env!("VRG_TELEMETRY_ENDPOINT"))
                .map(|value| Endpoint::parse(&value))
                .transpose()?,
            support: transport::build_value(option_env!("VRG_SUPPORT_ENDPOINT"))
                .map(|value| Endpoint::parse(&value))
                .transpose()?,
            token: configured_value("VRG_TELEMETRY_TOKEN", None),
        })
    }
}

struct Inner {
    config: Result<Config, String>,
    identity_path: PathBuf,
    instance_id: Uuid,
    launch_recorded: AtomicBool,
    active: Mutex<Option<Arc<Session>>>,
    worker: AsyncMutex<Option<JoinHandle<()>>>,
    /// Reads the AP lease count from the controller without holding controller
    /// locks; sampling happens in the export worker, not on the GUI path.
    client_sampler: Mutex<Option<ClientSampler>>,
}

#[derive(Clone)]
pub struct Telemetry {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Telemetry")
            .field("status", &self.status())
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TelemetryStatus {
    pub configured: bool,
    pub active: bool,
    /// When the server last confirmed receiving something; `None` if nothing
    /// has been delivered since telemetry was enabled.
    pub last_delivery_unix: Option<u64>,
    /// Export cycles rejected since the last success.
    pub consecutive_failures: u32,
    /// Seconds until the worker's next attempt; `None` when the worker is off.
    pub next_attempt_in_seconds: Option<u64>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new(
            Ok(Config {
                otlp: None,
                support: None,
                token: None,
            }),
            PathBuf::new(),
        )
    }
}

impl Telemetry {
    pub fn from_env(identity_path: PathBuf) -> Self {
        Self::new(Config::from_build(), identity_path)
    }

    fn new(config: Result<Config, String>, identity_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                identity_path,
                instance_id: Uuid::new_v4(),
                launch_recorded: AtomicBool::new(false),
                active: Mutex::new(None),
                worker: AsyncMutex::new(None),
                client_sampler: Mutex::new(None),
            }),
        }
    }

    fn session(&self) -> Option<Arc<Session>> {
        self.inner.active.lock().ok()?.clone()
    }

    pub fn status(&self) -> TelemetryStatus {
        let session = self.session();
        let delivery = session
            .as_ref()
            .map(|session| session.delivery())
            .unwrap_or_default();
        TelemetryStatus {
            configured: self
                .inner
                .config
                .as_ref()
                .is_ok_and(|config| config.otlp.is_some() || config.support.is_some()),
            active: session
                .as_ref()
                .is_some_and(|session| session.enabled.load(Ordering::Acquire)),
            last_delivery_unix: delivery.last_success_unix,
            consecutive_failures: delivery.consecutive_failures,
            next_attempt_in_seconds: session.is_some().then_some(delivery.next_attempt_seconds),
        }
    }

    pub fn set_client_sampler(&self, sampler: impl Fn() -> Option<u32> + Send + Sync + 'static) {
        if let Ok(mut slot) = self.inner.client_sampler.lock() {
            *slot = Some(Arc::new(sampler));
        }
    }

    pub async fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut worker = self.inner.worker.lock().await;
        if !enabled {
            let session = self
                .inner
                .active
                .lock()
                .ok()
                .and_then(|mut active| active.take());
            if let Some(session) = &session {
                session.enabled.store(false, Ordering::Release);
            }
            if let Some(worker) = worker.take() {
                worker.abort();
                let _ = worker.await;
            }
            if let Some(session) = session {
                session.shutdown();
            }
            return Ok(());
        }
        if self.session().is_some() {
            return Ok(());
        }
        let config = self.inner.config.clone()?;
        if config.otlp.is_none() && config.support.is_none() {
            return Err("telemetry server is not configured for this build".to_owned());
        }
        let client = transport::client()?;
        let installation = if config.support.is_some() {
            Some(
                load_installation_id(&self.inner.identity_path)
                    .map_err(|_| "could not persist the telemetry installation ID")?,
            )
        } else {
            None
        };
        let session = Arc::new(Session::new(
            config.otlp.as_ref(),
            client.clone(),
            config.token.as_deref(),
            self.inner.instance_id,
        )?);
        if !self.inner.launch_recorded.swap(true, Ordering::AcqRel) {
            session.launch();
        }
        session.hotspot_state(false);
        *self
            .inner
            .active
            .lock()
            .map_err(|_| "telemetry state is unavailable")? = Some(session.clone());
        let sampler = self
            .inner
            .client_sampler
            .lock()
            .ok()
            .and_then(|sampler| sampler.clone());
        *worker = Some(tokio::spawn(export_loop(
            session,
            config,
            client,
            installation,
            EXPORT_INTERVAL,
            sampler,
        )));
        Ok(())
    }

    pub async fn shutdown(&self) {
        let mut worker = self.inner.worker.lock().await;
        if let Some(worker) = worker.take() {
            worker.abort();
            let _ = worker.await;
        }
        let session = self
            .inner
            .active
            .lock()
            .ok()
            .and_then(|mut active| active.take());
        if let Some(session) = session {
            session.hotspot_state(false);
            let _ = tokio::time::timeout(Duration::from_secs(3), session.export()).await;
            session.shutdown();
        }
    }

    pub fn operation(&self, operation: Operation) -> OperationGuard {
        OperationGuard {
            session: self.session(),
            operation,
            started_at: Instant::now(),
        }
    }

    pub fn log(&self, level: &tracing::Level, target: &str) {
        if let Some(session) = self.session() {
            session.log(level, target);
        }
    }

    pub fn hotspot_state(&self, running: bool) {
        if let Some(session) = self.session() {
            session.hotspot_state(running);
        }
    }

    pub fn clients(&self, count: u32) {
        if let Some(session) = self.session() {
            session.clients(count);
        }
    }

    /// A startup connectivity check finished. Call only when the check actually
    /// ran; skipping an unconfigured surface records nothing rather than a
    /// phantom failure.
    pub fn availability(&self, surface: &'static str, available: bool) {
        if let Some(session) = self.session() {
            session.availability(surface, available);
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.get_mut().take() {
            worker.abort();
        }
        if let Ok(active) = self.active.get_mut()
            && let Some(session) = active.take()
        {
            session.shutdown();
        }
    }
}

async fn export_loop(
    session: Arc<Session>,
    config: Config,
    client: reqwest::Client,
    installation: Option<Uuid>,
    base_interval: Duration,
    client_sampler: Option<ClientSampler>,
) {
    let mut delay = Duration::ZERO;
    // Something other than success means "keep retrying": the collector may be
    // down exactly when the user's network is, and support wants to see the
    // installation once connectivity returns.
    let mut registered = config.support.is_none() || installation.is_none();
    loop {
        tokio::time::sleep(delay).await;
        if !session.enabled.load(Ordering::Acquire) {
            return;
        }
        if let Some(sampler) = &client_sampler
            && let Some(count) = sampler()
        {
            session.clients(count);
        }
        let mut succeeded = true;
        if !registered {
            registered = client
                .post(config.support.as_ref().unwrap().url("v1/installations"))
                .json(&Installation {
                    installation_id: installation.unwrap(),
                })
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
            succeeded &= registered;
        }
        if session.export().await.is_err() {
            succeeded = false;
        }
        if succeeded {
            session.record_delivery(true, base_interval);
            delay = base_interval;
        } else {
            delay = delay
                .max(base_interval)
                .saturating_mul(2)
                .min(MAX_EXPORT_BACKOFF);
            session.record_delivery(false, delay);
        }
    }
}

fn load_installation_id(path: &Path) -> std::io::Result<Uuid> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    fn read_id(path: &Path) -> std::io::Result<Uuid> {
        let mut value = String::new();
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        }
        options.open(path)?.take(128).read_to_string(&mut value)?;
        Uuid::parse_str(value.trim())
            .ok()
            .filter(is_random_id)
            .ok_or_else(|| std::io::Error::other("invalid installation ID"))
    }
    match read_id(path) {
        Ok(id) => return Ok(id),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let id = Uuid::new_v4();
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        write!(file, "{id}")?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => Ok(id),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_id(path),
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_id_is_random_stable_and_private() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("vrg-telemetry-{}", Uuid::new_v4()));
        let path = directory.join("installation-id");
        let first = load_installation_id(&path).unwrap();
        assert!(is_random_id(&first));
        assert_eq!(first, load_installation_id(&path).unwrap());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn disabled_telemetry_does_not_create_an_identity_or_initialize_exporters() {
        let path = std::env::temp_dir().join(format!("vrg-unused-{}", Uuid::new_v4()));
        let telemetry = Telemetry::new(Err("invalid endpoint".to_owned()), path.clone());
        telemetry.set_enabled(false).await.unwrap();
        telemetry.operation(Operation::HotspotStart).finish(None);
        telemetry.shutdown().await;
        assert!(!path.exists());
        assert!(!telemetry.status().active);
    }

    #[tokio::test]
    async fn opt_out_cancels_the_worker_and_discards_the_session() {
        let telemetry = Telemetry::new(
            Ok(Config {
                otlp: Some(Endpoint::parse("http://127.0.0.1:9").unwrap()),
                support: None,
                token: None,
            }),
            PathBuf::new(),
        );
        telemetry.set_enabled(true).await.unwrap();
        let old_session = telemetry.session().unwrap();
        let operation = telemetry.operation(Operation::HotspotStart);
        telemetry.set_enabled(false).await.unwrap();
        operation.finish(None);
        assert!(!telemetry.status().active);
        assert!(!old_session.enabled.load(Ordering::Acquire));
        assert!(telemetry.inner.worker.lock().await.is_none());
        telemetry.set_enabled(true).await.unwrap();
        assert!(!Arc::ptr_eq(&old_session, &telemetry.session().unwrap()));
        telemetry.set_enabled(false).await.unwrap();
    }

    fn config(server: &test_server::TestServer, token: Option<&str>) -> Config {
        Config {
            otlp: Some(server.endpoint.clone()),
            support: Some(server.endpoint.clone()),
            token: token.map(str::to_owned),
        }
    }

    fn identity_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("vrg-telemetry-{}", Uuid::new_v4()))
            .join("installation-id")
    }

    #[tokio::test]
    async fn enabled_telemetry_registers_the_installation_and_exports_metrics_and_logs() {
        let server = test_server::TestServer::new(false, Duration::ZERO).await;
        let path = identity_path();
        let telemetry = Telemetry::new(Ok(config(&server, Some("export-token"))), path.clone());
        telemetry.set_enabled(true).await.unwrap();
        telemetry
            .operation(Operation::HotspotStart)
            .finish(Some(ErrorKind::Permission));
        telemetry.hotspot_state(true);
        telemetry.clients(3);
        server.wait_for_requests(3).await;
        telemetry.shutdown().await;

        let requests = server.requests();
        let paths = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"/v1/installations"), "{paths:?}");
        assert!(paths.contains(&"/v1/metrics"), "{paths:?}");
        assert!(paths.contains(&"/v1/logs"), "{paths:?}");

        let installation = requests
            .iter()
            .find(|request| request.path == "/v1/installations")
            .unwrap();
        let registered: Installation = serde_json::from_slice(&installation.body).unwrap();
        assert_eq!(
            registered.installation_id,
            load_installation_id(&path).unwrap()
        );
        assert_eq!(
            paths
                .iter()
                .filter(|path| **path == "/v1/installations")
                .count(),
            1,
            "registration is sent once at startup, not on a schedule"
        );

        for request in requests
            .iter()
            .filter(|request| request.path != "/v1/installations")
        {
            assert_eq!(request.headers["authorization"], "Bearer export-token");
            assert_eq!(
                request.headers["content-type"], "application/x-protobuf",
                "{}",
                request.path
            );
        }
        let metrics = requests
            .iter()
            .find(|request| request.path == "/v1/metrics")
            .unwrap();
        let encoded = String::from_utf8_lossy(&metrics.body);
        assert!(encoded.contains("vrghotspot.operations"), "{encoded}");
        assert!(encoded.contains("hotspot_start"), "{encoded}");
        assert!(!encoded.contains(&registered.installation_id.to_string()));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn opting_out_stops_all_network_delivery() {
        let server = test_server::TestServer::new(false, Duration::ZERO).await;
        let path = identity_path();
        let telemetry = Telemetry::new(Ok(config(&server, None)), path.clone());
        telemetry.set_enabled(true).await.unwrap();
        server.wait_for_requests(1).await;
        telemetry.set_enabled(false).await.unwrap();

        let delivered = server.requests().len();
        telemetry
            .operation(Operation::SubscriptionImport)
            .finish(None);
        telemetry.clients(9);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(server.requests().len(), delivered);
        assert!(!telemetry.status().active);
        telemetry.shutdown().await;
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn rejected_exports_report_failure_and_keep_logs_for_the_next_attempt() {
        let server = test_server::TestServer::new(false, Duration::ZERO).await;
        server.reply(503, Vec::new());
        let path = identity_path();
        let telemetry = Telemetry::new(Ok(config(&server, None)), path.clone());
        telemetry.set_enabled(true).await.unwrap();
        let session = telemetry.session().unwrap();
        session.record_operation(Operation::CoreStart, Duration::from_secs(1), None);
        assert_eq!(session.queued_log_count(), 1);
        assert!(session.export().await.is_err());
        assert_eq!(
            session.queued_log_count(),
            1,
            "a rejected log export must keep records so the next attempt can deliver them"
        );

        server.reply(200, Vec::new());
        session.export().await.unwrap();
        assert_eq!(
            session.queued_log_count(),
            0,
            "accepted logs must leave the queue instead of being resent forever"
        );
        telemetry.shutdown().await;
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn a_rejected_registration_is_retried_and_delivery_status_recovers() {
        let server = test_server::TestServer::new(false, Duration::ZERO).await;
        server.reply(503, Vec::new());
        let client = transport::client().unwrap();
        let session = Arc::new(
            Session::new(Some(&server.endpoint), client.clone(), None, Uuid::new_v4()).unwrap(),
        );
        let worker = tokio::spawn(export_loop(
            session.clone(),
            config(&server, None),
            client,
            Some(Uuid::new_v4()),
            Duration::from_millis(10),
            None,
        ));
        let mut attempts = 0;
        for _ in 0..500 {
            attempts = server
                .requests()
                .iter()
                .filter(|request| request.path == "/v1/installations")
                .count();
            if attempts >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(attempts >= 2, "registration must retry after a failure");
        assert!(session.delivery().consecutive_failures > 0);
        server.reply(200, Vec::new());
        for _ in 0..500 {
            let delivery = session.delivery();
            if delivery.last_success_unix.is_some() && delivery.consecutive_failures == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let delivery = session.delivery();
        assert!(delivery.last_success_unix.is_some());
        assert_eq!(delivery.consecutive_failures, 0);
        session.enabled.store(false, Ordering::Release);
        worker.abort();
        let _ = worker.await;
    }

    #[tokio::test]
    async fn the_client_sampler_runs_in_the_export_loop_without_a_gui() {
        let server = test_server::TestServer::new(false, Duration::ZERO).await;
        let path = identity_path();
        let telemetry = Telemetry::new(
            Ok(Config {
                otlp: Some(server.endpoint.clone()),
                support: None,
                token: None,
            }),
            path,
        );
        telemetry.set_client_sampler(|| Some(5));
        telemetry.set_enabled(true).await.unwrap();
        server.wait_for_requests(1).await;
        telemetry.shutdown().await;
        let requests = server.requests();
        let metrics = requests
            .iter()
            .find(|request| request.path == "/v1/metrics")
            .unwrap();
        let encoded = String::from_utf8_lossy(&metrics.body);
        assert!(encoded.contains("vrghotspot.hotspot.clients"), "{encoded}");
    }
}
