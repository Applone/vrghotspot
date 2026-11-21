use super::protocol::{
    DiagnosticLog, MAX_LOG_ENTRIES, MAX_MESSAGE_BYTES, MAX_REPORT_BYTES, ReportContext,
    ReportReceipt, SCHEMA_VERSION, SupportReport,
};
use super::redaction::{Redactor, truncate};
use super::transport::{Endpoint, limited_body};
use crate::app::{AppSettings, HotspotStatus};
use crate::ui::logs::LogEntry;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
#[cfg(any(windows, test))]
use {super::protocol::WindowsIcsDiagnostic, crate::os::hotspot::IcsSignatureMismatch};

const MAX_PENDING_REPORTS: usize = 4;
const REPORT_EXPIRY: Duration = Duration::from_secs(30 * 60);
const UPLOAD_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Clone, Serialize)]
pub struct ReportPreview {
    pub report_id: Uuid,
    pub destination: String,
    pub payload: String,
    pub log_count: usize,
    pub logs_truncated: bool,
}

struct PendingReport {
    preview: ReportPreview,
    prepared_at: Instant,
    submitted: bool,
}

#[derive(Clone)]
pub struct ReportManager {
    endpoint: Result<Option<Endpoint>, String>,
    started_at: Instant,
    pending: Arc<Mutex<VecDeque<PendingReport>>>,
    upload: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

impl Default for ReportManager {
    fn default() -> Self {
        Self::new(Ok(None))
    }
}

impl ReportManager {
    /// The report destination is baked in at build time; see
    /// [`super::transport::build_value`].
    pub fn from_env() -> Self {
        Self::new(
            super::transport::build_value(option_env!("VRG_SUPPORT_ENDPOINT"))
                .map(|value| Endpoint::parse(&value))
                .transpose(),
        )
    }

    fn new(endpoint: Result<Option<Endpoint>, String>) -> Self {
        Self {
            endpoint,
            started_at: Instant::now(),
            pending: Arc::new(Mutex::new(VecDeque::new())),
            upload: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn configured(&self) -> bool {
        self.endpoint.as_ref().is_ok_and(Option::is_some)
    }

    fn endpoint(&self) -> Result<&Endpoint, String> {
        self.endpoint
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or_else(|| "support report server is not configured for this build".to_owned())
    }

    pub fn prepare(
        &self,
        error: &str,
        settings: &AppSettings,
        status: HotspotStatus,
        entries: &[LogEntry],
        redactor: &Redactor,
    ) -> Result<ReportPreview, String> {
        if error.trim().is_empty() || error.len() > 64 * 1024 {
            return Err("invalid report error length".to_owned());
        }
        let mut report = self.new_report(
            truncate(&redactor.redact(error), MAX_MESSAGE_BYTES),
            settings,
            status,
        );
        append_logs(&mut report, entries, redactor)?;
        self.enqueue(report)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn prepare_ics_report(
        &self,
        mismatch: IcsSignatureMismatch,
        dll: impl std::io::Read,
        windows_build: String,
        settings: &AppSettings,
        status: HotspotStatus,
    ) -> Result<ReportPreview, String> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        use std::io::Read;

        // Leave the final envelope size check to SupportReport::validate.
        let max_dll_bytes = MAX_REPORT_BYTES / 4 * 3;
        let mut bytes = Vec::new();
        dll.take(max_dll_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "could not read the system DLL")?;
        if bytes.len() > max_dll_bytes {
            return Err("report exceeds size limit".to_owned());
        }
        if format!("{:x}", Sha256::digest(&bytes)) != mismatch.sha256 {
            return Err("system DLL changed since signature verification".to_owned());
        }
        self.enqueue(SupportReport {
            windows_ics: Some(WindowsIcsDiagnostic {
                dll_name: crate::os::hotspot::ICS_CLIENT_DLL.to_owned(),
                dll_sha256: mismatch.sha256,
                dll_base64: Some(STANDARD.encode(bytes)),
                reason: mismatch.reason,
                windows_build,
            }),
            ..self.new_report(
                "hnetcfgclient.dll signature mismatch".to_owned(),
                settings,
                status,
            )
        })
    }

    fn new_report(
        &self,
        error: String,
        settings: &AppSettings,
        status: HotspotStatus,
    ) -> SupportReport {
        SupportReport {
            schema_version: SCHEMA_VERSION,
            report_id: Uuid::new_v4(),
            created_at: unix_seconds(SystemTime::now()),
            error,
            context: ReportContext {
                app_version: env!("CARGO_PKG_VERSION").to_owned(),
                core_version: truncate(
                    option_env!("VRG_MIHOMO_VERSION_BUILT").unwrap_or("unknown"),
                    128,
                ),
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
                uptime_seconds: self.started_at.elapsed().as_secs(),
                hotspot_status: format!("{status:?}"),
                sharing_enabled: settings.enable_sharing,
                telemetry_enabled: settings.telemetry_enabled,
                profile_count: settings.profiles.len(),
            },
            logs: Vec::new(),
            logs_truncated: false,
            windows_ics: None,
        }
    }

    fn enqueue(&self, report: SupportReport) -> Result<ReportPreview, String> {
        let endpoint = self.endpoint()?;
        report.validate().map_err(str::to_owned)?;
        let preview = ReportPreview {
            report_id: report.report_id,
            destination: endpoint.display(),
            payload: serde_json::to_string(&report).map_err(|error| error.to_string())?,
            log_count: report.logs.len(),
            logs_truncated: report.logs_truncated,
        };
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "support report state unavailable")?;
        pending.retain(|report| report.prepared_at.elapsed() < REPORT_EXPIRY);
        while pending.len() >= MAX_PENDING_REPORTS {
            pending.pop_front();
        }
        pending.push_back(PendingReport {
            preview: preview.clone(),
            prepared_at: Instant::now(),
            submitted: false,
        });
        Ok(preview)
    }

    pub fn discard(&self, report_id: Uuid) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.retain(|report| report.preview.report_id != report_id);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }

    pub async fn send(&self, report_id: Uuid, consent: bool) -> Result<ReportReceipt, String> {
        if !consent {
            return Err("explicit consent is required to send a support report".to_owned());
        }
        let endpoint = self.endpoint()?;
        let mut upload = self
            .upload
            .try_lock()
            .map_err(|_| "a support report is already being sent")?;
        let payload = {
            let pending = self
                .pending
                .lock()
                .map_err(|_| "support report state unavailable")?;
            let report = pending
                .iter()
                .find(|report| {
                    report.preview.report_id == report_id
                        && report.prepared_at.elapsed() < REPORT_EXPIRY
                })
                .ok_or("support report has expired; prepare a new report")?;
            if report.submitted {
                return Ok(ReportReceipt { report_id });
            }
            report.preview.payload.clone()
        };
        if upload.is_some_and(|sent| sent.elapsed() < UPLOAD_COOLDOWN) {
            return Err("wait 10 seconds before retrying the support report".to_owned());
        }
        *upload = Some(Instant::now());
        let response = super::transport::client()?
            .post(endpoint.url("v1/reports"))
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|error| format!("support report upload failed: {}", error.without_url()))?;
        if !matches!(
            response.status(),
            reqwest::StatusCode::OK | reqwest::StatusCode::CREATED
        ) {
            return Err(format!(
                "support report server returned HTTP {}; the report was not confirmed",
                response.status().as_u16()
            ));
        }
        let body = limited_body(response).await?;
        let receipt: ReportReceipt = serde_json::from_slice(&body)
            .map_err(|_| "support report server returned an invalid receipt")?;
        if receipt.report_id != report_id {
            return Err("support report server returned a mismatched report ID".to_owned());
        }
        if let Ok(mut pending) = self.pending.lock()
            && let Some(report) = pending
                .iter_mut()
                .find(|report| report.preview.report_id == report_id)
        {
            report.submitted = true;
        }
        Ok(receipt)
    }
}

fn append_logs(
    report: &mut SupportReport,
    entries: &[LogEntry],
    redactor: &Redactor,
) -> Result<(), String> {
    let mut budget = MAX_REPORT_BYTES.saturating_sub(32 * 1024);
    for entry in entries.iter().rev().take(MAX_LOG_ENTRIES) {
        let message = redactor.redact(&entry.message);
        report.logs_truncated |= message.len() > MAX_MESSAGE_BYTES;
        let entry = DiagnosticLog {
            timestamp: unix_seconds(entry.timestamp),
            level: entry.level.to_string(),
            target: truncate(&redactor.redact(&entry.target), 256),
            message: truncate(&message, MAX_MESSAGE_BYTES),
        };
        let size = serde_json::to_vec(&entry)
            .map_err(|error| error.to_string())?
            .len()
            + 1;
        if size > budget {
            report.logs_truncated = true;
            break;
        }
        budget -= size;
        report.logs.push(entry);
    }
    report.logs_truncated |= report.logs.len() < entries.len();
    report.logs.reverse();
    Ok(())
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::logs::InMemoryLogStore;

    #[tokio::test]
    async fn sending_requires_consent_even_when_telemetry_is_disabled() {
        let manager = ReportManager::default();
        let result = manager.send(Uuid::new_v4(), false).await.unwrap_err();
        assert!(result.contains("consent"));
    }

    #[test]
    fn preparing_is_local_redacted_and_retains_original_error_context() {
        use tracing_subscriber::layer::SubscriberExt;
        let manager =
            ReportManager::new(Ok(Some(Endpoint::parse("http://127.0.0.1:8090").unwrap())));
        let logs = InMemoryLogStore::default();
        let subscriber = tracing_subscriber::registry()
            .with(crate::ui::logs::InMemoryLogLayer::new(logs.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "core_bridge", "before error secret-value");
        });
        let mut redactor = Redactor::default();
        redactor.remember("secret-value");
        let preview = manager
            .prepare(
                "full error secret-value",
                &AppSettings::default(),
                HotspotStatus::Stopped,
                &logs.entries(),
                &redactor,
            )
            .unwrap();
        assert!(!preview.payload.contains("secret-value"));
        let report: SupportReport = serde_json::from_str(&preview.payload).unwrap();
        assert_eq!(report.report_id, preview.report_id);
        assert!(!report.context.telemetry_enabled);
        assert_eq!(report.logs.len(), 1);
        assert_eq!(report.logs[0].target, "core_bridge");
        logs.clear();
        assert_eq!(
            serde_json::from_str::<SupportReport>(&preview.payload)
                .unwrap()
                .logs
                .len(),
            1
        );
        manager.discard(preview.report_id);
        assert!(manager.pending.lock().unwrap().is_empty());
    }

    async fn prepared(manager: &ReportManager, error: &str) -> Result<ReportPreview, String> {
        manager.prepare(
            error,
            &AppSettings::default(),
            HotspotStatus::Stopped,
            &[],
            &Redactor::default(),
        )
    }

    #[tokio::test]
    async fn consented_reports_upload_once_and_return_the_id_support_can_look_up() {
        let server = super::super::test_server::TestServer::new(false, Duration::ZERO).await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        let preview = prepared(&manager, "hotspot failed to start").await.unwrap();
        server.reply(
            201,
            serde_json::to_vec(&ReportReceipt {
                report_id: preview.report_id,
            })
            .unwrap(),
        );

        let receipt = manager.send(preview.report_id, true).await.unwrap();
        assert_eq!(receipt.report_id, preview.report_id);
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/reports");
        let uploaded: SupportReport = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(uploaded.report_id, preview.report_id);

        assert_eq!(
            manager
                .send(preview.report_id, true)
                .await
                .unwrap()
                .report_id,
            preview.report_id
        );
        assert_eq!(server.requests().len(), 1);
    }

    #[tokio::test]
    async fn windows_ics_details_are_only_sent_after_explicit_consent() {
        use crate::os::hotspot::IcsMismatchReason;

        let server = super::super::test_server::TestServer::new(false, Duration::ZERO).await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        let dll = b"MZ\0\xffexample DLL bytes";
        let hash = format!("{:x}", Sha256::digest(dll));
        let preview = manager
            .prepare_ics_report(
                IcsSignatureMismatch {
                    sha256: hash.clone(),
                    reason: IcsMismatchReason::UnrecognizedDll,
                },
                &dll[..],
                "19045.6456".to_owned(),
                &AppSettings::default(),
                HotspotStatus::Running,
            )
            .unwrap();

        assert!(manager.send(preview.report_id, false).await.is_err());
        assert!(server.requests().is_empty());
        server.reply(
            200,
            serde_json::to_vec(&ReportReceipt {
                report_id: preview.report_id,
            })
            .unwrap(),
        );
        manager.send(preview.report_id, true).await.unwrap();

        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/reports");
        assert_eq!(requests[0].body, preview.payload.as_bytes());
        let report: SupportReport = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(!report.context.telemetry_enabled);
        assert!(report.logs.is_empty());
        let mut diagnostic = report.windows_ics.unwrap();
        assert_eq!(
            STANDARD
                .decode(diagnostic.dll_base64.take().unwrap())
                .unwrap(),
            dll
        );
        assert_eq!(
            diagnostic,
            WindowsIcsDiagnostic {
                dll_name: "hnetcfgclient.dll".to_owned(),
                dll_sha256: hash,
                dll_base64: None,
                reason: IcsMismatchReason::UnrecognizedDll,
                windows_build: "19045.6456".to_owned(),
            }
        );
        assert!(
            !prepared(&manager, "network failure")
                .await
                .unwrap()
                .payload
                .contains("windows_ics")
        );
    }

    #[test]
    fn changed_or_oversized_dll_cannot_be_queued_for_upload() {
        let manager = ReportManager::new(Ok(Some(Endpoint::parse("http://127.0.0.1").unwrap())));
        for (dll, message) in [
            (vec![0; 32], "system DLL changed"),
            (vec![0; MAX_REPORT_BYTES / 4 * 3 + 1], "size limit"),
        ] {
            let result = manager.prepare_ics_report(
                IcsSignatureMismatch {
                    sha256: "a".repeat(64),
                    reason: crate::os::hotspot::IcsMismatchReason::UnrecognizedDll,
                },
                dll.as_slice(),
                "19045".to_owned(),
                &AppSettings::default(),
                HotspotStatus::Running,
            );
            assert!(result.err().unwrap().contains(message));
        }
        assert!(manager.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mismatched_receipt_is_not_shown_to_the_user_as_success() {
        let server = super::super::test_server::TestServer::new(false, Duration::ZERO).await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        let preview = prepared(&manager, "tunnel unreachable").await.unwrap();
        server.reply(
            200,
            serde_json::to_vec(&ReportReceipt {
                report_id: Uuid::new_v4(),
            })
            .unwrap(),
        );
        assert!(
            manager
                .send(preview.report_id, true)
                .await
                .unwrap_err()
                .contains("mismatched report ID")
        );
    }

    #[tokio::test]
    async fn every_prepared_report_gets_its_own_random_id() {
        let manager =
            ReportManager::new(Ok(Some(Endpoint::parse("http://127.0.0.1:8090").unwrap())));
        let first = prepared(&manager, "first failure").await.unwrap();
        let second = prepared(&manager, "second failure").await.unwrap();
        assert_ne!(first.report_id, second.report_id);
        for preview in [&first, &second] {
            assert!(super::super::protocol::is_random_id(&preview.report_id));
        }
    }

    #[tokio::test]
    async fn discarded_and_expired_reports_cannot_be_sent() {
        let server = super::super::test_server::TestServer::new(false, Duration::ZERO).await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        let discarded = prepared(&manager, "discarded failure").await.unwrap();
        manager.discard(discarded.report_id);
        assert!(
            manager
                .send(discarded.report_id, true)
                .await
                .unwrap_err()
                .contains("expired")
        );
        assert!(
            server.requests().is_empty(),
            "nothing may leave the machine"
        );
    }
}
