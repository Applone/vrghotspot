use super::transport::{Endpoint, limited_body};
use crate::os::hotspot::{ICS_CLIENT_DLL, IcsMismatchReason, IcsSignatureMismatch};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

const SCHEMA_VERSION: u32 = 2;
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportReceipt {
    pub report_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IcsReport {
    schema_version: u32,
    report_id: Uuid,
    windows_ics: WindowsIcsDiagnostic,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsIcsDiagnostic {
    dll_name: String,
    dll_sha256: String,
    dll_base64: String,
    reason: IcsMismatchReason,
    windows_build: String,
}

const MAX_PENDING_REPORTS: usize = 4;
const REPORT_EXPIRY: Duration = Duration::from_secs(30 * 60);
const UPLOAD_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Clone, Serialize)]
pub struct ReportPreview {
    pub report_id: Uuid,
    pub destination: String,
    pub payload: String,
}

struct PendingReport {
    preview: ReportPreview,
    prepared_at: Instant,
    submitted: bool,
}

#[derive(Clone)]
pub struct ReportManager {
    endpoint: Result<Option<Endpoint>, String>,
    pending: Arc<Mutex<VecDeque<PendingReport>>>,
    upload: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

impl ReportManager {
    #[cfg(windows)]
    pub fn from_build() -> Self {
        Self::new(
            option_env!("VRG_SUPPORT_ENDPOINT")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(Endpoint::parse)
                .transpose(),
        )
    }

    fn new(endpoint: Result<Option<Endpoint>, String>) -> Self {
        Self {
            endpoint,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            upload: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    #[cfg(windows)]
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

    pub(crate) fn prepare_ics_report(
        &self,
        mismatch: IcsSignatureMismatch,
        dll: impl Read,
        windows_build: String,
    ) -> Result<ReportPreview, String> {
        let endpoint = self.endpoint()?;
        let max_dll_bytes = MAX_REPORT_BYTES / 4 * 3;
        let mut bytes = Vec::new();
        dll.take(max_dll_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "could not read the system DLL")?;
        if bytes.len() > max_dll_bytes {
            return Err("report exceeds size limit".to_owned());
        }
        if bytes.is_empty() || hex::encode(Sha256::digest(&bytes)) != mismatch.sha256 {
            return Err("system DLL changed since signature verification".to_owned());
        }

        let report = IcsReport {
            schema_version: SCHEMA_VERSION,
            report_id: Uuid::new_v4(),
            windows_ics: WindowsIcsDiagnostic {
                dll_name: ICS_CLIENT_DLL.to_owned(),
                dll_sha256: mismatch.sha256,
                dll_base64: STANDARD.encode(bytes),
                reason: mismatch.reason,
                windows_build,
            },
        };
        let payload = serde_json::to_string(&report).map_err(|error| error.to_string())?;
        if payload.len() > MAX_REPORT_BYTES {
            return Err("report exceeds size limit".to_owned());
        }
        let preview = ReportPreview {
            report_id: report.report_id,
            destination: endpoint.url("v1/reports").to_string(),
            payload,
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

#[cfg(test)]
mod tests {
    use super::super::test_server::TestServer;
    use super::*;

    fn prepare(manager: &ReportManager, dll: &[u8]) -> ReportPreview {
        manager
            .prepare_ics_report(
                IcsSignatureMismatch {
                    sha256: hex::encode(Sha256::digest(dll)),
                    reason: IcsMismatchReason::UnrecognizedDll,
                },
                dll,
                "19045.6456".to_owned(),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn only_consented_ics_reports_are_uploaded_and_receipts_prevent_resending() {
        let server = TestServer::new().await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        let dll = b"MZ\0\xffexample DLL bytes";
        let preview = prepare(&manager, dll);

        assert!(
            manager
                .send(preview.report_id, false)
                .await
                .unwrap_err()
                .contains("consent")
        );
        assert!(server.requests().is_empty());
        server.reply(
            201,
            serde_json::to_vec(&ReportReceipt {
                report_id: preview.report_id,
            })
            .unwrap(),
        );

        for _ in 0..2 {
            assert_eq!(
                manager
                    .send(preview.report_id, true)
                    .await
                    .unwrap()
                    .report_id,
                preview.report_id
            );
        }
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/reports");
        assert_eq!(requests[0].body, preview.payload.as_bytes());
        let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(payload.as_object().unwrap().len(), 3);
        let report: IcsReport = serde_json::from_value(payload).unwrap();
        assert_eq!(report.schema_version, 2);
        assert_eq!(report.report_id, preview.report_id);
        assert_eq!(report.windows_ics.dll_name, ICS_CLIENT_DLL);
        assert_eq!(
            report.windows_ics.reason,
            IcsMismatchReason::UnrecognizedDll
        );
        assert_eq!(report.windows_ics.windows_build, "19045.6456");
        assert_eq!(
            report.windows_ics.dll_sha256,
            hex::encode(Sha256::digest(dll))
        );
        assert_eq!(STANDARD.decode(report.windows_ics.dll_base64).unwrap(), dll);
    }

    #[test]
    fn changed_or_oversized_dll_cannot_be_queued_for_upload() {
        let manager = ReportManager::new(Ok(Some(Endpoint::parse("http://127.0.0.1").unwrap())));
        for (dll, hash_matches, expected) in [
            (vec![0; 32], false, "system DLL changed"),
            (vec![0; MAX_REPORT_BYTES / 4 * 3 + 1], false, "size limit"),
            (vec![0; MAX_REPORT_BYTES / 4 * 3], true, "size limit"),
        ] {
            let sha256 = if hash_matches {
                hex::encode(Sha256::digest(&dll))
            } else {
                "a".repeat(64)
            };
            let result = manager.prepare_ics_report(
                IcsSignatureMismatch {
                    sha256,
                    reason: IcsMismatchReason::UnrecognizedDll,
                },
                dll.as_slice(),
                "19045".to_owned(),
            );
            assert!(result.err().unwrap().contains(expected));
        }
        assert!(manager.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mismatched_receipt_is_not_shown_to_the_user_as_success() {
        let server = TestServer::new().await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        let preview = prepare(&manager, b"MZ example");
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
    async fn missing_or_discarded_reports_cannot_be_sent() {
        let server = TestServer::new().await;
        let manager = ReportManager::new(Ok(Some(server.endpoint.clone())));
        let first = prepare(&manager, b"MZ example");
        let second = prepare(&manager, b"MZ example");
        assert_ne!(first.report_id, second.report_id);
        for id in [first.report_id, second.report_id] {
            assert_eq!(id.get_version(), Some(uuid::Version::Random));
            assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        }
        manager.discard(first.report_id);
        for id in [first.report_id, Uuid::new_v4()] {
            assert!(
                manager
                    .send(id, true)
                    .await
                    .unwrap_err()
                    .contains("expired")
            );
        }
        assert!(server.requests().is_empty());
    }
}
