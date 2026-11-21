use crate::os::hotspot::IcsMismatchReason;
use serde::{Deserialize, Serialize};
use uuid::{Uuid, Variant, Version};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_LOG_ENTRIES: usize = 2_000;
pub const MAX_MESSAGE_BYTES: usize = 8_192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub installation_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportReceipt {
    pub report_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupportReport {
    pub schema_version: u32,
    pub report_id: Uuid,
    pub created_at: u64,
    pub error: String,
    pub context: ReportContext,
    pub logs: Vec<DiagnosticLog>,
    pub logs_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) windows_ics: Option<WindowsIcsDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowsIcsDiagnostic {
    pub dll_name: String,
    pub dll_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dll_base64: Option<String>,
    pub reason: IcsMismatchReason,
    pub windows_build: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportContext {
    pub app_version: String,
    pub core_version: String,
    pub os: String,
    pub arch: String,
    pub uptime_seconds: u64,
    pub hotspot_status: String,
    pub sharing_enabled: bool,
    pub telemetry_enabled: bool,
    pub profile_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticLog {
    pub timestamp: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

pub fn is_random_id(id: &Uuid) -> bool {
    id.get_version() == Some(Version::Random) && id.get_variant() == Variant::RFC4122
}

impl SupportReport {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != SCHEMA_VERSION || !is_random_id(&self.report_id) {
            return Err("unsupported report schema or invalid report ID");
        }
        if self.error.is_empty() || self.error.len() > MAX_MESSAGE_BYTES {
            return Err("invalid error length");
        }
        let context = &self.context;
        if [
            &context.app_version,
            &context.core_version,
            &context.os,
            &context.arch,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 128)
            || !matches!(
                context.hotspot_status.as_str(),
                "Stopped" | "Starting" | "Running" | "Stopping"
            )
        {
            return Err("invalid report context");
        }
        if self.logs.len() > MAX_LOG_ENTRIES
            || self.logs.iter().any(|entry| {
                entry.message.len() > MAX_MESSAGE_BYTES
                    || entry.target.len() > 256
                    || !matches!(
                        entry.level.as_str(),
                        "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR"
                    )
            })
        {
            return Err("invalid diagnostic logs");
        }
        let encoded = serde_json::to_vec(self).map_err(|_| "invalid report encoding")?;
        if encoded.len() > MAX_REPORT_BYTES {
            return Err("report exceeds size limit");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_random_ids() {
        assert!(is_random_id(&Uuid::new_v4()));
        assert!(!is_random_id(&Uuid::nil()));
        assert!(!is_random_id(&Uuid::max()));
    }

    #[test]
    fn rejects_unexpected_installation_attributes() {
        let payload = serde_json::json!({
            "installation_id": Uuid::new_v4(),
            "hostname": "not-allowed"
        });
        assert!(serde_json::from_value::<Installation>(payload).is_err());
    }
}
