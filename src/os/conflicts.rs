use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::fs;

use sysinfo::{ProcessesToUpdate, System};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ConflictScanner {
    process_names: Vec<String>,
}

impl ConflictScanner {
    pub fn with_process_names(process_names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            process_names: process_names.into_iter().map(Into::into).collect(),
        }
    }

    pub async fn scan(&self) -> Result<ConflictReport, ConflictError> {
        let process_names = self.process_names.clone();
        tokio::task::spawn_blocking(move || {
            Ok(ConflictReport {
                tun_interfaces: scan_tun_interfaces()?,
                system_proxy: scan_system_proxy(),
                conflicting_processes: scan_processes(&process_names)?,
            })
        })
        .await?
    }

    fn default_names() -> Vec<String> {
        [
            "zapret",
            "v2ray",
            "xray",
            "clash",
            "clash-meta",
            "mihomo",
            "sing-box",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
}

impl Default for ConflictScanner {
    fn default() -> Self {
        Self {
            process_names: Self::default_names(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConflictReport {
    pub tun_interfaces: Vec<String>,
    pub system_proxy: Option<SystemProxy>,
    pub conflicting_processes: Vec<String>,
}

impl ConflictReport {
    pub fn has_conflicts(&self) -> bool {
        !self.tun_interfaces.is_empty()
            || self.system_proxy.is_some()
            || !self.conflicting_processes.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProxy {
    pub server: String,
    pub bypass: Option<String>,
}

fn scan_processes(names: &[String]) -> Result<Vec<String>, ConflictError> {
    let mut system = System::new()?;
    system.refresh_processes(ProcessesToUpdate::All, true);
    let wanted: Vec<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();

    Ok(system
        .processes()
        .values()
        .filter_map(|process| {
            let process_name = process.name().to_string_lossy().to_ascii_lowercase();
            #[cfg(windows)]
            let process_name = process_name.strip_suffix(".exe").unwrap_or(&process_name);
            #[cfg(target_os = "linux")]
            let process_name = process_name.as_str();
            wanted
                .iter()
                .any(|candidate| candidate == process_name)
                .then(|| process.name().to_string_lossy().into_owned())
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn scan_tun_interfaces() -> Result<Vec<String>, ConflictError> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        let tun_flags = entry.path().join("tun_flags");
        if tun_flags.exists()
            || lower.starts_with("tun")
            || lower.starts_with("wg")
            || lower.contains("mihomo")
        {
            interfaces.push(name);
        }
    }
    interfaces.sort();
    Ok(interfaces)
}

#[cfg(windows)]
fn scan_tun_interfaces() -> Result<Vec<String>, ConflictError> {
    let mut interfaces = crate::native::network::adapters()?
        .into_iter()
        .filter(|adapter| adapter.up && adapter.is_tun())
        .map(|adapter| adapter.name)
        .collect::<Vec<_>>();
    interfaces.sort();
    Ok(interfaces)
}

fn scan_system_proxy() -> Option<SystemProxy> {
    let server = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))?;
    let bypass = ["NO_PROXY", "no_proxy"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
    Some(SystemProxy { server, bypass })
}

#[derive(Debug, Error)]
pub enum ConflictError {
    #[error("failed to inspect running processes: {0}")]
    Processes(#[from] sysinfo::Error),
    #[cfg(windows)]
    #[error("failed to inspect Windows network interfaces: {0}")]
    Windows(#[from] anyhow::Error),
    #[cfg(target_os = "linux")]
    #[error("failed to inspect Linux network interfaces: {0}")]
    Io(#[from] std::io::Error),
    #[error("conflict scan task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn process_scan_matches_current_process_case_insensitively() {
        #[cfg(target_os = "linux")]
        let name = fs::read_to_string("/proc/self/comm")
            .expect("read current process name")
            .trim_end()
            .to_owned();
        #[cfg(windows)]
        let name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let query = name.to_ascii_uppercase();
        #[cfg(windows)]
        let query = query.trim_end_matches(".EXE").to_owned();
        let matches = scan_processes(&[query]).expect("scan processes");
        assert!(matches.contains(&name));
        assert!(scan_processes(&[]).expect("scan without names").is_empty());
    }

    #[test]
    fn process_inspection_error_preserves_cause() {
        let error = ConflictError::from(sysinfo::Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "process access denied",
        )));
        assert_eq!(
            error.to_string(),
            "failed to inspect running processes: process access denied"
        );
        assert_eq!(error.source().unwrap().to_string(), "process access denied");
    }
}
