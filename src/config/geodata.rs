use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tracing::{info, warn};

pub const DEFAULT_GEOIP_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat";
pub const DEFAULT_GEOSITE_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat";

// Mihomo resolves the v2ray-format geodata files by these exact names in the
// home dir (`GeoIP()` / `GeoSite()`), used when `geodata-mode: true`.
const GEOIP_FILE: &str = "GeoIP.dat";
const GEOSITE_FILE: &str = "GeoSite.dat";
const MIN_DAT_SIZE_BYTES: u64 = 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoDataSettings {
    pub asset_dir: Option<String>,
    pub geoip_url: Option<String>,
    pub geosite_url: Option<String>,
}

impl Default for GeoDataSettings {
    fn default() -> Self {
        Self {
            asset_dir: std::env::var("VRG_CORE_ASSET_DIR")
                .or_else(|_| std::env::var("VRG_XRAY_ASSET_DIR"))
                .ok(),
            geoip_url: std::env::var("VRG_GEOIP_URL").ok(),
            geosite_url: std::env::var("VRG_GEOSITE_URL").ok(),
        }
    }
}

impl GeoDataSettings {
    pub fn with_resolved_defaults(&self) -> Self {
        Self {
            asset_dir: Some(self.asset_dir().to_string_lossy().into_owned()),
            geoip_url: Some(self.geoip_url().to_owned()),
            geosite_url: Some(self.geosite_url().to_owned()),
        }
    }

    pub fn asset_dir(&self) -> PathBuf {
        self.asset_dir
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_asset_dir)
    }

    pub fn geoip_url(&self) -> &str {
        self.geoip_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(DEFAULT_GEOIP_URL)
    }

    pub fn geosite_url(&self) -> &str {
        self.geosite_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(DEFAULT_GEOSITE_URL)
    }

    pub fn describe_for_logs(&self) -> String {
        format!(
            "core_asset_dir={}, geoip_url_configured={}, geosite_url_configured={}",
            self.asset_dir()
                .to_string_lossy()
                .replace(['\n', '\r'], " "),
            self.geoip_url.is_some(),
            self.geosite_url.is_some()
        )
    }
}

pub async fn ensure_geo_data(settings: &GeoDataSettings) -> Result<PathBuf, GeoDataError> {
    let asset_dir = settings.asset_dir();
    fs::create_dir_all(&asset_dir)?;

    let geoip_path = asset_dir.join(GEOIP_FILE);
    let geosite_path = asset_dir.join(GEOSITE_FILE);

    let geoip_ok = valid_dat_file(&geoip_path);
    let geosite_ok = valid_dat_file(&geosite_path);

    if geoip_ok && geosite_ok {
        info!(asset_dir = %asset_dir.display(), "Mihomo geo data is present");
        return Ok(asset_dir);
    }

    warn!(
        geoip_present = geoip_ok,
        geosite_present = geosite_ok,
        asset_dir = %asset_dir.display(),
        "Mihomo geo data is missing or invalid, downloading"
    );
    update_geo_data(settings).await
}

pub async fn update_geo_data(settings: &GeoDataSettings) -> Result<PathBuf, GeoDataError> {
    let asset_dir = settings.asset_dir();
    fs::create_dir_all(&asset_dir)?;

    let client = reqwest::Client::builder()
        .user_agent(format!(
            "{}/{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(DOWNLOAD_TIMEOUT)
        .build()?;

    download_dat(&client, settings.geoip_url(), &asset_dir.join(GEOIP_FILE)).await?;
    download_dat(
        &client,
        settings.geosite_url(),
        &asset_dir.join(GEOSITE_FILE),
    )
    .await?;

    info!(asset_dir = %asset_dir.display(), "Mihomo geo data updated");
    Ok(asset_dir)
}

async fn download_dat(
    client: &reqwest::Client,
    url: &str,
    target: &Path,
) -> Result<(), GeoDataError> {
    let parsed = Url::parse(url).map_err(|source| GeoDataError::InvalidUrl {
        url: url.to_owned(),
        source,
    })?;

    let response = client.get(parsed).send().await?.error_for_status()?;
    let bytes = response.bytes().await?;
    if bytes.len() < MIN_DAT_SIZE_BYTES as usize {
        return Err(GeoDataError::DownloadedFileTooSmall {
            file: target.display().to_string(),
            bytes: bytes.len(),
        });
    }

    let tmp = target.with_extension("dat.tmp");
    let mut file = fs::File::create(&tmp)?;
    file.write_all(&bytes)?;
    file.flush()?;
    drop(file);

    if fs::rename(&tmp, target).is_err() {
        fs::copy(&tmp, target)?;
        let _ = fs::remove_file(&tmp);
    }

    Ok(())
}

fn valid_dat_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.len() >= MIN_DAT_SIZE_BYTES)
        .unwrap_or(false)
}

fn default_asset_dir() -> PathBuf {
    if let Some(xdg_data_home) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg_data_home)
            .join("vrghotspot")
            .join("core-assets");
    }

    #[cfg(windows)]
    if let Some(data_home) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(data_home)
            .join("vrghotspot")
            .join("core-assets");
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("vrghotspot")
            .join("core-assets");
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("core-assets")
}

#[derive(Debug, Error)]
pub enum GeoDataError {
    #[error("invalid geo data URL `{url}`: {source}")]
    InvalidUrl {
        url: String,
        source: url::ParseError,
    },
    #[error("failed to download geo data: {0}")]
    Download(#[from] reqwest::Error),
    #[error("failed to write geo data file: {0}")]
    Io(#[from] std::io::Error),
    #[error("downloaded geo data file `{file}` is too small ({bytes} bytes)")]
    DownloadedFileTooSmall { file: String, bytes: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_defaults_are_visible_to_callers() {
        let settings = GeoDataSettings {
            asset_dir: None,
            geoip_url: None,
            geosite_url: None,
        };

        let resolved = settings.with_resolved_defaults();

        assert!(
            resolved
                .asset_dir
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(resolved.geoip_url.as_deref(), Some(DEFAULT_GEOIP_URL));
        assert_eq!(resolved.geosite_url.as_deref(), Some(DEFAULT_GEOSITE_URL));
    }
}
