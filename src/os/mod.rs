pub mod conflicts;
pub mod hotspot;

pub(crate) fn app_config_dir() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    let directory = if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else {
        #[cfg(target_os = "linux")]
        let path = PathBuf::from(std::env::var_os("HOME")?).join(".config");
        #[cfg(windows)]
        let path = PathBuf::from(std::env::var_os("APPDATA")?);
        path
    };
    Some(directory.join("vrghotspot"))
}
