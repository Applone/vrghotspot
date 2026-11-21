#[path = "diagnostic_options.rs"]
pub(crate) mod options;
#[cfg(all(windows, target_arch = "x86_64"))]
use crate::native;

use crate::pe::Image;
use anyhow::{Context, Result};
use options::Options;

pub fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let Some(options) = Options::parse(std::env::args_os().skip(1))? else {
        println!("{}", options::HELP);
        return Ok(());
    };
    if options.self_test || options.hotspot_tun {
        return runtime(&options, None);
    }
    let path = match &options.dll_path {
        Some(path) => path.clone(),
        None => system_dll()?,
    };
    let mut image = Image::read(&path)?;
    println!("DLL: {}\nSHA-256: {}", path.display(), image.hash);
    let resolved = image.scan()?;
    println!(
        "{}",
        if image.verified() {
            "Inspected reference build."
        } else {
            "Unverified Windows build: matches are candidates."
        }
    );
    anyhow::ensure!(
        resolved,
        "Missing/ambiguous signatures. No native code was loaded or called."
    );
    if options.scan_only {
        println!("Offline scan complete. No DLL code was loaded or called.");
        return Ok(());
    }
    image.require_verified()?;
    runtime(&options, Some((&path, &image)))
}

fn system_dll() -> Result<std::path::PathBuf> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        Ok(native::system_directory()?.join("hnetcfgclient.dll"))
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        anyhow::bail!("Specify --dll-path for an extracted DLL and use --scan-only.")
    }
}

fn runtime(options: &Options, image: Option<(&std::path::Path, &Image)>) -> Result<()> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        native::run(options, image).context("Windows operation failed")
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (options, image);
        Err(anyhow::anyhow!("Runtime calls require x86-64 Windows."))
            .context("Only offline scanning is available on this platform")
    }
}
