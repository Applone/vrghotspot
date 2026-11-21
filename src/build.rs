use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // The bundled subscription address is compiled in from the environment, so a
    // changed secret has to invalidate the build. The same applies to the
    // telemetry and support endpoints baked into the binary.
    println!("cargo:rerun-if-env-changed=VRG_DEFAULT_SUBSCRIPTION_URL");
    println!("cargo:rerun-if-env-changed=VRG_TELEMETRY_ENDPOINT");
    println!("cargo:rerun-if-env-changed=VRG_SUPPORT_ENDPOINT");
    println!("cargo:rerun-if-changed=src/third_party/core_bridge");
    println!("cargo:rerun-if-changed=src/third_party/mihomo");
    println!("cargo:rerun-if-env-changed=VRG_MIHOMO_VERSION");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CC_x86_64_pc_windows_gnu");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo did not provide target OS");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo did not provide target arch");
    let go_arch = match (target_os.as_str(), target_arch.as_str()) {
        ("linux" | "windows", "x86_64") => "amd64",
        ("linux", "aarch64") => "arm64",
        _ => panic!("unsupported target: {target_arch}-{target_os}"),
    };
    if target_os == "windows" {
        assert_eq!(
            env::var("CARGO_CFG_TARGET_ENV").as_deref(),
            Ok("gnu"),
            "use x86_64-pc-windows-gnu with MinGW GCC for the embedded Go archive"
        );
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bridge_dir = manifest_dir.join("src/third_party/core_bridge");
    let mihomo_dir = manifest_dir.join("src/third_party/mihomo");
    if !mihomo_dir.join("go.mod").exists() {
        panic!(
            "vendored Mihomo source is missing from {}",
            mihomo_dir.display()
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let archive = out_dir.join("libvrg_core_bridge.a");
    let mversion = mihomo_version(&mihomo_dir);
    println!("cargo:rustc-env=VRG_MIHOMO_VERSION_BUILT={mversion}");
    let ldflags = format!("-X \"github.com/metacubex/mihomo/constant.Version={mversion}\"");

    let mut go = Command::new("go");
    if target_os == "windows" {
        let default_cc = if cfg!(windows) {
            "gcc"
        } else {
            "x86_64-w64-mingw32-gcc"
        };
        let cc = env::var_os("CC_x86_64_pc_windows_gnu").unwrap_or_else(|| default_cc.into());
        go.env("CC", cc);
    }
    let output = go
        .args([
            "build",
            "-mod=readonly",
            "-buildmode=c-archive",
            "-buildvcs=false",
            "-ldflags",
            &ldflags,
            "-o",
        ])
        .arg(&archive)
        .current_dir(&bridge_dir)
        .env("CGO_ENABLED", "1")
        .env("GOOS", &target_os)
        .env("GOARCH", go_arch)
        .output()
        .expect("failed to run `go build`; install Go and ensure it is on PATH");
    if !output.status.success() {
        panic!(
            "failed to compile embedded Mihomo bridge\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=vrg_core_bridge");
    let system_libraries = if target_os == "windows" {
        ["ntdll", "ws2_32", "winmm"]
    } else {
        ["pthread", "dl", "m"]
    };
    for library in system_libraries {
        println!("cargo:rustc-link-lib={library}");
    }
    tauri_build::build();
}

fn mihomo_version(mihomo_dir: &Path) -> String {
    if let Ok(version) = env::var("VRG_MIHOMO_VERSION")
        && !version.trim().is_empty()
    {
        return version.trim().to_owned();
    }

    // A vendored source tree would otherwise report the parent application's tag.
    if !mihomo_dir.join(".git").exists() {
        return "v1.19.28".to_owned();
    }
    Command::new("git")
        .args(["describe", "--tags", "--always"])
        .current_dir(mihomo_dir)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "v1.19.28".to_owned())
}
