use std::process::Command;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vrghotspot-diagnostics"))
        .args(arguments)
        .output()
        .expect("run CLI")
}

#[test]
fn help_exits_successfully_without_inspecting_windows() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for mode in ["--scan-only", "--self-test", "--apply", "--hotspot-tun"] {
        assert!(help.contains(mode));
    }
}

#[test]
fn bad_options_fail_before_accessing_the_system() {
    let output = run(&["--self-test", "--apply"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot be combined")
    );
}

#[test]
fn extracted_non_pe_file_fails_without_native_calls() {
    let path = std::env::temp_dir().join(format!("vrghotspot-test-{}.dll", std::process::id()));
    std::fs::write(&path, b"not a PE DLL").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vrghotspot-diagnostics"))
        .args(["--scan-only", "--dll-path"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Missing DOS header")
    );
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
#[test]
fn runtime_modes_report_the_platform_requirement() {
    for mode in ["--self-test", "--hotspot-tun"] {
        let output = run(&[mode]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("x86-64 Windows")
        );
    }
}
