use std::process::Command;

#[test]
fn independent_binary_has_own_version_and_rejects_override_arguments() {
    let exe = env!("CARGO_BIN_EXE_kw-agent-updater");
    let version = Command::new(exe).arg("--version").output().unwrap();
    assert!(version.status.success());
    let text = String::from_utf8(version.stdout).unwrap();
    assert!(text.starts_with("kw-agent-updater "));
    assert!(text.ends_with(" (protocol 1)\n"));
    let override_attempt = Command::new(exe)
        .args([
            "service",
            "--root",
            r"C:\tenant",
            "--authority",
            "local.json",
        ])
        .output()
        .unwrap();
    assert!(!override_attempt.status.success());
}
