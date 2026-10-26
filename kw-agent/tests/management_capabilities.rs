use std::process::Command;

#[test]
fn fixed_probe_reports_protocol_without_identity_keys_or_request_files() {
    let output = Command::new(env!("CARGO_BIN_EXE_kw-agent"))
        .args(["management-exec", "--capabilities"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let caps: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(caps["version"], 1);
    assert_eq!(
        caps["script_request_version"],
        if cfg!(any(target_os = "linux", windows)) {
            2
        } else {
            0
        }
    );
    assert_eq!(
        caps["interpreter_policy"],
        if cfg!(target_os = "linux") {
            "linux-shebang-v1"
        } else if cfg!(windows) {
            "windows-powershell-v1"
        } else {
            ""
        }
    );
    assert_eq!(caps.as_object().unwrap().len(), 3);
}
