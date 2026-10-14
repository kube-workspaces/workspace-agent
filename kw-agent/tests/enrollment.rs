use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const UID: &str = "00000000-0000-4000-8000-000000000001";
const GENERATION: &str = "opaque-generation:v2";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Enrollment(PathBuf);
impl Enrollment {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "kw-enrollment-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let token = kw_core::EnrollmentToken {
            token: "one-use-test-token".into(),
            workspace_uid: UID.into(),
            workspace_generation: GENERATION.into(),
            expires_at: kw_core::now_secs() + 300,
        };
        std::fs::write(
            dir.join("enrollment-token.json"),
            serde_json::to_vec(&token).unwrap(),
        )
        .unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_kw-agent"))
            .args([
                "daemon",
                "--workspace-uid",
                UID,
                "--workspace-generation",
                GENERATION,
                "--beats",
                "1",
                "--data-dir",
            ])
            .arg(&dir)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        Self(dir)
    }
    fn command(&self, verb: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kw-agent"));
        command.args([verb, "--data-dir"]).arg(&self.0);
        command
    }
}
impl Drop for Enrollment {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn enrolled_desktop_attaches_without_duplicated_identity_flags() {
    let enrolled = Enrollment::new();
    let public = std::fs::read(enrolled.0.join("public/binding.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&public).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 2);
    assert_eq!(value["workspaceUid"], UID);
    let mut server = enrolled
        .command("serve")
        .args(["--max-sessions", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(server.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("listening ")
        .expect("server listening");
    let result = kw_transport::client::run(address, UID, GENERATION);
    if result.is_err() {
        let _ = server.kill();
    }
    assert!(result.unwrap().admitted);
    assert!(server.wait().unwrap().success());
}

#[test]
fn stale_launcher_flags_fail_before_opening_the_display_or_listener() {
    let enrolled = Enrollment::new();
    for (flag, wrong, message) in [
        (
            "--workspace-uid",
            "00000000-0000-4000-8000-000000000002",
            "UID mismatch",
        ),
        (
            "--workspace-generation",
            "mistyped-generation",
            "generation mismatch",
        ),
    ] {
        let result = enrolled
            .command("serve")
            .args([flag, wrong, "--capture-video"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains(message));
        assert!(result.stdout.is_empty());
        let check = enrolled
            .command("identity-check")
            .args([flag, wrong])
            .output()
            .unwrap();
        assert!(!check.status.success());
        assert!(String::from_utf8_lossy(&check.stderr).contains(message));
    }
    let checked = enrolled.command("identity-check").output().unwrap();
    assert!(checked.status.success());
    let json: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(
        json.as_object().unwrap().len(),
        3,
        "diagnostics must never print the private key"
    );
    assert_eq!(json["publicBindingPresent"], true);
}
