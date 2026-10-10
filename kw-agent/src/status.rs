//! Local daemon status (Layer 4 guest indicator, read-only).
//!
//! Reads the `status.json` heartbeat file the daemon writes into its data
//! dir and reports whether the daemon is alive, which workspace/generation
//! it is bound to, and whether its binary matches this one. Prints no key
//! material: the file never contains any (see `daemon.rs`).
//!
//! Serve-side session state (control epoch, holder, queue depths, last
//! keyframe/resize/IDR) is intentionally out of scope: `serve` runs in a
//! separate process and publishes nothing durable yet. This command answers
//! "is the daemon enrolled and beating", never "is a viewer streaming".

use std::path::Path;

/// Freshness bound: five daemon beat intervals (`daemon.rs` beats every
/// 60 s). Tight enough to catch a dead daemon, loose enough to survive
/// guest scheduling jitter.
pub const DEFAULT_MAX_BEAT_AGE_SECS: u64 = 300;

/// Parsed daemon heartbeat. Field names mirror `daemon.rs` exactly.
#[derive(Debug)]
pub struct Status {
    pub agent_version: String,
    pub workspace_uid: String,
    pub workspace_generation: String,
    pub enrolled_at: u64,
    pub beat: u64,
    pub beat_at: u64,
}

fn get_str(value: &serde_json::Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("status.json: {field} missing or not a string"))
}

fn get_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("status.json: {field} missing or not a u64"))
}

/// Read and shape-check `<data_dir>/status.json`.
pub fn read_status(data_dir: &Path) -> Result<Status, String> {
    let path = data_dir.join("status.json");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("status.json unreadable: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("status.json invalid: {e}"))?;
    Ok(Status {
        agent_version: get_str(&value, "agentVersion")?,
        workspace_uid: get_str(&value, "workspaceUid")?,
        workspace_generation: get_str(&value, "workspaceGeneration")?,
        enrolled_at: get_u64(&value, "enrolledAt")?,
        beat: get_u64(&value, "beat")?,
        beat_at: get_u64(&value, "beatAt")?,
    })
}

/// Checkable verdict over a parsed heartbeat. `beat_age_secs` saturates at
/// zero so a clock-skewed future `beatAt` reads as fresh, not as an
/// underflow.
#[derive(Debug)]
pub struct Summary {
    pub fresh: bool,
    pub beat_age_secs: u64,
    pub version_match: bool,
}

pub fn summarize(
    status: &Status,
    own_version: &str,
    now_secs: u64,
    max_beat_age_secs: u64,
) -> Summary {
    let beat_age_secs = now_secs.saturating_sub(status.beat_at);
    Summary {
        fresh: beat_age_secs <= max_beat_age_secs,
        beat_age_secs,
        version_match: status.agent_version == own_version,
    }
}

#[cfg(test)]
mod tests {
    use super::{read_status, summarize, Status, DEFAULT_MAX_BEAT_AGE_SECS};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn scratch_dir() -> std::path::PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "kw-agent-status-test-{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn write_status(dir: &std::path::Path, body: &str) {
        std::fs::write(dir.join("status.json"), body).expect("fixture");
    }

    fn valid_body(beat_at: u64) -> String {
        serde_json::json!({
            "agentVersion": "v0.1.0-test",
            "workspaceUid": "uid-1",
            "workspaceGeneration": "gen-7",
            "enrolledAt": 1_000,
            "beat": 12,
            "beatAt": beat_at,
        })
        .to_string()
    }

    #[test]
    fn reads_valid_heartbeat() {
        let dir = scratch_dir();
        write_status(&dir, &valid_body(2_000));
        let status = read_status(&dir).expect("valid");
        assert_eq!(status.agent_version, "v0.1.0-test");
        assert_eq!(status.workspace_uid, "uid-1");
        assert_eq!(status.workspace_generation, "gen-7");
        assert_eq!(status.enrolled_at, 1_000);
        assert_eq!(status.beat, 12);
        assert_eq!(status.beat_at, 2_000);
    }

    #[test]
    fn missing_file_is_an_error() {
        let dir = scratch_dir();
        assert!(read_status(&dir).is_err());
    }

    #[test]
    fn invalid_json_is_an_error() {
        let dir = scratch_dir();
        write_status(&dir, "{not json");
        assert!(read_status(&dir).is_err());
    }

    #[test]
    fn missing_field_is_an_error() {
        let dir = scratch_dir();
        write_status(
            &dir,
            r#"{"agentVersion":"v","workspaceUid":"u","workspaceGeneration":"g","enrolledAt":1,"beat":2}"#,
        );
        let err = read_status(&dir).expect_err("beatAt missing");
        assert!(err.contains("beatAt"), "unexpected: {err}");
    }

    #[test]
    fn wrong_type_is_an_error() {
        let dir = scratch_dir();
        write_status(
            &dir,
            r#"{"agentVersion":"v","workspaceUid":"u","workspaceGeneration":"g","enrolledAt":"yesterday","beat":2,"beatAt":3}"#,
        );
        let err = read_status(&dir).expect_err("enrolledAt mistyped");
        assert!(err.contains("enrolledAt"), "unexpected: {err}");
    }

    fn status_at(beat_at: u64) -> Status {
        Status {
            agent_version: "v0.1.0-test".to_owned(),
            workspace_uid: "uid-1".to_owned(),
            workspace_generation: "gen-7".to_owned(),
            enrolled_at: 1_000,
            beat: 12,
            beat_at,
        }
    }

    #[test]
    fn fresh_beat_with_matching_version() {
        let summary = summarize(
            &status_at(2_000),
            "v0.1.0-test",
            2_000 + DEFAULT_MAX_BEAT_AGE_SECS,
            DEFAULT_MAX_BEAT_AGE_SECS,
        );
        assert!(summary.fresh);
        assert_eq!(summary.beat_age_secs, DEFAULT_MAX_BEAT_AGE_SECS);
        assert!(summary.version_match);
    }

    #[test]
    fn old_beat_is_stale() {
        let summary = summarize(
            &status_at(2_000),
            "v0.1.0-test",
            2_000 + DEFAULT_MAX_BEAT_AGE_SECS + 1,
            DEFAULT_MAX_BEAT_AGE_SECS,
        );
        assert!(!summary.fresh);
        assert_eq!(summary.beat_age_secs, DEFAULT_MAX_BEAT_AGE_SECS + 1);
        assert!(summary.version_match);
    }

    #[test]
    fn future_beat_reads_fresh_not_underflow() {
        let summary = summarize(&status_at(9_999), "v0.1.0-test", 2_000, 60);
        assert!(summary.fresh);
        assert_eq!(summary.beat_age_secs, 0);
    }

    #[test]
    fn version_drift_is_reported_not_hidden() {
        let summary = summarize(&status_at(2_000), "v0.2.0", 2_010, 60);
        assert!(summary.fresh);
        assert!(!summary.version_match);
    }
}
