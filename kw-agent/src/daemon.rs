//! Boot-persistent daemon (v0.1): enroll once, then heartbeat.
//!
//! No network, no capture, no input, no mode changes. Each beat rewrites
//! `status.json` in the data dir and prints one log line. The key itself is
//! never printed, logged, or written anywhere except `identity.json`.

use kw_core::{enroll, now_secs};
use std::path::PathBuf;

///Seconds between beats.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

pub struct Options {
    pub data_dir: PathBuf,
    pub workspace_uid: String,
    pub workspace_generation: String,
    pub interval_secs: u64,
    /// Exit after this many beats (0 = run until killed). Exists so the
    /// proof harness can smoke-test the daemon without a service manager.
    pub beats: u64,
}

/// Run until killed (or `beats` reached). Returns the beat count.
pub fn run(options: &Options) -> Result<u64, String> {
    let identity = enroll(
        &options.data_dir,
        &options.workspace_uid,
        &options.workspace_generation,
        now_secs(),
    )
    .map_err(|e| format!("enrollment failed: {e}"))?;
    println!(
        "kw-agent daemon enrolled workspace={} generation={} key_bytes={}",
        identity.workspace_uid,
        identity.workspace_generation,
        identity.agent_key_hex.len() / 2
    );
    let mut beats = 0u64;
    loop {
        beats += 1;
        let status = serde_json::json!({
            "agentVersion": env!("CARGO_PKG_VERSION"),
            "workspaceUid": identity.workspace_uid,
            "workspaceGeneration": identity.workspace_generation,
            "enrolledAt": identity.enrolled_at,
            "beat": beats,
            "beatAt": now_secs(),
        });
        let text = serde_json::to_string(&status).map_err(|e| format!("encode: {e}"))?;
        std::fs::write(options.data_dir.join("status.json"), text)
            .map_err(|e| format!("status write: {e}"))?;
        println!("beat {beats}");
        if options.beats != 0 && beats >= options.beats {
            return Ok(beats);
        }
        std::thread::sleep(std::time::Duration::from_secs(options.interval_secs));
    }
}

/// Default data dir: `%PROGRAMDATA%\workspace-agent` on Windows,
/// `/var/lib/workspace-agent` elsewhere. `KW_DATA_DIR` overrides (tests).
pub fn default_data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KW_DATA_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("PROGRAMDATA").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("workspace-agent")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/lib/workspace-agent")
    }
}
