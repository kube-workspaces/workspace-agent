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
    crate::binding::Binding {
        workspace_uid: options.workspace_uid.clone(),
        workspace_generation: options.workspace_generation.clone(),
    }
    .validate()?;
    let identity = enroll(
        &options.data_dir,
        &options.workspace_uid,
        &options.workspace_generation,
        now_secs(),
    )
    .map_err(|e| format!("enrollment failed: {e}"))?;
    let binding = crate::binding::Binding {
        workspace_uid: identity.workspace_uid.clone(),
        workspace_generation: identity.workspace_generation.clone(),
    };
    binding.check(
        Some(&options.workspace_uid),
        Some(&options.workspace_generation),
    )?;
    crate::binding::publish(&options.data_dir, &binding)?;
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
            "agentVersion": kw_protocol::AGENT_VERSION,
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

/// SCM starts even on an unconfigured MSI installation. Enrollment is staged
/// separately by provisioning, never embedded in the service command line.
#[cfg(windows)]
pub fn initialize(data_dir: &std::path::Path) -> Result<Option<kw_core::Identity>, String> {
    let identity = match kw_core::load(data_dir).map_err(|e| e.to_string())? {
        Some(identity) => enroll(
            data_dir,
            &identity.workspace_uid,
            &identity.workspace_generation,
            now_secs(),
        )
        .map_err(|e| e.to_string())?,
        None => {
            let text = match std::fs::read_to_string(data_dir.join("enrollment-token.json")) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("enrollment token read: {error}")),
            };
            let token: kw_core::EnrollmentToken =
                serde_json::from_str(text.trim_start_matches('\u{feff}'))
                    .map_err(|_| "enrollment token malformed")?;
            crate::binding::Binding {
                workspace_uid: token.workspace_uid.clone(),
                workspace_generation: token.workspace_generation.clone(),
            }
            .validate()?;
            enroll(
                data_dir,
                &token.workspace_uid,
                &token.workspace_generation,
                now_secs(),
            )
            .map_err(|e| e.to_string())?
        }
    };
    crate::binding::publish(
        data_dir,
        &crate::binding::Binding {
            workspace_uid: identity.workspace_uid.clone(),
            workspace_generation: identity.workspace_generation.clone(),
        },
    )?;
    Ok(Some(identity))
}

#[cfg(windows)]
pub fn write_heartbeat(
    dir: &std::path::Path,
    identity: &kw_core::Identity,
    beat: u64,
) -> Result<(), String> {
    let status = serde_json::json!({
        "agentVersion": kw_protocol::AGENT_VERSION, "workspaceUid": identity.workspace_uid,
        "workspaceGeneration": identity.workspace_generation, "enrolledAt": identity.enrolled_at,
        "beat": beat, "beatAt": now_secs(),
    });
    std::fs::write(dir.join("status.json"), status.to_string()).map_err(|e| e.to_string())
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
