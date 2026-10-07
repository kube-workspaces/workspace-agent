//! Guest identity and clone-only enrollment.
//!
//! The image ships binaries and platform trust only — never credentials.
//! At first boot the clone consumes a one-use, time-bounded,
//! UID+generation-bound enrollment token, generates its own key, and stores
//! the identity in machine-protected storage. Ordinary restarts reuse it;
//! Reset/deletion revokes it (the token is already gone).
//!
//! v0.1 storage note: the identity file lives in the platform data dir with
//! owner-only permissions set by the installer. DPAPI/ACL hardening and key
//! rotation are explicit follow-ups, not claimed here.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Enrollment token minted per clone at provisioning time.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentToken {
    pub token: String,
    pub workspace_uid: String,
    pub workspace_generation: String,
    /// Unix seconds. The token is single-use before this time.
    pub expires_at: u64,
}

/// Stable guest identity. The key is 32 OS-random bytes, hex-encoded.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub agent_key_hex: String,
    pub workspace_uid: String,
    pub workspace_generation: String,
    pub enrolled_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollError {
    /// Token is empty, already consumed (file gone), or malformed.
    Invalid,
    /// Token expired relative to `now_secs`.
    Expired,
    /// Token bound to a different workspace UID or generation.
    Binding,
    /// Storage read/write failure (carries no secret material).
    Storage(String),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::Invalid => write!(f, "invalid or already-consumed token"),
            EnrollError::Expired => write!(f, "enrollment token expired"),
            EnrollError::Binding => write!(f, "token bound to a different workspace"),
            EnrollError::Storage(what) => write!(f, "identity storage: {what}"),
        }
    }
}

impl std::error::Error for EnrollError {}

fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.json")
}

fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join("enrollment-token.json")
}

/// Unix seconds from the system clock.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Load the stored identity, if enrollment already happened.
pub fn load(data_dir: &Path) -> Result<Option<Identity>, EnrollError> {
    let path = identity_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| EnrollError::Storage("identity.json malformed".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(EnrollError::Storage(format!("read: {error}"))),
    }
}

/// Validate a token against the expected binding and clock.
pub fn check_token(
    token: &EnrollmentToken,
    workspace_uid: &str,
    workspace_generation: &str,
    now_secs: u64,
) -> Result<(), EnrollError> {
    if token.token.trim().is_empty() {
        return Err(EnrollError::Invalid);
    }
    if token.expires_at <= now_secs {
        return Err(EnrollError::Expired);
    }
    if token.workspace_uid != workspace_uid || token.workspace_generation != workspace_generation {
        return Err(EnrollError::Binding);
    }
    Ok(())
}

fn generate_key_hex() -> Result<String, EnrollError> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| EnrollError::Storage(format!("rng: {e}")))?;
    Ok(key.iter().map(|b| format!("{b:02x}")).collect())
}

/// Enroll once: validate the staged token, generate the identity key, store
/// the identity, and delete the token so it cannot be replayed.
///
/// If an identity already exists, it is returned unchanged (ordinary restart
/// preserves identity) and the token file — if any — is left alone.
pub fn enroll(
    data_dir: &Path,
    workspace_uid: &str,
    workspace_generation: &str,
    now_secs: u64,
) -> Result<Identity, EnrollError> {
    if let Some(identity) = load(data_dir)? {
        return Ok(identity);
    }
    let text = std::fs::read_to_string(token_path(data_dir)).map_err(|_| EnrollError::Invalid)?;
    // Tolerate a UTF-8 BOM (Windows PowerShell 5.1 `Set-Content -Encoding
    // UTF8` emits one). The installer writes BOM-less UTF-8; this keeps
    // enrollment robust against hand-staged tokens too.
    let token: EnrollmentToken =
        serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
            .map_err(|_| EnrollError::Invalid)?;
    check_token(&token, workspace_uid, workspace_generation, now_secs)?;
    let identity = Identity {
        agent_key_hex: generate_key_hex()?,
        workspace_uid: token.workspace_uid.clone(),
        workspace_generation: token.workspace_generation.clone(),
        enrolled_at: now_secs,
    };
    std::fs::create_dir_all(data_dir).map_err(|e| EnrollError::Storage(format!("mkdir: {e}")))?;
    // Owner-only permissions on creation (Unix; Windows ACLs are set by the
    // installer on the data dir — see packaging/windows/install.ps1).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(identity_path(data_dir))
            .map_err(|e| EnrollError::Storage(format!("create: {e}")))?;
        serde_json::to_writer_pretty(&file, &identity)
            .map_err(|e| EnrollError::Storage(format!("write: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        let text = serde_json::to_string_pretty(&identity)
            .map_err(|e| EnrollError::Storage(format!("encode: {e}")))?;
        std::fs::write(identity_path(data_dir), text)
            .map_err(|e| EnrollError::Storage(format!("write: {e}")))?;
    }
    // Consume the token: a stolen copy must not enroll a second identity.
    // A failed delete after a successful store keeps the valid identity and
    // reports storage trouble without rolling back.
    if let Err(error) = std::fs::remove_file(token_path(data_dir)) {
        return Err(EnrollError::Storage(format!(
            "token consumed but not deleted: {error}"
        )));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> EnrollmentToken {
        EnrollmentToken {
            token: "one-use-secret".into(),
            workspace_uid: "ws-1".into(),
            workspace_generation: "gen-1".into(),
            expires_at: 2000,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kw-identity-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn rejects_empty_expired_and_foreign_tokens() {
        let mut bad = token();
        bad.token = "  ".into();
        assert_eq!(
            check_token(&bad, "ws-1", "gen-1", 1000),
            Err(EnrollError::Invalid)
        );
        assert_eq!(
            check_token(&token(), "ws-1", "gen-1", 2000),
            Err(EnrollError::Expired)
        );
        assert_eq!(
            check_token(&token(), "ws-2", "gen-1", 1000),
            Err(EnrollError::Binding)
        );
        assert_eq!(
            check_token(&token(), "ws-1", "gen-9", 1000),
            Err(EnrollError::Binding)
        );
        assert!(check_token(&token(), "ws-1", "gen-1", 1000).is_ok());
    }

    #[test]
    fn enroll_consumes_token_and_reuses_identity() {
        let dir = scratch("consume");
        assert_eq!(load(&dir).expect("load"), None);
        std::fs::write(
            token_path(&dir),
            serde_json::to_string(&token()).expect("token json"),
        )
        .expect("stage token");
        let first = enroll(&dir, "ws-1", "gen-1", 1000).expect("enrolls");
        assert_eq!(first.agent_key_hex.len(), 64);
        assert!(!token_path(&dir).exists(), "token consumed");
        let second = enroll(&dir, "ws-1", "gen-1", 1500).expect("reuses");
        assert_eq!(
            first.agent_key_hex, second.agent_key_hex,
            "restart preserves identity"
        );
        assert_ne!(first.agent_key_hex, "00".repeat(32), "key is random");
    }

    #[test]
    fn enroll_tolerates_utf8_bom() {
        // Windows PowerShell 5.1 `Set-Content -Encoding UTF8` emits a BOM.
        let dir = scratch("bom");
        let mut text = String::from("\u{feff}");
        text.push_str(&serde_json::to_string(&token()).expect("token json"));
        std::fs::write(token_path(&dir), text).expect("stage token");
        let identity = enroll(&dir, "ws-1", "gen-1", 1000).expect("enrolls despite BOM");
        assert_eq!(identity.agent_key_hex.len(), 64);
    }

    #[test]
    fn enroll_without_token_is_invalid() {
        let dir = scratch("missing");
        assert_eq!(
            enroll(&dir, "ws-1", "gen-1", 1000),
            Err(EnrollError::Invalid)
        );
    }

    #[test]
    fn enroll_rejects_foreign_binding() {
        let dir = scratch("binding");
        std::fs::write(
            token_path(&dir),
            serde_json::to_string(&token()).expect("token json"),
        )
        .expect("stage token");
        assert_eq!(
            enroll(&dir, "other-ws", "gen-1", 1000),
            Err(EnrollError::Binding)
        );
        // Failed enrollment must not consume the token.
        assert!(token_path(&dir).exists());
    }
}
