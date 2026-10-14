//! Public projection of enrollment. Never share identity.json's private key
//! with the interactive desktop user; publish only these two binding fields.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub workspace_uid: String,
    pub workspace_generation: String,
}

impl Binding {
    pub fn validate(&self) -> Result<(), String> {
        let uid = self.workspace_uid.as_bytes();
        if uid.len() != 36
            || !uid.iter().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            return Err("workspace UID must be a canonical UUID (8-4-4-4-12 hex digits)".into());
        }
        // Generation is an opaque provisioning identifier, not necessarily a UUID.
        if self.workspace_generation.is_empty()
            || self.workspace_generation.trim() != self.workspace_generation
            || self.workspace_generation.chars().any(char::is_control)
        {
            return Err("workspace generation must be non-empty, without surrounding whitespace or control characters".into());
        }
        Ok(())
    }

    pub fn check(&self, uid: Option<&str>, generation: Option<&str>) -> Result<(), String> {
        if uid.is_some_and(|value| value != self.workspace_uid) {
            return Err(
                "workspace UID mismatch: supplied value differs from enrolled identity".into(),
            );
        }
        if generation.is_some_and(|value| value != self.workspace_generation) {
            return Err(
                "workspace generation mismatch: supplied value differs from enrolled identity"
                    .into(),
            );
        }
        Ok(())
    }
}

pub fn enrolled(data_dir: &Path) -> Result<Binding, String> {
    let identity = kw_core::load(data_dir)
        .map_err(|error| error.to_string())?
        .ok_or("identity.json missing: enroll the daemon first")?;
    let binding = Binding {
        workspace_uid: identity.workspace_uid,
        workspace_generation: identity.workspace_generation,
    };
    binding.validate()?;
    Ok(binding)
}

pub fn read(data_dir: &Path) -> Result<Option<Binding>, String> {
    let path = data_dir.join("public").join("binding.json");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("public/binding.json unreadable: {error}")),
    };
    let binding: Binding = serde_json::from_str(&text).map_err(|_| {
        "public/binding.json malformed (expected only workspaceUid and workspaceGeneration)"
    })?;
    binding.validate()?;
    Ok(Some(binding))
}

pub fn publish(data_dir: &Path, binding: &Binding) -> Result<(), String> {
    binding.validate()?;
    let dir = data_dir.join("public");
    std::fs::create_dir_all(&dir).map_err(|error| format!("binding directory: {error}"))?;
    let path = dir.join("binding.json");
    let text = serde_json::to_string_pretty(binding).map_err(|error| error.to_string())?;
    // Readers see either the old complete binding or the new complete binding.
    let temp = dir.join("binding.json.tmp");
    std::fs::write(&temp, text).map_err(|error| format!("binding write: {error}"))?;
    std::fs::rename(temp, path).map_err(|error| format!("binding publish: {error}"))
}

/// Explicit bindings remain available for standalone protocol diagnostics.
/// Once enrolled, they cannot override the published identity.
pub fn resolve(
    data_dir: &Path,
    uid: Option<&str>,
    generation: Option<&str>,
) -> Result<Binding, String> {
    if let Some(binding) = read(data_dir)? {
        binding.check(uid, generation)?;
        return Ok(binding);
    }
    match (uid, generation) {
        (Some(uid), Some(generation)) if !uid.is_empty() && !generation.is_empty() => Ok(Binding {
            workspace_uid: uid.into(),
            workspace_generation: generation.into(),
        }),
        _ => Err("public/binding.json missing: start the enrolled daemon and re-run registration, or supply both binding flags for standalone diagnostics".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const UID: &str = "00000000-0000-4000-8000-000000000001";

    fn binding() -> Binding {
        Binding {
            workspace_uid: UID.into(),
            workspace_generation: "opaque-generation:v2".into(),
        }
    }

    #[test]
    fn catches_transcription_errors_without_requiring_uuid_generation() {
        assert!(binding().validate().is_ok());
        let mut bad = binding();
        bad.workspace_uid.push('0');
        assert!(bad.validate().unwrap_err().contains("UID"));
        assert!(binding()
            .check(None, Some("opaque-generation:v3"))
            .unwrap_err()
            .contains("generation mismatch"));
        assert!(binding()
            .check(Some("wrong"), None)
            .unwrap_err()
            .contains("UID mismatch"));
    }

    #[test]
    fn publishes_only_public_fields_and_refuses_overrides() {
        let dir = std::env::temp_dir().join(format!("kw-binding-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = kw_core::Identity {
            agent_key_hex: "private-do-not-share".into(),
            workspace_uid: UID.into(),
            workspace_generation: binding().workspace_generation,
            enrolled_at: 1,
        };
        std::fs::write(
            dir.join("identity.json"),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
        let enrolled = enrolled(&dir).unwrap();
        publish(&dir, &enrolled).unwrap();
        publish(&dir, &enrolled).unwrap(); // also replaces an existing projection
        let text = std::fs::read_to_string(dir.join("public/binding.json")).unwrap();
        assert!(!text.contains("private"));
        assert!(!text.contains("agentKey"));
        assert_eq!(resolve(&dir, None, None).unwrap(), enrolled);
        assert!(resolve(&dir, Some("mistyped"), None).is_err());
        assert!(resolve(&dir, None, Some("mistyped")).is_err());
        std::fs::write(dir.join("public/binding.json"), "{broken").unwrap();
        assert!(resolve(&dir, Some(UID), Some("fallback")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
