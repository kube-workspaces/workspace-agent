//! Publisher-authenticated updater artifacts. No download, listener, process or
//! installation authorization is implemented by this offline contract.

pub mod journal;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;

pub const DOMAIN: &[u8] = b"kw-agent-update-manifest/v1\0";
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const AGENT_UPGRADE_CODE: &str = "f72bb43e-dba8-4dbb-a963-b201e6c0d885";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Untrusted,
    Digest,
    Signature,
    Payload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Msi {
    pub artifact: Artifact,
    pub product_code: String,
    pub upgrade_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Updater {
    pub artifact: Artifact,
    pub protocol_version: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Driver {
    pub artifact: Artifact,
    pub version: String,
    pub signer_sha256: String,
    pub hardware_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub minimum_agent_version: String,
    pub maximum_agent_version: String,
    pub management_min: u16,
    pub management_max: u16,
    pub desktop_min: u16,
    pub desktop_max: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predecessor {
    pub target_id: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub target_id: String,
    pub os: String,
    pub architecture: String,
    pub agent_version: String,
    pub build_sha256: String,
    pub msi: Msi,
    pub updater: Updater,
    pub driver: Option<Driver>,
    pub compatibility: Compatibility,
    pub rollback_predecessors: Vec<Predecessor>,
    pub reboot_policy: String,
}

#[derive(Debug)]
pub struct VerifiedManifest {
    manifest: Manifest,
    digest: String,
}

pub fn digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn key_id(public: &[u8; 32]) -> String {
    digest(public)[..32].to_owned()
}

/// The keyring and expected manifest digest must come from protected operator
/// configuration, never from the body being verified. Sign exact bytes.
pub fn verify(
    raw: &[u8],
    signature: &[u8],
    id: &str,
    expected_digest: &str,
    keys: &HashMap<String, [u8; 32]>,
) -> Result<VerifiedManifest, Error> {
    if raw.is_empty() || raw.len() > MAX_MANIFEST_BYTES || std::str::from_utf8(raw).is_err() {
        return Err(Error::Invalid);
    }
    if keys.is_empty() || keys.len() > 16 || keys.iter().any(|(id, public)| id != &key_id(public)) {
        return Err(Error::Untrusted);
    }
    let public = keys.get(id).ok_or(Error::Untrusted)?;
    if !valid_digest(expected_digest) || digest(raw) != expected_digest {
        return Err(Error::Digest);
    }
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::Untrusted)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + raw.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::Signature)?;
    // Derived struct visitors reject unknown and duplicate fields at every
    // schema level; from_slice also rejects trailing JSON and invalid UTF-8.
    let manifest: Manifest = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
    if !manifest.valid() {
        return Err(Error::Invalid);
    }
    Ok(VerifiedManifest {
        manifest,
        digest: expected_digest.to_owned(),
    })
}

impl VerifiedManifest {
    pub fn sha256(&self) -> &str {
        &self.digest
    }
    pub fn metadata(&self) -> &Manifest {
        &self.manifest
    }

    /// Reads at most the signed size plus one byte, without buffering payloads.
    pub fn verify_artifact(&self, name: &str, reader: &mut impl Read) -> Result<(), Error> {
        let mut artifacts = vec![&self.manifest.msi.artifact, &self.manifest.updater.artifact];
        if let Some(driver) = &self.manifest.driver {
            artifacts.push(&driver.artifact);
        }
        let artifact = artifacts
            .into_iter()
            .find(|a| a.file == name)
            .ok_or(Error::Payload)?;
        let mut limited = reader.take(artifact.size + 1);
        let mut hash = Sha256::new();
        let mut total = 0;
        let mut buffer = [0_u8; 8192];
        loop {
            let size = limited.read(&mut buffer).map_err(|_| Error::Payload)?;
            if size == 0 {
                break;
            }
            total += size as u64;
            hash.update(&buffer[..size]);
        }
        let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if total != artifact.size || actual != artifact.sha256 {
            return Err(Error::Payload);
        }
        Ok(())
    }
}

fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && lower_or_digit(s.as_bytes()[0])
        && s.bytes().all(|b| lower_or_digit(b) || b"._-".contains(&b))
}

fn lower_or_digit(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn valid_guid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

fn version(s: &str, count: usize) -> Option<Vec<u16>> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != count {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for (i, part) in parts.iter().enumerate() {
        let number: u16 = part.parse().ok()?;
        if number.to_string() != *part || (count == 3 && i < 2 && number > 255) {
            return None;
        }
        out.push(number);
    }
    Some(out)
}

impl Artifact {
    fn valid(&self, extension: &str) -> bool {
        if !identifier(&self.file)
            || self.file.ends_with('.')
            || !self.file.ends_with(extension)
            || self.size == 0
            || self.size > MAX_ARTIFACT_BYTES
            || !valid_digest(&self.sha256)
        {
            return false;
        }
        let stem = self.file.split('.').next().unwrap_or_default();
        if ["con", "prn", "aux", "nul"].contains(&stem) {
            return false;
        }
        !(stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && (b'1'..=b'9').contains(&stem.as_bytes()[3]))
    }
}

impl Driver {
    fn valid(&self) -> bool {
        if version(&self.version, 4).is_none()
            || !self.artifact.valid(".zip")
            || !valid_digest(&self.signer_sha256)
            || self.hardware_ids.is_empty()
            || self.hardware_ids.len() > 8
        {
            return false;
        }
        let mut seen = HashSet::new();
        self.hardware_ids.iter().all(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id.contains('\\')
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.&\\-".contains(&b))
                && seen.insert(id.to_ascii_lowercase())
        })
    }
}

impl Manifest {
    fn valid(&self) -> bool {
        let c = &self.compatibility;
        let ordered = match (
            version(&c.minimum_agent_version, 3),
            version(&c.maximum_agent_version, 3),
        ) {
            (Some(a), Some(b)) => a <= b,
            _ => false,
        };
        if self.version != 1
            || !identifier(&self.target_id)
            || self.os != "windows"
            || self.architecture != "amd64"
            || version(&self.agent_version, 3).is_none()
            || !valid_digest(&self.build_sha256)
            || !self.msi.artifact.valid(".msi")
            || !valid_guid(&self.msi.product_code)
            || self.msi.product_code == "00000000-0000-0000-0000-000000000000"
            || self.msi.upgrade_code != AGENT_UPGRADE_CODE
            || self.msi.product_code == self.msi.upgrade_code
            || !self.updater.artifact.valid(".exe")
            || self.updater.protocol_version != 1
            || self.msi.artifact.file == self.updater.artifact.file
            || !ordered
            || c.management_min == 0
            || c.management_max < c.management_min
            || c.management_max > 64
            || c.desktop_min == 0
            || c.desktop_max < c.desktop_min
            || c.desktop_max > 64
            || !["never", "may-require"].contains(&self.reboot_policy.as_str())
            || self.rollback_predecessors.len() > 16
        {
            return false;
        }
        if let Some(driver) = &self.driver {
            if !driver.valid() {
                return false;
            }
        }
        let mut ids = HashSet::new();
        let mut digests = HashSet::new();
        self.rollback_predecessors.iter().all(|p| {
            identifier(&p.target_id)
                && p.target_id != self.target_id
                && valid_digest(&p.manifest_sha256)
                && ids.insert(&p.target_id)
                && digests.insert(&p.manifest_sha256)
        })
    }
}
