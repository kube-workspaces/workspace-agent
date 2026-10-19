//! Protected launch binding and read-only recovery for the independent helper.
//! A local launch file identifies an attempt; it is not current phase authority.

use super::{
    identifier,
    journal::Binding,
    persistence::{self, FileStore},
    valid_digest,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

pub const MAX_LAUNCH_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Binding,
    Storage,
    Authority,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchBinding {
    pub version: u32,
    pub binding: Binding,
    pub plan_sha256: String,
}

/// Supplied only after independently authenticated current off-guest recovery
/// coordination. A checkpoint's own digest or a local launch-file field is not
/// an acceptable source. It never authorizes a new effect by itself.
pub struct RecoveryHead {
    pub plan_sha256: String,
    pub checkpoint_sha256: String,
    pub minimum_sequence: u64,
}

pub trait RecoveryAuthority: Send {
    /// None means temporarily unavailable; errors mean denied/invalid authority.
    fn current_head(&mut self, launch: &LaunchBinding) -> Result<Option<RecoveryHead>, Error>;
}

/// Until authenticated management transport is integrated, the shipped helper
/// waits for authority. No permissive local-file or QGA fallback exists.
pub struct UnavailableAuthority;
impl RecoveryAuthority for UnavailableAuthority {
    fn current_head(&mut self, _: &LaunchBinding) -> Result<Option<RecoveryHead>, Error> {
        Ok(None)
    }
}

impl LaunchBinding {
    fn valid(&self) -> bool {
        let b = &self.binding;
        self.version == 1
            && valid_digest(&self.plan_sha256)
            && [
                &b.attempt_id,
                &b.namespace,
                &b.workspace_name,
                &b.workspace_uid,
                &b.vm_uid,
                &b.actor_uid,
                &b.recording_id,
            ]
            .iter()
            .all(|s| identifier(s))
            && b.revocation_epoch <= i64::MAX as u64
            && [&b.target_sha256, &b.previous_sha256, &b.inventory_sha256]
                .iter()
                .all(|s| valid_digest(s))
            && b.target_sha256 != b.previous_sha256
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if !self.valid() {
            return Err(Error::Binding);
        }
        let raw = serde_json::to_vec(self).map_err(|_| Error::Binding)?;
        if raw.len() > MAX_LAUNCH_BYTES {
            return Err(Error::Binding);
        }
        Ok(raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_LAUNCH_BYTES {
            return Err(Error::Binding);
        }
        let binding: Self = serde_json::from_slice(raw).map_err(|_| Error::Binding)?;
        if !binding.valid() || binding.encode()? != raw {
            return Err(Error::Binding);
        }
        Ok(binding)
    }

    /// Bootstrap writes this once after durable admission, before SCM startup.
    /// A crash/partial write fails closed rather than repairing or adopting it.
    pub fn write_new(&self, root: &Path) -> Result<(), Error> {
        let raw = self.encode()?;
        persistence::security::check_root(root).map_err(|_| Error::Storage)?;
        let mut file =
            persistence::private_new(&root.join("resume.json")).map_err(|_| Error::Storage)?;
        file.write_all(&raw)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Storage)?;
        persistence::sync_root(root).map_err(|_| Error::Storage)
    }

    pub fn read(root: &Path) -> Result<Self, Error> {
        persistence::security::check_root(root).map_err(|_| Error::Storage)?;
        let path = root.join("resume.json");
        persistence::security::check_file(&path).map_err(|_| Error::Storage)?;
        let mut raw = Vec::new();
        File::open(path)
            .map_err(|_| Error::Storage)?
            .take(MAX_LAUNCH_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Storage)?;
        Self::decode(&raw)
    }

    /// Read-only restart reconciliation. Retain the returned store until stop to
    /// hold exclusive checkpoint ownership. Never deserialize an action permit.
    pub fn recover(
        &self,
        root: &Path,
        authority: &mut dyn RecoveryAuthority,
    ) -> Result<Option<FileStore>, Error> {
        if !self.valid() {
            return Err(Error::Binding);
        }
        let Some(head) = authority.current_head(self)? else {
            return Ok(None);
        };
        if head.plan_sha256 != self.plan_sha256 {
            return Err(Error::Authority);
        }
        let store = FileStore::reopen(
            root,
            &head.plan_sha256,
            &head.checkpoint_sha256,
            head.minimum_sequence,
        )
        .map_err(|_| Error::Authority)?;
        if store.journal().snapshot().plan.binding != self.binding {
            return Err(Error::Authority);
        }
        Ok(Some(store))
    }
}

/// Protect the independent SCM image path. Bootstrap must also verify the
/// publisher-approved helper artifact before copying/registering this file.
pub fn validate_host(root: &Path, image: &Path) -> Result<(), Error> {
    persistence::security::check_root(root).map_err(|_| Error::Storage)?;
    let image_parent = image
        .parent()
        .ok_or(Error::Binding)?
        .canonicalize()
        .map_err(|_| Error::Storage)?;
    if image_parent != root.canonicalize().map_err(|_| Error::Storage)?
        || image.file_name() != Some(std::ffi::OsStr::new("kw-agent-updater.exe"))
    {
        return Err(Error::Binding);
    }
    persistence::security::check_file(image).map_err(|_| Error::Storage)
}

#[derive(Serialize)]
pub struct RuntimeStatus {
    version: u32,
    process_id: u32,
    attempt_id: String,
    state: &'static str,
    journal_sequence: Option<u64>,
    journal_phase: Option<String>,
    effects_enabled: bool,
}

impl RuntimeStatus {
    pub fn new(launch: &LaunchBinding, store: Option<&FileStore>) -> Self {
        Self {
            version: 1,
            process_id: std::process::id(),
            attempt_id: launch.binding.attempt_id.clone(),
            state: if store.is_some() {
                "checkpoint_verified"
            } else {
                "waiting_for_authority"
            },
            journal_sequence: store.map(|s| s.journal().snapshot().sequence),
            journal_phase: store.map(|s| s.journal().snapshot().phase.clone()),
            effects_enabled: false,
        }
    }

    /// Protected operational hint, never audit/dispatch authority. Caller holds
    /// the machine updater mutex. A stale temporary status can be safely removed
    /// because neither status file is used as a checkpoint or phase grant.
    pub fn write(&self, root: &Path) -> Result<(), Error> {
        persistence::security::check_root(root).map_err(|_| Error::Storage)?;
        let raw = serde_json::to_vec(self).map_err(|_| Error::Storage)?;
        let pending = root.join("updater-status.next");
        let target = root.join("updater-status.json");
        for path in [&pending, &target] {
            if path.try_exists().map_err(|_| Error::Storage)? {
                persistence::security::check_file(path).map_err(|_| Error::Storage)?;
            }
        }
        if pending.try_exists().map_err(|_| Error::Storage)? {
            fs::remove_file(&pending).map_err(|_| Error::Storage)?;
        }
        let mut file = persistence::private_new(&pending).map_err(|_| Error::Storage)?;
        file.write_all(&raw)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Storage)?;
        drop(file);
        persistence::replace(&pending, &target)
            .and_then(|_| persistence::sync_root(root))
            .map_err(|_| Error::Storage)
    }
}

#[cfg(test)]
mod tests;
