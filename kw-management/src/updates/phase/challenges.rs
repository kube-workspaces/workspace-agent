//! Bounded, machine-exclusive durable guest challenges. This is not a live
//! identity/policy source, a management transport, or rollback-resistant storage.
//! Use a dedicated protected root, separate from the updater journal root.

use super::{CurrentAuthority, LiveContext, Permit, MAX_SECONDS};
use crate::file_lock::ExclusiveFile;
use crate::updates::{
    installer::Error as DispatchError,
    journal::{Action, Error, Plan},
    persistence::{acquire, private_new, replace, security, sync_root},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: usize = 8192;

/// Independently minted before requesting a signature. Times bound the guest's
/// outstanding challenge; issuer timestamps must independently pass verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub plan_sha256: String,
    pub action: Action,
    pub owner_fence: u64,
    pub nonce: String,
    pub peer_sha256: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl Challenge {
    fn valid(&self) -> bool {
        Permit {
            version: 1,
            audience: "agent-upgrade.phase.v1".into(),
            plan_sha256: self.plan_sha256.clone(),
            action: self.action.clone(),
            owner_fence: self.owner_fence,
            challenge: self.nonce.clone(),
            peer_sha256: self.peer_sha256.clone(),
            issued_at: self.created_at,
            expires_at: self.expires_at,
        }
        .valid()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    pending: Option<Challenge>,
}

/// One outstanding challenge per machine root, across all attempts and owners.
/// Never auto-initialize on a missing/corrupt file. Retain the root and lock for
/// the helper lifetime; deletion/backup restore requires independent recovery.
pub struct FileChallenges {
    root: PathBuf,
    _lock: ExclusiveFile,
    head: Snapshot,
    uncertain: bool,
    #[cfg(test)]
    fail_after_replace: bool,
}

impl FileChallenges {
    pub fn initialize(root: &Path) -> Result<Self, Error> {
        let lock = acquire(root)?;
        // An existing owner.lock alone can be left by a failed initialization;
        // neither a committed state nor an uncertain temporary is overwritten.
        for name in ["challenges.json", "challenges.next"] {
            if root.join(name).try_exists().map_err(io_error)? {
                return Err(Error::Conflict);
            }
        }
        let mut store = Self {
            root: root.to_owned(),
            _lock: lock,
            head: Snapshot {
                version: 1,
                pending: None,
            },
            uncertain: false,
            #[cfg(test)]
            fail_after_replace: false,
        };
        store.write(store.head.clone())?;
        Ok(store)
    }

    pub fn reopen(root: &Path) -> Result<Self, Error> {
        let lock = acquire(root)?;
        // Do not infer whether an interrupted issue/consume committed. Pending
        // temporary state requires explicit recovery, not automatic deletion.
        if root
            .join("challenges.next")
            .try_exists()
            .map_err(io_error)?
        {
            return Err(Error::Persistence);
        }
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
            head: read(root)?,
            uncertain: false,
            #[cfg(test)]
            fail_after_replace: false,
        })
    }

    fn checked(&self) -> Result<(), Error> {
        if self.uncertain {
            return Err(Error::Persistence);
        }
        security::check_root(&self.root)?;
        if read(&self.root)? != self.head {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn issue(
        &mut self,
        plan: &Plan,
        action: &Action,
        fence: u64,
        peer: &PeerContext,
    ) -> Result<Challenge, Error> {
        self.checked()?;
        if self.head.pending.is_some() || !plan.valid() {
            return Err(Error::Conflict);
        }
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).map_err(|_| Error::Persistence)?;
        let challenge = Challenge {
            plan_sha256: plan.sha256(),
            action: action.clone(),
            owner_fence: fence,
            nonce: URL_SAFE_NO_PAD.encode(random),
            peer_sha256: peer.peer_sha256.clone(),
            created_at: peer.now,
            expires_at: peer.now.checked_add(MAX_SECONDS).ok_or(Error::Conflict)?,
        };
        if !challenge.valid() {
            return Err(Error::Conflict);
        }
        self.write(Snapshot {
            version: 1,
            pending: Some(challenge.clone()),
        })?;
        Ok(challenge)
    }

    fn consume(&mut self) -> Result<Challenge, Error> {
        self.checked()?;
        let challenge = self.head.pending.clone().ok_or(Error::Conflict)?;
        // Return the challenge ONLY after the spent state is durably committed.
        self.write(Snapshot {
            version: 1,
            pending: None,
        })?;
        Ok(challenge)
    }

    /// Abandon an outstanding challenge without authorizing any effect. Retries
    /// require a fresh random challenge, never restoration of the spent nonce.
    pub fn invalidate(&mut self) -> Result<(), Error> {
        self.consume().map(|_| ())
    }

    fn write(&mut self, next: Snapshot) -> Result<(), Error> {
        self.uncertain = true;
        let pending = self.root.join("challenges.next");
        let mut file = private_new(&pending)?;
        file.write_all(&serde_json::to_vec(&next).map_err(io_error)?)
            .map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        replace(&pending, &self.root.join("challenges.json"))?;
        #[cfg(test)]
        if self.fail_after_replace {
            return Err(Error::Persistence);
        }
        sync_root(&self.root)?;
        self.head = next;
        self.uncertain = false;
        Ok(())
    }
}

fn io_error<T>(_: T) -> Error {
    Error::Persistence
}

fn read(root: &Path) -> Result<Snapshot, Error> {
    let path = root.join("challenges.json");
    security::check_file(&path)?;
    let file = OpenOptions::new().read(true).open(path).map_err(io_error)?;
    let mut raw = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(io_error)?;
    if raw.is_empty() || raw.len() > MAX_BYTES {
        return Err(Error::Persistence);
    }
    let snapshot: Snapshot = serde_json::from_slice(&raw).map_err(io_error)?;
    if snapshot.version != 1
        || snapshot.pending.as_ref().is_some_and(|p| !p.valid())
        || serde_json::to_vec(&snapshot).map_err(io_error)? != raw
    {
        return Err(Error::Persistence);
    }
    Ok(snapshot)
}

/// Obtained from the authenticated transport and trusted clock, never a permit
/// field or request header. Outage/unknown clock must return an error instead.
pub struct PeerContext {
    pub peer_sha256: String,
    pub now: i64,
}

/// Required live identity/epoch/boot, owner lease/fence, cancellation/deadline,
/// policy and exact durable intent checks. No production source is supplied.
pub trait LiveAuthority {
    fn check(
        &mut self,
        plan: &Plan,
        action: &Action,
        fence: u64,
    ) -> Result<PeerContext, DispatchError>;
}

/// Adds durable replay protection to a REQUIRED independent live authority.
/// Does not construct journal actions, acknowledge recording or dispatch work.
pub struct DurableCurrentAuthority<S> {
    store: FileChallenges,
    current: S,
}

impl<S: LiveAuthority> DurableCurrentAuthority<S> {
    pub fn new(store: FileChallenges, current: S) -> Self {
        Self { store, current }
    }

    pub fn challenge(
        &mut self,
        plan: &Plan,
        action: &Action,
        fence: u64,
    ) -> Result<Challenge, DispatchError> {
        let peer = self.current.check(plan, action, fence)?;
        self.store
            .issue(plan, action, fence, &peer)
            .map_err(|_| DispatchError::Authority)
    }
}

impl<S: LiveAuthority> CurrentAuthority for DurableCurrentAuthority<S> {
    fn check(
        &mut self,
        plan: &Plan,
        action: &Action,
        fence: u64,
    ) -> Result<LiveContext, DispatchError> {
        // Burn before ANY binding/live/signature check, including an outage.
        let challenge = self.store.consume().map_err(|_| DispatchError::Authority)?;
        let peer = self.current.check(plan, action, fence)?;
        if !plan.valid()
            || challenge.plan_sha256 != plan.sha256()
            || challenge.action != *action
            || challenge.owner_fence != fence
            || challenge.peer_sha256 != peer.peer_sha256
            || peer.now < challenge.created_at
            || peer.now >= challenge.expires_at
        {
            return Err(DispatchError::Authority);
        }
        Ok(LiveContext {
            challenge: challenge.nonce,
            peer_sha256: peer.peer_sha256,
            now: peer.now,
        })
    }
}

#[cfg(test)]
mod tests;
