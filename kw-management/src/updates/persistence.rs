//! Exclusive, bounded, file-backed updater checkpoints.
//!
//! The root must be a dedicated machine updater directory, provisioned beneath
//! trusted parents outside the agent MSI replacement tree. `create_root` creates
//! only the final component, with a private ACL/mode from birth; it never repairs
//! an existing directory. Callers must retain this store for the helper lifetime.
//! An OS file lock fences other cooperating helper processes and is released on
//! process death. It is not a substitute for the API lease or signed phase grant.
//!
//! Recovery requires the plan/checkpoint digest and sequence floor from trusted
//! off-guest coordination. Neither a local hash nor an orphan temporary file is
//! authority. An uncertain write result requires reopening/reconciliation, never
//! retrying the installer. No installer, service or management transport runs here.

pub(crate) mod security;
#[cfg(test)]
mod tests;

use super::journal::{Error, Journal, Store, MAX_JOURNAL_BYTES};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub use security::create_root;

/// Exactly one helper owns the machine updater root, across all attempts.
/// Checkpoints are retained by the caller before admitting a subsequent attempt.
pub struct FileStore {
    root: PathBuf,
    _lock: File,
    head: Journal,
    uncertain: bool,
    #[cfg(test)]
    fail_after_replace: bool,
}

impl Drop for FileStore {
    fn drop(&mut self) {
        // Explicitly unlock before close: a concurrent Unix fork can briefly
        // retain the same open-file description until its CLOEXEC takes effect.
        let _ = FileExt::unlock(&self._lock);
    }
}

impl FileStore {
    /// Initializes an empty updater root. Never overwrites an existing attempt.
    pub fn initialize(root: &Path, initial: Journal) -> Result<Self, Error> {
        let lock = acquire(root)?;
        if initial.snapshot().sequence != 0
            || initial.snapshot().phase != "ready"
            || root
                .join("checkpoint.json")
                .try_exists()
                .map_err(io_error)?
            || root
                .join("checkpoint.next")
                .try_exists()
                .map_err(io_error)?
        {
            return Err(Error::Conflict);
        }
        // Validate even caller-constructed initial journals before persistence.
        Journal::decode(
            &initial.encode(),
            &initial.snapshot().plan.sha256(),
            &initial.sha256(),
            0,
        )?;
        let mut store = Self {
            root: root.to_owned(),
            _lock: lock,
            head: initial,
            uncertain: false,
            #[cfg(test)]
            fail_after_replace: false,
        };
        store.write_checkpoint(&store.head.encode())?;
        Ok(store)
    }

    pub fn reopen(
        root: &Path,
        plan_sha256: &str,
        checkpoint_sha256: &str,
        minimum_sequence: u64,
    ) -> Result<Self, Error> {
        let lock = acquire(root)?;
        let head = Journal::decode(
            &read_checkpoint(root)?,
            plan_sha256,
            checkpoint_sha256,
            minimum_sequence,
        )?;
        // A crash before rename can leave a partial .next. Only remove it after
        // the committed checkpoint matched independent trusted coordination.
        let pending = root.join("checkpoint.next");
        if pending.try_exists().map_err(io_error)? {
            security::check_file(&pending)?;
            fs::remove_file(pending).map_err(io_error)?;
            sync_root(root)?;
        }
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
            head,
            uncertain: false,
            #[cfg(test)]
            fail_after_replace: false,
        })
    }

    pub fn journal(&self) -> &Journal {
        &self.head
    }

    fn write_checkpoint(&mut self, raw: &[u8]) -> Result<(), Error> {
        // Once any I/O begins, an error poisons this handle. In particular, a
        // successful rename followed by a failed directory flush is uncertain.
        self.uncertain = true;
        let pending = self.root.join("checkpoint.next");
        let mut file = private_new(&pending)?;
        file.write_all(raw).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        replace(&pending, &self.root.join("checkpoint.json"))?;
        #[cfg(test)]
        if self.fail_after_replace {
            return Err(Error::Persistence);
        }
        sync_root(&self.root)?;
        self.uncertain = false;
        Ok(())
    }
}

impl Store for FileStore {
    fn compare_and_swap(&mut self, expected: &str, next: &[u8]) -> Result<(), Error> {
        if self.uncertain {
            return Err(Error::Persistence);
        }
        security::check_root(&self.root)?;
        // Verify disk as well as RAM: out-of-band edits must not be overwritten.
        let current = Journal::decode(
            &read_checkpoint(&self.root)?,
            &self.head.snapshot().plan.sha256(),
            &self.head.sha256(),
            self.head.snapshot().sequence,
        )?;
        if current.sha256() != expected {
            return Err(Error::Conflict);
        }
        if next.is_empty() || next.len() > MAX_JOURNAL_BYTES {
            return Err(Error::Journal);
        }
        let mut hashed = b"kw-agent-upgrade-journal/v1\0".to_vec();
        hashed.extend_from_slice(next);
        let candidate = Journal::decode(
            next,
            &current.snapshot().plan.sha256(),
            &super::digest(&hashed),
            current.snapshot().sequence + 1,
        )?;
        if candidate.snapshot().sequence != current.snapshot().sequence + 1
            || candidate.snapshot().owner_fence < current.snapshot().owner_fence
            || candidate.snapshot().started_at != current.snapshot().started_at
            || candidate.snapshot().updated_at < current.snapshot().updated_at
            || candidate.snapshot().plan != current.snapshot().plan
        {
            return Err(Error::Conflict);
        }
        self.write_checkpoint(next)?;
        self.head = candidate;
        Ok(())
    }
}

fn io_error(_: std::io::Error) -> Error {
    Error::Persistence
}

fn acquire(root: &Path) -> Result<File, Error> {
    security::check_root(root)?;
    let path = root.join("owner.lock");
    let lock = match private_new(&path) {
        Ok(file) => file,
        Err(_) => {
            security::check_file(&path)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(io_error)?
        }
    };
    security::check_file(&path)?;
    lock.try_lock_exclusive().map_err(|_| Error::Conflict)?;
    Ok(lock)
}

#[cfg(windows)]
fn private_new(path: &Path) -> Result<File, Error> {
    security::native::create_file(path)
}

#[cfg(unix)]
fn private_new(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io_error)
}

fn read_checkpoint(root: &Path) -> Result<Vec<u8>, Error> {
    let path = root.join("checkpoint.json");
    security::check_file(&path)?;
    let file = File::open(path).map_err(io_error)?;
    let mut raw = Vec::new();
    file.take(MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(io_error)?;
    if raw.len() > MAX_JOURNAL_BYTES {
        return Err(Error::Journal);
    }
    Ok(raw)
}

#[cfg(unix)]
fn replace(from: &Path, to: &Path) -> Result<(), Error> {
    fs::rename(from, to).map_err(io_error)
}

#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<(), Error> {
    use windows::{core::PCWSTR, Win32::Storage::FileSystem::*};
    unsafe {
        MoveFileExW(
            PCWSTR(security::wide(from).as_ptr()),
            PCWSTR(security::wide(to).as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(|_| Error::Persistence)
    }
}

#[cfg(unix)]
fn sync_root(root: &Path) -> Result<(), Error> {
    File::open(root)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error)
}

#[cfg(windows)]
fn sync_root(_: &Path) -> Result<(), Error> {
    // MoveFileExW above requests synchronous write-through completion.
    Ok(())
}
