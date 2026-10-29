use super::KeyUnavailable;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    MachineKey,
    CertificateBundle,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::MachineKey => "machine-key.json",
            Self::CertificateBundle => "certificate-bundle.json",
        }
    }
    fn c_name(self) -> &'static [u8] {
        match self {
            Self::MachineKey => b"machine-key.json\0",
            Self::CertificateBundle => b"certificate-bundle.json\0",
        }
    }
    fn limit(self) -> u64 {
        match self {
            Self::MachineKey => 16 * 1024,
            Self::CertificateBundle => 288 * 1024,
        }
    }
}
pub(super) struct Store {
    kind: Kind,
    root: PathBuf,
    directory: File,
    file: File,
    hash: Option<[u8; 32]>,
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}
fn owner() -> u32 {
    // SAFETY: geteuid has no pointer arguments or caller-owned resources.
    unsafe { libc::geteuid() }
}
fn id(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn parents(path: &Path) -> Result<(), KeyUnavailable> {
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute()
        || normalized.as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(KeyUnavailable);
    }
    let mut parent = path.parent();
    while let Some(path) = parent {
        let metadata = fs::symlink_metadata(path).map_err(|_| KeyUnavailable)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || ![0, owner()].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
        {
            return Err(KeyUnavailable);
        }
        parent = path.parent();
    }
    Ok(())
}
fn directory(path: &Path) -> Result<File, KeyUnavailable> {
    parents(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| KeyUnavailable)?;
    let metadata = file.metadata().map_err(|_| KeyUnavailable)?;
    if !metadata.is_dir() || metadata.uid() != owner() || metadata.mode() & 0o7777 != 0o700 {
        return Err(KeyUnavailable);
    }
    Ok(file)
}
fn record_file(directory: &File, create: bool, kind: Kind) -> Result<File, KeyUnavailable> {
    let flags = libc::O_RDWR
        | libc::O_NONBLOCK
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if create {
            libc::O_CREAT | libc::O_EXCL
        } else {
            0
        };
    // SAFETY: the directory descriptor remains borrowed/live, the fixed name is
    // NUL-terminated, and create uses an explicit private mode. No path traversal
    // or final symlink following is possible through this relative filename.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            kind.c_name().as_ptr().cast(),
            flags,
            0o600 as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(KeyUnavailable);
    }
    // SAFETY: openat returned a fresh owned descriptor; File closes it on every
    // error path as well as after successful use.
    let file = unsafe { File::from_raw_fd(descriptor) };
    file.try_lock_exclusive().map_err(|_| KeyUnavailable)?;
    let metadata = file.metadata().map_err(|_| KeyUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != owner()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > kind.limit()
    {
        return Err(KeyUnavailable);
    }
    Ok(file)
}
impl Store {
    pub(super) fn require_separate_root(&self, path: &Path) -> Result<(), KeyUnavailable> {
        if path.starts_with(&self.root) {
            return Err(KeyUnavailable);
        }
        Ok(())
    }
    pub(super) fn initialize(root: &Path, kind: Kind) -> Result<Self, KeyUnavailable> {
        parents(root)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root)
            .map_err(|_| KeyUnavailable)?;
        let directory = directory(root)?;
        let file = record_file(&directory, true, kind)?;
        let store = Self {
            kind,
            root: root.to_owned(),
            directory,
            file,
            hash: None,
        };
        store.check()?;
        Ok(store)
    }
    pub(super) fn reopen(root: &Path, kind: Kind) -> Result<Self, KeyUnavailable> {
        let directory = directory(root)?;
        let file = record_file(&directory, false, kind)?;
        let store = Self {
            kind,
            root: root.to_owned(),
            directory,
            file,
            hash: None,
        };
        store.check()?;
        Ok(store)
    }
    fn check(&self) -> Result<(), KeyUnavailable> {
        parents(&self.root)?;
        let directory = directory(&self.root)?;
        if id(&directory.metadata().map_err(|_| KeyUnavailable)?)
            != id(&self.directory.metadata().map_err(|_| KeyUnavailable)?)
        {
            return Err(KeyUnavailable);
        }
        let metadata =
            fs::symlink_metadata(self.root.join(self.kind.name())).map_err(|_| KeyUnavailable)?;
        let held = self.file.metadata().map_err(|_| KeyUnavailable)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || id(&metadata) != id(&held)
            || held.uid() != owner()
            || held.mode() & 0o7777 != 0o600
            || held.nlink() != 1
            || held.len() > self.kind.limit()
        {
            return Err(KeyUnavailable);
        }
        let entries = fs::read_dir(&self.root).map_err(|_| KeyUnavailable)?;
        for entry in entries {
            if entry.map_err(|_| KeyUnavailable)?.file_name() != self.kind.name() {
                return Err(KeyUnavailable);
            }
        }
        Ok(())
    }
    pub(super) fn write_once(&mut self, raw: &[u8]) -> Result<(), KeyUnavailable> {
        self.check()?;
        if self.hash.is_some()
            || raw.is_empty()
            || raw.len() as u64 > self.kind.limit()
            || self.file.metadata().map_err(|_| KeyUnavailable)?.len() != 0
        {
            return Err(KeyUnavailable);
        }
        self.file.write_all(raw).map_err(|_| KeyUnavailable)?;
        self.file.sync_all().map_err(|_| KeyUnavailable)?;
        self.directory.sync_all().map_err(|_| KeyUnavailable)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.parent().ok_or(KeyUnavailable)?)
            .map_err(|_| KeyUnavailable)?;
        parent.sync_all().map_err(|_| KeyUnavailable)?;
        self.check()?;
        self.remember(raw);
        Ok(())
    }
    pub(super) fn read(&mut self) -> Result<Zeroizing<Vec<u8>>, KeyUnavailable> {
        self.check()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| KeyUnavailable)?;
        let mut raw = Zeroizing::new(Vec::new());
        Read::by_ref(&mut self.file)
            .take(self.kind.limit() + 1)
            .read_to_end(&mut raw)
            .map_err(|_| KeyUnavailable)?;
        if raw.is_empty() || raw.len() as u64 > self.kind.limit() {
            return Err(KeyUnavailable);
        }
        self.check()?;
        Ok(raw)
    }
    pub(super) fn remember(&mut self, raw: &[u8]) {
        self.hash = Some(Sha256::digest(raw).into());
    }
    pub(super) fn unchanged(&mut self) -> Result<(), KeyUnavailable> {
        let raw = self.read()?;
        if Some(Sha256::digest(&*raw).into()) != self.hash {
            return Err(KeyUnavailable);
        }
        Ok(())
    }
}
