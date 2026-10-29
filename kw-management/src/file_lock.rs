//! Own a successful lock immediately, before any caller validation can fail.
//! Closing a descriptor alone is insufficient on Unix when a fork/duplicate
//! still retains its open-file description. Never clone this guard or unlock a
//! file whose acquisition failed.

use fs2::FileExt;
use std::{fs::File, io};

pub(crate) struct ExclusiveFile {
    file: File,
}
impl ExclusiveFile {
    /// `file` must be independently opened, not a duplicate of another guard.
    pub(crate) fn try_lock(file: File) -> io::Result<Self> {
        FileExt::try_lock_exclusive(&file)?;
        Ok(Self { file })
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}
impl Drop for ExclusiveFile {
    fn drop(&mut self) {
        // This guard exists only after successful acquisition. Explicit unlock
        // also releases duplicated descriptions left by a concurrent fork.
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::PathBuf,
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let root = std::env::temp_dir().join(format!("kw-exclusive-file-{suffix}"));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("owner.lock"))
                .unwrap();
            Self(root)
        }
        fn open(&self) -> File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.0.join("owner.lock"))
                .unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn raw_descriptor_close_retains_lock_but_guard_drop_releases_duplicates() {
        let temp = Temp::new();
        let raw = temp.open();
        FileExt::try_lock_exclusive(&raw).unwrap();
        let inherited = raw.try_clone().unwrap();
        drop(raw);
        assert!(ExclusiveFile::try_lock(temp.open()).is_err());
        FileExt::unlock(&inherited).unwrap();
        drop(inherited);

        let owner = ExclusiveFile::try_lock(temp.open()).unwrap();
        let inherited = owner.file().try_clone().unwrap();
        drop(owner);
        let replacement = ExclusiveFile::try_lock(temp.open()).unwrap();
        drop(inherited);
        assert!(ExclusiveFile::try_lock(temp.open()).is_err());
        drop(replacement);
        assert!(ExclusiveFile::try_lock(temp.open()).is_ok());
    }

    #[test]
    fn failed_acquisition_never_unlocks_a_successful_owner() {
        let temp = Temp::new();
        let owner = ExclusiveFile::try_lock(temp.open()).unwrap();
        for _ in 0..10 {
            assert!(ExclusiveFile::try_lock(temp.open()).is_err());
        }
        // The lock still exists after every failed contender was dropped.
        assert!(FileExt::try_lock_exclusive(&temp.open()).is_err());
        drop(owner);
        let replacement = ExclusiveFile::try_lock(temp.open()).unwrap();
        assert!(ExclusiveFile::try_lock(temp.open()).is_err());
        drop(replacement);
        assert!(ExclusiveFile::try_lock(temp.open()).is_ok());
    }
}
