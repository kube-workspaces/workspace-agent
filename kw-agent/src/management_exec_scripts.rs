//! Linux script staging after signature verification and persistent replay claim.
//! The script lock serializes staging/recovery through process-tree teardown.
//! A subsequent verified request removes crash leftovers, never executes them.

use kw_management::{digest, QgaScript};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

pub(super) struct StagedScript {
    directory: PathBuf,
    // Kept open across spawn and cleanup. Kernel releases it on runner death.
    _lock: File,
}

fn private_directory(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "script directory unavailable")?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("script directory is not private or has the wrong owner".into());
    }
    Ok(())
}

fn cleanup(directory: &Path) -> Result<(), String> {
    private_directory(directory)?;
    let path = directory.join("script");
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() && meta.nlink() == 1 => {
            fs::remove_file(path).map_err(|_| "script removal failed")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("unexpected staged script file".into()),
    }
    // Never recursively delete caller-created or unexpected content.
    fs::remove_dir(directory).map_err(|_| "script directory removal failed".into())
}

impl StagedScript {
    pub(super) fn create(state_dir: &Path, jti: &str, script: &QgaScript) -> Result<Self, String> {
        script.validate()?;
        let parent = fs::symlink_metadata(state_dir).map_err(|_| "script parent unavailable")?;
        if !state_dir.is_absolute()
            || !parent.is_dir()
            || parent.uid() != unsafe { libc::geteuid() }
            || parent.mode() & 0o022 != 0
        {
            return Err("script parent is not trusted".into());
        }
        let root = state_dir.join("scripts");
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err("script directory creation failed".into()),
        }
        private_directory(&root)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("lock"))
            .map_err(|_| "script lock unavailable")?;
        let meta = lock.metadata().map_err(|_| "script lock unavailable")?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err("script lock is not private".into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another script is active; request was not dispatched".into());
        }
        for entry in fs::read_dir(&root).map_err(|_| "script recovery unavailable")? {
            let entry = entry.map_err(|_| "script recovery unavailable")?;
            if entry.file_name() == "lock" {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or("unexpected script recovery entry")?;
            if name.len() != 64 || !name.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err("unexpected script recovery entry".into());
            }
            cleanup(&entry.path())?;
        }
        let directory = root.join(digest(jti.as_bytes()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| "script staging directory creation failed")?;
        let staged = Self {
            directory,
            _lock: lock,
        };
        // create_new plus a private, exclusive directory prevents replacement,
        // symlink adoption and collisions. The basename hint never becomes a path.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(staged.path())
            .map_err(|_| "script staging failed")?;
        file.write_all(script.body.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| "script staging failed")?;
        // Close before exec: Linux rejects executing a file held open for write.
        drop(file);
        Ok(staged)
    }

    pub(super) fn path(&self) -> PathBuf {
        self.directory.join("script")
    }

    pub(super) fn finish(self) -> Result<(), String> {
        cleanup(&self.directory)
    }
}

impl Drop for StagedScript {
    fn drop(&mut self) {
        if self.directory.exists() {
            let _ = cleanup(&self.directory);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script() -> QgaScript {
        QgaScript {
            body: "#!/bin/sh\nexit 0\n".into(),
            name: None,
            interpreter_policy: "linux-shebang-v1".into(),
        }
    }

    #[test]
    fn active_script_is_fenced_and_crash_leftovers_are_removed_without_execution() {
        let dir = super::super::tests::temp_dir("script-recovery");
        let first = StagedScript::create(&dir, "first", &script()).unwrap();
        assert!(StagedScript::create(&dir, "second", &script()).is_err());
        assert!(first.path().exists());
        let leftover = first.directory.clone();
        first.finish().unwrap();
        // Reconstruct the on-disk state left by runner death: no held lock,
        // private directory and a script that must only be removed.
        fs::DirBuilder::new().mode(0o700).create(&leftover).unwrap();
        fs::write(leftover.join("script"), "#!/bin/sh\nexit 99\n").unwrap();
        let second = StagedScript::create(&dir, "second", &script()).unwrap();
        assert!(!leftover.exists());
        second.finish().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_symlink_or_nonprivate_staging_root() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = super::super::tests::temp_dir("script-root");
        let other = super::super::tests::temp_dir("script-root-target");
        symlink(&other, dir.join("scripts")).unwrap();
        assert!(StagedScript::create(&dir, "first", &script()).is_err());
        fs::remove_file(dir.join("scripts")).unwrap();
        fs::create_dir(dir.join("scripts")).unwrap();
        fs::set_permissions(dir.join("scripts"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(StagedScript::create(&dir, "first", &script()).is_err());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(other).unwrap();
    }
}
