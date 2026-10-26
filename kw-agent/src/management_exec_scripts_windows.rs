//! SYSTEM-only script staging. Explicit protected ACLs from creation, no inherited
//! content permissions, no path hints, no shell-string interpolation. The lock
//! fences staging/recovery until Job Object teardown and script cleanup complete.

use kw_management::{digest, QgaScript};
use std::{
    fs::{self, File},
    io::Write,
    os::windows::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{LocalFree, BOOL, HANDLE, HLOCAL, PSID},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
    },
};

const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const DIRECTORY_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)";
const FILE_SDDL: &str = "O:SYG:SYD:P(A;;FA;;;SY)";

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn descriptor(directory: bool) -> Result<Descriptor, String> {
    let text: Vec<u16> = if directory { DIRECTORY_SDDL } else { FILE_SDDL }
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut raw = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            1,
            &mut raw,
            None,
        )
    }
    .map_err(|_| "script security descriptor unavailable")?;
    Ok(Descriptor(raw))
}

fn create_directory(path: &Path) -> Result<(), String> {
    let security = descriptor(true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0 .0,
        bInheritHandle: false.into(),
    };
    unsafe { CreateDirectoryW(PCWSTR(wide(path).as_ptr()), Some(&attributes)) }
        .map_err(|_| "private script directory creation failed".into())
}

fn create_file(path: &Path, lock: bool) -> Result<File, String> {
    let security = descriptor(false)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0 .0,
        bInheritHandle: false.into(),
    };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide(path).as_ptr()),
            0x80000000 | 0x40000000,
            if lock {
                FILE_SHARE_MODE(0)
            } else {
                FILE_SHARE_READ
            },
            Some(&attributes),
            if lock { OPEN_ALWAYS } else { CREATE_NEW },
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| "script file or exclusive lock unavailable")?;
    let file = unsafe { File::from_raw_handle(handle.0 as *mut std::ffi::c_void) };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle() as isize), &mut info) }
        .map_err(|_| "script file metadata unavailable")?;
    if info.nNumberOfLinks != 1
        || info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_DIRECTORY.0)
            != 0
    {
        return Err("script file must be a non-redirected single-link file".into());
    }
    Ok(file)
}

fn security_info(path: &Path) -> Result<Descriptor, String> {
    let mut raw = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide(path).as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut raw,
        )
    }
    .map_err(|_| "script ACL unavailable")?;
    Ok(Descriptor(raw))
}

fn check_private(path: &Path, directory: bool) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "script metadata unavailable")?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || meta.is_dir() != directory
        || (!directory && !meta.is_file())
    {
        return Err("redirected or unexpected script entry".into());
    }
    let security = security_info(path)?;
    let mut text = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security.0,
            1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    }
    .map_err(|_| "script ACL unreadable")?;
    let result = unsafe { text.to_string() }.map_err(|_| "script ACL unreadable");
    unsafe {
        let _ = LocalFree(HLOCAL(text.0.cast()));
    }
    let text = result?;
    let expected = if directory {
        "O:SYD:P(A;OICI;FA;;;SY)"
    } else {
        "O:SYD:P(A;;FA;;;SY)"
    };
    if text != expected && text != expected.replacen("D:P", "D:PAI", 1) {
        return Err("script entry must have its protected SYSTEM-only ACL".into());
    }
    if !directory {
        let file = File::open(path).map_err(|_| "script link metadata unavailable")?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle() as isize), &mut info) }
            .map_err(|_| "script link metadata unavailable")?;
        if info.nNumberOfLinks != 1 {
            return Err("script entry must not be hardlinked".into());
        }
    }
    Ok(())
}

fn privileged(sid: PSID) -> bool {
    unsafe {
        if IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
        {
            return true;
        }
        // Windows system-directory ancestors can be owned by TrustedInstaller.
        let mut text = PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut text).is_err() {
            return false;
        }
        let value = text.to_string();
        let _ = LocalFree(HLOCAL(text.0.cast()));
        value.is_ok_and(|v| v == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
    }
}

fn check_parent(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("script state path must be absolute".into());
    }
    for component in path.components() {
        match component {
            Component::ParentDir => return Err("script state path cannot traverse parents".into()),
            Component::Prefix(prefix)
                if !matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ) =>
            {
                return Err("script state path must be on a local disk".into())
            }
            Component::Normal(name) => {
                let name: Vec<u16> = name.encode_wide().collect();
                if name.iter().any(|c| *c == 0 || *c == b':' as u16)
                    || name
                        .last()
                        .is_some_and(|c| *c == b'.' as u16 || *c == b' ' as u16)
                {
                    return Err("invalid script state component".into());
                }
            }
            _ => (),
        }
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| "script parent unavailable")?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err("script parents cannot redirect".into());
        }
        // Ancestors must not let an ordinary principal replace the next path
        // component or rewrite its ACL. Creating unrelated sibling files/folders
        // (as allowed by ProgramData) does not confer replacement authority.
        check_parent_acl(
            ancestor,
            if ancestor == path {
                0x500d0156
            } else {
                0x100c0040
            },
        )?;
    }
    Ok(())
}

fn check_parent_acl(path: &Path, write_mask: u32) -> Result<(), String> {
    // The management parent inherits the installed data directory's protected
    // machine ACL. No ordinary principal may replace entries or change its ACL.
    let security = security_info(path)?;
    let mut owner = PSID::default();
    let mut defaulted = BOOL::default();
    let mut present = BOOL::default();
    let mut acl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorOwner(security.0, &mut owner, &mut defaulted)
            .map_err(|_| "script owner unavailable")?;
        GetSecurityDescriptorDacl(security.0, &mut present, &mut acl, &mut defaulted)
            .map_err(|_| "script parent ACL unavailable")?;
        if !privileged(owner) || !present.as_bool() || acl.is_null() {
            return Err("script state parent is not machine-owned".into());
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .map_err(|_| "script parent ACL unavailable")?;
        for index in 0..info.AceCount {
            let mut raw = std::ptr::null_mut();
            GetAce(acl, index, &mut raw).map_err(|_| "script parent ACE unavailable")?;
            let header = &*(raw as *const ACE_HEADER);
            if header.AceType == 1 || header.AceFlags & 0x08 != 0 {
                continue;
            } // deny/inherit-only cannot grant access here
            if header.AceType != 0 {
                return Err("unsupported script parent ACE".into());
            }
            if (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                return Err("malformed script parent ACE".into());
            }
            let ace = &*(raw as *const ACCESS_ALLOWED_ACE);
            let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
            // Generic write/all, DELETE, WRITE_DAC/OWNER and file write/append/
            // attributes/delete-child. Read and traversal grants are harmless.
            if ace.Mask & write_mask != 0 && !privileged(sid) {
                return Err("script state parent is writable by another principal".into());
            }
        }
    }
    Ok(())
}

fn cleanup(directory: &Path) -> Result<(), String> {
    check_private(directory, true)?;
    let path = directory.join("script.ps1");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            check_private(&path, false)?;
            fs::remove_file(path).map_err(|_| "script removal failed")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("script cleanup unavailable".into()),
    }
    fs::remove_dir(directory).map_err(|_| "script directory removal failed".into())
}

pub(super) struct StagedScript {
    directory: PathBuf,
    _lock: File,
}

impl StagedScript {
    pub(super) fn create(state_dir: &Path, jti: &str, script: &QgaScript) -> Result<Self, String> {
        if !crate::windows_runtime::process_is_local_system() {
            return Err("script staging requires SYSTEM".into());
        }
        script.validate()?;
        if script.interpreter_policy != "windows-powershell-v1" {
            return Err("unsupported Windows script policy".into());
        }
        check_parent(state_dir)?;
        let root = state_dir.join("scripts");
        if !root.exists() && create_directory(&root).is_err() && !root.exists() {
            return Err("script root creation failed".into());
        }
        check_private(&root, true)?;
        let lock_path = root.join("lock");
        if lock_path.exists() {
            check_private(&lock_path, false)?;
        }
        let lock = create_file(&lock_path, true)?;
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
        create_directory(&directory)?;
        let staged = Self {
            directory,
            _lock: lock,
        };
        let mut file = create_file(&staged.path(), false)?;
        // Windows PowerShell 5.1 otherwise interprets BOM-less non-ASCII input
        // using the host ANSI code page. The signed policy specifies UTF-8 BOM.
        file.write_all(b"\xef\xbb\xbf")
            .and_then(|_| file.write_all(script.body.as_bytes()))
            .and_then(|_| file.sync_all())
            .map_err(|_| "script staging failed")?;
        drop(file);
        Ok(staged)
    }

    pub(super) fn path(&self) -> PathBuf {
        self.directory.join("script.ps1")
    }
    pub(super) fn configure(&self, spec: &mut super::CommandSpec) {
        spec.executable = POWERSHELL.into();
        spec.args = [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(Some(self.path().to_string_lossy().into_owned()))
        .collect();
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

    #[test]
    fn no_ordinary_identity_can_stage_system_scripts() {
        if crate::windows_runtime::process_is_local_system() {
            return;
        }
        let script = QgaScript {
            body: "#!powershell\nexit 0\n".into(),
            name: None,
            interpreter_policy: "windows-powershell-v1".into(),
        };
        assert!(
            StagedScript::create(Path::new(r"C:\unused-script-test"), "test", &script).is_err()
        );
    }

    #[test]
    #[ignore = "requires a disposable Windows SYSTEM test session; see Windows script runbook"]
    fn system_script_acl_file_execution_and_recovery() {
        assert!(crate::windows_runtime::process_is_local_system());
        let state = std::env::temp_dir().join(format!(
            "kw-script-test-{}-{}",
            std::process::id(),
            kw_core::now_secs()
        ));
        create_directory(&state).unwrap();
        let script=QgaScript { body:"#!powershell\r\n[Console]::WriteLine('script'); [Console]::Error.WriteLine('stderr'); exit 7\r\n".into(),name:Some("ignored.ps1".into()),interpreter_policy:"windows-powershell-v1".into() };
        let staged = StagedScript::create(&state, "first", &script).unwrap();
        check_private(&staged.directory, true).unwrap();
        check_private(&staged.path(), false).unwrap();
        assert_eq!(
            fs::read(staged.path()).unwrap(),
            [b"\xef\xbb\xbf".as_slice(), script.body.as_bytes()].concat()
        );
        assert!(StagedScript::create(&state, "second", &script).is_err());
        let mut spec = super::super::CommandSpec {
            executable: String::new(),
            args: vec![],
            cwd: None,
            deadline: std::time::Duration::from_secs(20),
            output_limit: kw_management::QGA_MAX_OUTPUT_BYTES,
        };
        staged.configure(&mut spec);
        assert_eq!(spec.executable, POWERSHELL);
        assert_eq!(spec.args[5], "-File");
        let result = super::super::windows_runner::spawn(&spec);
        assert_eq!(result.outcome, "completed");
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "script");
        assert_eq!(String::from_utf8(result.stderr).unwrap().trim(), "stderr");
        let leftover = staged.directory.clone();
        staged.finish().unwrap();
        assert!(!leftover.exists());
        create_directory(&leftover).unwrap();
        drop(create_file(&leftover.join("script.ps1"), false).unwrap());
        let next = StagedScript::create(&state, "second", &script).unwrap();
        assert!(!leftover.exists());
        next.finish().unwrap();
        fs::remove_dir_all(state).unwrap();
    }
}
