use super::{restricted_directory_sddl, KeyUnavailable, MachinePath};
use std::{
    fs::File,
    os::windows::io::{AsRawHandle, FromRawHandle},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{LocalFree, HANDLE, HLOCAL},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
    },
};

struct Local(HLOCAL);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: Local is the unique owner of a LocalAlloc-family result from
        // the security-descriptor APIs used below.
        unsafe {
            let _ = LocalFree(self.0);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    volume: u32,
    index: u64,
}
struct Pinned {
    file: File,
    identity: Identity,
    path: String,
}
pub(super) struct Directory {
    chain: Vec<Pinned>,
}
fn handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle() as isize)
}
fn metadata(file: &File) -> Result<Identity, KeyUnavailable> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the borrowed File keeps the handle alive and info is writable.
    unsafe {
        if GetFileType(handle(file)) != FILE_TYPE_DISK {
            return Err(KeyUnavailable);
        }
        GetFileInformationByHandle(handle(file), &mut info).map_err(|_| KeyUnavailable)?;
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(KeyUnavailable);
    }
    Ok(Identity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}
fn final_path(file: &File, expected: &str) -> Result<(), KeyUnavailable> {
    let mut buffer = [0; 512];
    // SAFETY: buffer is live/writable and the borrowed handle remains open.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            handle(file),
            &mut buffer,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
        )
    } as usize;
    if count == 0 || count >= buffer.len() {
        return Err(KeyUnavailable);
    }
    let actual = String::from_utf16(&buffer[..count]).map_err(|_| KeyUnavailable)?;
    if !actual.eq_ignore_ascii_case(&format!(r"\\?\{expected}")) {
        return Err(KeyUnavailable);
    }
    Ok(())
}
fn filesystem(file: &File) -> Result<(), KeyUnavailable> {
    let mut name = [0; 32];
    let mut flags = 0;
    // SAFETY: both output buffers are live and the borrowed handle stays open.
    unsafe {
        GetVolumeInformationByHandleW(
            handle(file),
            None,
            None,
            None,
            Some(&mut flags),
            Some(&mut name),
        )
        .map_err(|_| KeyUnavailable)?;
    }
    let end = name.iter().position(|c| *c == 0).ok_or(KeyUnavailable)?;
    // Deliberately support local NTFS only in this preflight. FILE_PERSISTENT_ACLS
    // is 0x8; no claim of ReFS, FAT, remote or third-party filesystem protection.
    if String::from_utf16(&name[..end]).map_err(|_| KeyUnavailable)? != "NTFS" || flags & 0x8 == 0 {
        return Err(KeyUnavailable);
    }
    Ok(())
}
fn acl(file: &File) -> Result<(), KeyUnavailable> {
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: GetSecurityInfo allocates the descriptor for this live handle;
    // Local owns the returned allocation and releases it on every later exit.
    unsafe {
        GetSecurityInfo(
            handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut raw),
        )
        .map_err(|_| KeyUnavailable)?;
        let _descriptor = Local(HLOCAL(raw.0));
        let mut control = 0;
        let mut revision = 0;
        GetSecurityDescriptorControl(raw, &mut control, &mut revision)
            .map_err(|_| KeyUnavailable)?;
        if control & SE_DACL_PROTECTED.0 == 0 {
            return Err(KeyUnavailable);
        }
        let mut text = PWSTR::null();
        let mut count = 0;
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            raw,
            1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            Some(&mut count),
        )
        .map_err(|_| KeyUnavailable)?;
        let _text = Local(HLOCAL(text.0.cast()));
        if count == 0 || count > 512 {
            return Err(KeyUnavailable);
        }
        let text = text.to_string().map_err(|_| KeyUnavailable)?;
        if !restricted_directory_sddl(&text) {
            return Err(KeyUnavailable);
        }
    }
    Ok(())
}
impl Directory {
    pub(super) fn open(path: &MachinePath) -> Result<Self, KeyUnavailable> {
        let mut current = path.0[..3].to_owned();
        let mut prefixes = vec![current.clone()];
        for component in path.0[3..].split('\\') {
            if !current.ends_with('\\') {
                current.push('\\');
            }
            current.push_str(component);
            prefixes.push(current.clone());
        }
        let mut chain = Vec::with_capacity(prefixes.len());
        for path in prefixes {
            let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
            // SAFETY: the path is validated ASCII/NUL-free and NUL-terminated;
            // CreateFileW returns a fresh owned handle. OPEN_REPARSE_POINT stops
            // final-component following; each ancestor is inspected separately.
            let file = unsafe {
                let raw = CreateFileW(
                    PCWSTR(name.as_ptr()),
                    // Attribute-only opens do not participate in Windows share
                    // checks. Directory-read access makes no-delete sharing an
                    // effective rename/delete fence without requesting writes.
                    FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
                .map_err(|_| KeyUnavailable)?;
                File::from_raw_handle(raw.0 as *mut std::ffi::c_void)
            };
            // No FILE_SHARE_DELETE: every opened ancestor stays pinned against
            // rename/delete until the probe drops. This is not an ancestor ACL
            // authority policy, and is insufficient to enable credential storage.
            let identity = metadata(&file)?;
            final_path(&file, &path)?;
            chain.push(Pinned {
                file,
                identity,
                path,
            });
        }
        let directory = Self { chain };
        directory.check()?;
        Ok(directory)
    }
    pub(super) fn check(&self) -> Result<(), KeyUnavailable> {
        let root = self.chain.first().ok_or(KeyUnavailable)?;
        let drive: Vec<u16> = root.path.encode_utf16().chain(Some(0)).collect();
        // SAFETY: drive is a live NUL-terminated root path. DRIVE_FIXED is 3;
        // mapped remote, removable, unknown and device drives fail closed.
        if unsafe { GetDriveTypeW(PCWSTR(drive.as_ptr())) } != 3 {
            return Err(KeyUnavailable);
        }
        let leaf = self.chain.last().ok_or(KeyUnavailable)?;
        for item in &self.chain {
            if metadata(&item.file)? != item.identity
                || item.identity.volume != leaf.identity.volume
            {
                return Err(KeyUnavailable);
            }
            final_path(&item.file, &item.path)?;
        }
        filesystem(&leaf.file)?;
        acl(&leaf.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            Self(base.join(format!("kw-directory-probe-{suffix}")))
        }
        fn path(&self) -> MachinePath {
            let text = self
                .0
                .to_str()
                .unwrap()
                .strip_prefix(r"\\?\")
                .unwrap_or(self.0.to_str().unwrap());
            MachinePath::parse(text).unwrap()
        }
        fn create(&self, sddl: &str) {
            let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let name: Vec<u16> = self.0.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut raw = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(text.as_ptr()),
                    1,
                    &mut raw,
                    None,
                )
                .unwrap();
                let _descriptor = Local(HLOCAL(raw.0));
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: raw.0,
                    bInheritHandle: false.into(),
                };
                CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)).unwrap();
            }
        }
        fn set_acl(&self, sddl: &str) {
            use windows::Win32::Foundation::{BOOL, PSID};
            let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let name: Vec<u16> = self.0.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut raw = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(text.as_ptr()),
                    1,
                    &mut raw,
                    None,
                )
                .unwrap();
                let _descriptor = Local(HLOCAL(raw.0));
                let mut present = BOOL::default();
                let mut defaulted = BOOL::default();
                let mut dacl = std::ptr::null_mut();
                GetSecurityDescriptorDacl(raw, &mut present, &mut dacl, &mut defaulted).unwrap();
                assert!(present.as_bool());
                let mut control = 0;
                let mut revision = 0;
                GetSecurityDescriptorControl(raw, &mut control, &mut revision).unwrap();
                let protection = if control & SE_DACL_PROTECTED.0 != 0 {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_DACL_SECURITY_INFORMATION
                };
                SetNamedSecurityInfoW(
                    PCWSTR(name.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | protection,
                    PSID::default(),
                    PSID::default(),
                    Some(dacl),
                    None,
                )
                .unwrap();
            }
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    use std::os::windows::ffi::OsStrExt;

    #[test]
    fn protected_directory_probe_is_read_only_and_pins_rename() {
        let temp = Temp::new();
        temp.create("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let mut probe = super::super::DirectoryProbe::open(&temp.path()).unwrap();
        probe.recheck().unwrap();
        let guest = crate::identity::Identity::from_uri(
            "spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid/gen/1",
        )
        .unwrap();
        assert!(crate::credentials::MachineKey::initialize(&temp.0, &guest).is_err());
        assert!(crate::credentials::MachineKey::reopen(&temp.0, &guest).is_err());
        assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
        assert_eq!(
            format!("{probe:?}"),
            "Windows directory probe (path and handles redacted)"
        );
        let renamed = temp.0.with_extension("renamed");
        assert!(fs::rename(&temp.0, &renamed).is_err());
        drop(probe);
        fs::rename(&temp.0, &renamed).unwrap();
        fs::rename(&renamed, &temp.0).unwrap();
    }
    #[test]
    fn broader_or_unprotected_acl_is_never_adopted_or_repaired() {
        for (case, sddl) in [
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)",
            "O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:BAG:BAD:PNO_ACCESS_CONTROL",
        ]
        .into_iter()
        .enumerate()
        {
            let temp = Temp::new();
            temp.create(sddl);
            // Establish the actual descriptor after Windows creation/inheritance
            // normalization, rather than assuming the input SDDL survives it.
            temp.set_acl(sddl);
            assert!(
                super::super::DirectoryProbe::open(&temp.path()).is_err(),
                "ACL denial case {case}"
            );
            assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
        }
    }
    #[test]
    fn live_descriptor_weakening_permanently_poisons_the_probe() {
        let strict = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        let temp = Temp::new();
        temp.create(strict);
        let mut probe = super::super::DirectoryProbe::open(&temp.path()).unwrap();
        temp.set_acl("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)");
        assert!(probe.recheck().is_err());
        temp.set_acl(strict);
        assert!(probe.recheck().is_err());
        drop(probe);
        assert!(super::super::DirectoryProbe::open(&temp.path()).is_ok());
    }
    #[test]
    fn files_are_not_adopted_as_directories() {
        let temp = Temp::new();
        fs::write(&temp.0, b"unchanged public marker").unwrap();
        assert!(super::super::DirectoryProbe::open(&temp.path()).is_err());
        assert_eq!(fs::read(&temp.0).unwrap(), b"unchanged public marker");
        fs::remove_file(&temp.0).unwrap();
    }
}
