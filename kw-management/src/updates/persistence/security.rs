use super::Error;
use std::{fs, path::Path};

/// Create a new dedicated root under an already provisioned trusted parent.
/// Existing roots (even empty ones) are never adopted or chmod/ACL-repaired.
pub fn create_root(path: &Path) -> Result<(), Error> {
    check_parents(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(super::io_error)?;
    }
    #[cfg(windows)]
    native::create_directory(path)?;
    check_root(path)
}

fn check_parents(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::Persistence);
    }
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(Error::Persistence);
        }
        #[cfg(windows)]
        match component {
            std::path::Component::Prefix(prefix) => {
                if !matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ) {
                    return Err(Error::Persistence);
                }
            }
            std::path::Component::Normal(name) => {
                use std::os::windows::ffi::OsStrExt;
                let name: Vec<u16> = name.encode_wide().collect();
                if name.iter().any(|c| *c == 0 || *c == u16::from(b':'))
                    || name
                        .last()
                        .is_some_and(|c| *c == u16::from(b'.') || *c == u16::from(b' '))
                {
                    return Err(Error::Persistence);
                }
            }
            _ => {}
        }
    }
    let mut parent = path.parent();
    while let Some(path) = parent {
        if !path.as_os_str().is_empty() {
            let metadata = fs::symlink_metadata(path).map_err(super::io_error)?;
            if !metadata.is_dir() || redirected(&metadata) {
                return Err(Error::Persistence);
            }
        }
        parent = path.parent();
    }
    Ok(())
}

pub(super) fn check_root(path: &Path) -> Result<(), Error> {
    check_parents(path)?;
    check(path, true)
}

pub(super) fn check_file(path: &Path) -> Result<(), Error> {
    check(path, false)
}

fn check(path: &Path, directory: bool) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(super::io_error)?;
    if redirected(&metadata)
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(Error::Persistence);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || (!directory && metadata.nlink() != 1) {
            return Err(Error::Persistence);
        }
    }
    #[cfg(windows)]
    {
        native::check_acl(path)?;
        if !directory {
            native::check_links(path)?;
        }
    }
    Ok(())
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(unix)]
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
pub(super) fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
pub(super) mod native {
    use super::{wide, Error};
    use std::{
        fs::File,
        os::windows::io::{AsRawHandle, FromRawHandle},
        path::Path,
    };
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{LocalFree, HANDLE, HLOCAL},
            Security::{Authorization::*, *},
            Storage::FileSystem::*,
        },
    };

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(HLOCAL(self.0 .0));
            }
        }
    }

    fn descriptor(directory: bool) -> Result<Descriptor, Error> {
        let sddl = if directory {
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        } else {
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        };
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                1,
                &mut raw,
                None,
            )
            .map_err(|_| Error::Persistence)?;
        }
        Ok(Descriptor(raw))
    }

    pub(super) fn create_directory(path: &Path) -> Result<(), Error> {
        let descriptor = descriptor(true)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        unsafe {
            CreateDirectoryW(PCWSTR(wide(path).as_ptr()), Some(&attributes))
                .map_err(|_| Error::Persistence)
        }
    }

    pub(crate) fn create_file(path: &Path) -> Result<File, Error> {
        let descriptor = descriptor(false)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        unsafe {
            let handle = CreateFileW(
                PCWSTR(wide(path).as_ptr()),
                0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                Some(&attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .map_err(|_| Error::Persistence)?;
            Ok(File::from_raw_handle(handle.0 as *mut std::ffi::c_void))
        }
    }

    pub(super) fn check_acl(path: &Path) -> Result<(), Error> {
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
            .map_err(|_| Error::Persistence)?;
            let descriptor = Descriptor(raw);
            let mut text = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
            .map_err(|_| Error::Persistence)?;
            let result = text.to_string().map_err(|_| Error::Persistence);
            let _ = LocalFree(HLOCAL(text.0.cast()));
            let text = result?;
            // Accept only our exact protected descriptors. This deliberately
            // rejects inherited, extra, NULL, or caller-weakened ACLs/owners.
            if ![
                "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
                "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
            ]
            .contains(&text.as_str())
            {
                return Err(Error::Persistence);
            }
        }
        Ok(())
    }

    pub(super) fn check_links(path: &Path) -> Result<(), Error> {
        let file = File::open(path).map_err(super::super::io_error)?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe {
            GetFileInformationByHandle(HANDLE(file.as_raw_handle() as isize), &mut info)
                .map_err(|_| Error::Persistence)?;
        }
        if info.nNumberOfLinks != 1 {
            return Err(Error::Persistence);
        }
        Ok(())
    }
}
