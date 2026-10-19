//! Native MSI adapter for a dedicated updater process. Owns process-global MSI
//! UI state exclusively; do not embed alongside other MSI UI clients. No remote
//! endpoint, permissive phase-authority implementation or service launch exists.

use super::{valid_directory, Error, MsiAdapter, Observation, Package, Product, Transaction};
use crate::updates::persistence::security;
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::*,
        Storage::FileSystem::*,
        System::{ApplicationInstallationAndServicing::*, Registry::*, Threading::*},
    },
};

#[cfg(test)]
mod tests;

static MSI_OWNER: Mutex<()> = Mutex::new(());
const MAX_TEXT: usize = 4096;
const EVIDENCE_BUDGET: usize = 32 * 1024 * 1024;

/// Acknowledged, protected evidence sink, shared with the attempt's recording
/// budget. Callback text is installer content and must not enter metadata logs.
/// On failure the adapter lets MSI reach its safe boundary and reports loss.
pub trait Evidence: Send {
    fn append(&mut self, kind: u32, text: &str) -> Result<(), Error>;
    fn recording_lost(&mut self);
}

pub struct WindowsMsi<'a> {
    _owner: MutexGuard<'static, ()>,
    _directories: Vec<File>,
    target: Pinned,
    previous: Pinned,
    upgrade_code: String,
    evidence: &'a mut dyn Evidence,
    remaining: usize,
    recording_failed: bool,
}

struct Pinned {
    _file: File,
    path: PathBuf,
    package: Package,
}

impl Transaction {
    /// root/target and root/previous must be protected staging directories under
    /// trusted machine-provisioned parents, outside the MSI replacement tree.
    /// Both payloads are pinned against writes/deletion for this adapter lifetime.
    pub fn windows_adapter<'a>(
        &self,
        root: &Path,
        evidence: &'a mut dyn Evidence,
    ) -> Result<WindowsMsi<'a>, Error> {
        WindowsMsi::open(
            root,
            &self.target,
            &self.previous,
            super::super::AGENT_UPGRADE_CODE,
            evidence,
        )
    }
}

impl<'a> WindowsMsi<'a> {
    fn open(
        root: &Path,
        target: &Package,
        previous: &Package,
        upgrade_code: &str,
        evidence: &'a mut dyn Evidence,
    ) -> Result<Self, Error> {
        let owner = MSI_OWNER.try_lock().map_err(|_| Error::Busy)?;
        let mut directories = Vec::new();
        for dir in [root.to_owned(), root.join("target"), root.join("previous")] {
            security::check_root(&dir).map_err(|_| Error::Package)?;
            // Deny parent-directory rename while MSI consumes the pinned paths.
            directories.push(
                OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ.0)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
                    .open(&dir)
                    .map_err(|_| Error::Package)?,
            );
        }
        let target = Pinned::open(&root.join("target"), target, upgrade_code)?;
        let previous = Pinned::open(&root.join("previous"), previous, upgrade_code)?;
        Ok(Self {
            _owner: owner,
            _directories: directories,
            target,
            previous,
            upgrade_code: upgrade_code.into(),
            evidence,
            remaining: EVIDENCE_BUDGET,
            recording_failed: false,
        })
    }

    fn pinned(&self, package: &Package) -> Result<&Pinned, Error> {
        [&self.target, &self.previous]
            .into_iter()
            .find(|p| same_package(&p.package, package))
            .ok_or(Error::Package)
    }

    fn run(&mut self, kind: u32, operation: impl FnOnce() -> u32) -> Result<u32, Error> {
        // This synchronous acknowledgment happens before MSI is called. No log
        // file or unbounded stdout stream can bypass the evidence sink budget.
        if self.recording_failed {
            return Err(Error::Recording);
        }
        let callback = Mutex::new(Callback {
            evidence: self.evidence,
            remaining: &mut self.remaining,
            lost: false,
        });
        if callback
            .lock()
            .map_err(|_| Error::Recording)?
            .append(kind, "msi_begin")
            .is_err()
        {
            self.recording_failed = true;
            callback
                .lock()
                .map_err(|_| Error::Recording)?
                .evidence
                .recording_lost();
            return Err(Error::Recording);
        }
        let ui = unsafe {
            let previous = MsiSetInternalUI(INSTALLUILEVEL_NONE, None);
            MsiSetExternalUIW(
                Some(message),
                0x7fff,
                Some((&callback as *const Mutex<Callback<'_>>).cast()),
            );
            Ui(previous)
        };
        let code = operation();
        drop(ui); // Remove callback before its borrowed context goes out of scope.
        let mut callback = callback.into_inner().map_err(|_| Error::Recording)?;
        if callback.lost {
            self.recording_failed = true;
            callback.evidence.recording_lost();
            return Err(Error::Recording);
        }
        callback
            .append(kind, &format!("msi_result:{code}"))
            .map_err(|_| {
                self.recording_failed = true;
                callback.evidence.recording_lost();
                Error::Recording
            })?;
        Ok(code)
    }
}

impl MsiAdapter for WindowsMsi<'_> {
    fn observe(&mut self) -> Result<Observation, Error> {
        observe(&self.upgrade_code)
    }

    fn verify_package(&mut self, package: &Package) -> Result<(), Error> {
        self.pinned(package).map(|_| ()) // Pinned and rehashed by open; cannot mutate.
    }

    fn install(&mut self, package: &Package, directory: &str) -> Result<u32, Error> {
        if !valid_directory(directory) {
            return Err(Error::Binding);
        }
        let path = wide(self.pinned(package)?.path.as_os_str());
        // MSI properties, not shell argv. Quotes/controls/alternate streams in
        // the recorded directory were rejected; no caller-defined properties.
        let properties = wide(format!(
            "ALLUSERS=1 REBOOT=ReallySuppress INSTALLDIR=\"{directory}\""
        ));
        self.run(1, || unsafe {
            MsiInstallProductW(PCWSTR(path.as_ptr()), PCWSTR(properties.as_ptr()))
        })
    }

    fn uninstall(&mut self, product: &Product) -> Result<u32, Error> {
        // Even direct adapter calls cannot remove the predecessor/foreign code.
        if product.product_code != self.target.package.product_code
            || product.upgrade_code != self.upgrade_code
            || product.version != self.target.package.version
            || !valid_directory(&product.install_directory)
        {
            return Err(Error::Binding);
        }
        let current = self.observe()?;
        if current.installer_busy {
            return Err(Error::Busy);
        }
        if current.reboot_pending {
            return Err(Error::RebootPending);
        }
        if current.products != [product.clone()] {
            return Err(Error::Inventory);
        }
        let code = wide(braced(&product.product_code));
        self.run(2, || unsafe {
            MsiConfigureProductExW(
                PCWSTR(code.as_ptr()),
                INSTALLLEVEL_DEFAULT,
                INSTALLSTATE_ABSENT,
                windows::core::w!("REBOOT=ReallySuppress"),
            )
        })
    }
}

impl Pinned {
    fn open(dir: &Path, package: &Package, upgrade_code: &str) -> Result<Self, Error> {
        let path = dir.join(&package.file);
        security::check_file(&path).map_err(|_| Error::Package)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&path)
            .map_err(|_| Error::Package)?;
        security::check_file(&path).map_err(|_| Error::Package)?;
        let mut reader = (&file).take(package.size + 1);
        let mut hash = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let n = reader.read(&mut buffer).map_err(|_| Error::Package)?;
            if n == 0 {
                break;
            }
            length += n as u64;
            hash.update(&buffer[..n]);
        }
        let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if length != package.size || digest != package.sha256 {
            return Err(Error::Package);
        }
        inspect_package(&path, package, upgrade_code)?;
        Ok(Self {
            _file: file,
            path,
            package: Package {
                file: package.file.clone(),
                sha256: package.sha256.clone(),
                size: package.size,
                product_code: package.product_code.clone(),
                version: package.version.clone(),
            },
        })
    }
}

fn same_package(a: &Package, b: &Package) -> bool {
    a.file == b.file
        && a.sha256 == b.sha256
        && a.size == b.size
        && a.product_code == b.product_code
        && a.version == b.version
}

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn braced(guid: &str) -> String {
    format!("{{{guid}}}")
}
fn guid(value: &str) -> Result<String, Error> {
    let value = value
        .strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .unwrap_or(value)
        .to_ascii_lowercase();
    if !super::super::valid_guid(&value) {
        return Err(Error::Inventory);
    }
    Ok(value)
}

struct MsiHandle(MSIHANDLE);
impl Drop for MsiHandle {
    fn drop(&mut self) {
        unsafe {
            MsiCloseHandle(self.0);
        }
    }
}

fn database(path: &Path) -> Result<MsiHandle, Error> {
    let mut handle = MSIHANDLE::default();
    let path = wide(path);
    if unsafe { MsiOpenDatabaseW(PCWSTR(path.as_ptr()), PCWSTR::null(), &mut handle) } != 0 {
        return Err(Error::Package);
    }
    Ok(MsiHandle(handle))
}

fn query(db: &MsiHandle, sql: &str) -> Result<Vec<Vec<String>>, Error> {
    let sql = wide(sql);
    let mut view = MSIHANDLE::default();
    if unsafe { MsiDatabaseOpenViewW(db.0, PCWSTR(sql.as_ptr()), &mut view) } != 0 {
        return Err(Error::Package);
    }
    let view = MsiHandle(view);
    if unsafe { MsiViewExecute(view.0, MSIHANDLE::default()) } != 0 {
        return Err(Error::Package);
    }
    let mut rows = Vec::new();
    loop {
        let mut record = MSIHANDLE::default();
        let code = unsafe { MsiViewFetch(view.0, &mut record) };
        if code == ERROR_NO_MORE_ITEMS.0 {
            break;
        }
        if code != 0 || rows.len() >= 1024 {
            return Err(Error::Package);
        }
        let record = MsiHandle(record);
        let count = unsafe { MsiRecordGetFieldCount(record.0) };
        if count != 1 {
            return Err(Error::Package);
        }
        let mut fields = Vec::new();
        for field in 1..=count {
            let mut raw = [0; MAX_TEXT + 1];
            let mut len = MAX_TEXT as u32 + 1;
            if unsafe {
                MsiRecordGetStringW(record.0, field, PWSTR(raw.as_mut_ptr()), Some(&mut len))
            } != 0
                || len as usize > MAX_TEXT
            {
                return Err(Error::Package);
            }
            fields.push(String::from_utf16(&raw[..len as usize]).map_err(|_| Error::Package)?);
        }
        rows.push(fields);
    }
    Ok(rows)
}

fn property(db: &MsiHandle, name: &str) -> Result<String, Error> {
    // Only fixed internal property names reach this function.
    let rows = query(
        db,
        &format!("SELECT `Value` FROM `Property` WHERE `Property`='{name}'"),
    )?;
    if rows.len() != 1 {
        return Err(Error::Package);
    }
    Ok(rows[0][0].clone())
}

fn inspect_package(path: &Path, package: &Package, upgrade_code: &str) -> Result<(), Error> {
    let db = database(path)?;
    if guid(&property(&db, "ProductCode")?).map_err(|_| Error::Package)? != package.product_code
        || guid(&property(&db, "UpgradeCode")?).map_err(|_| Error::Package)? != upgrade_code
        || property(&db, "ProductVersion")? != package.version
        || property(&db, "ALLUSERS")? != "1"
    {
        return Err(Error::Package);
    }
    let mut summary = MSIHANDLE::default();
    if unsafe { MsiGetSummaryInformationW(db.0, PCWSTR::null(), 0, &mut summary) } != 0 {
        return Err(Error::Package);
    }
    let summary = MsiHandle(summary);
    let mut kind = 0;
    let mut number = 0;
    let mut raw = [0; MAX_TEXT + 1];
    let mut len = raw.len() as u32;
    if unsafe {
        MsiSummaryInfoGetPropertyW(
            summary.0,
            7,
            &mut kind,
            &mut number,
            None,
            PWSTR(raw.as_mut_ptr()),
            Some(&mut len),
        )
    } != 0
        || len as usize > MAX_TEXT
    {
        return Err(Error::Package);
    }
    let template = String::from_utf16(&raw[..len as usize]).map_err(|_| Error::Package)?;
    if kind != 30 || template.split(';').next() != Some("x64") {
        return Err(Error::Package);
    }
    len = raw.len() as u32;
    if unsafe {
        MsiSummaryInfoGetPropertyW(
            summary.0,
            15,
            &mut kind,
            &mut number,
            None,
            PWSTR(raw.as_mut_ptr()),
            Some(&mut len),
        )
    } != 0
        || kind != 3
        || number & 2 == 0
    {
        return Err(Error::Package);
    }
    // The signed MSI must contain its payload. External CAB/uncompressed source
    // files would otherwise bypass the publisher's artifact digest boundary.
    let media = query(&db, "SELECT `Cabinet` FROM `Media`")?;
    if media.is_empty()
        || media
            .iter()
            .any(|r| !r[0].starts_with('#') || r[0].len() < 2)
    {
        return Err(Error::Package);
    }
    let files = query(&db, "SELECT `Attributes` FROM `File`")?;
    if files.is_empty()
        || files
            .iter()
            .any(|r| !r[0].is_empty() && r[0].parse::<u32>().map_or(true, |v| v & 8192 != 0))
    {
        return Err(Error::Package);
    }
    Ok(())
}

fn installed_property(code: &str, property: &str) -> Result<String, Error> {
    let code = wide(braced(code));
    let property = wide(property);
    let mut raw = [0; MAX_TEXT + 1];
    let mut len = raw.len() as u32;
    if unsafe {
        MsiGetProductInfoExW(
            PCWSTR(code.as_ptr()),
            PCWSTR::null(),
            MSIINSTALLCONTEXT_MACHINE,
            PCWSTR(property.as_ptr()),
            PWSTR(raw.as_mut_ptr()),
            Some(&mut len),
        )
    } != 0
        || len as usize > MAX_TEXT
    {
        return Err(Error::Inventory);
    }
    String::from_utf16(&raw[..len as usize]).map_err(|_| Error::Inventory)
}

fn observe(upgrade_code: &str) -> Result<Observation, Error> {
    let mut products = Vec::new();
    let upgrade = wide(braced(upgrade_code));
    for index in 0..=16 {
        let mut code = [0; 39];
        let status = unsafe {
            MsiEnumRelatedProductsW(PCWSTR(upgrade.as_ptr()), 0, index, PWSTR(code.as_mut_ptr()))
        };
        if status == ERROR_NO_MORE_ITEMS.0 {
            break;
        }
        if status != 0 || index == 16 {
            return Err(Error::Inventory);
        }
        let len = code.iter().position(|c| *c == 0).ok_or(Error::Inventory)?;
        let code = guid(&String::from_utf16(&code[..len]).map_err(|_| Error::Inventory)?)?;
        if installed_property(&code, "State")? != "5" {
            return Err(Error::Inventory);
        }
        let version = installed_property(&code, "VersionString")?;
        let install_directory = installed_property(&code, "InstallLocation")?;
        if super::super::version(&version, 3).is_none() || !valid_directory(&install_directory) {
            return Err(Error::Inventory);
        }
        products.push(Product {
            product_code: code,
            upgrade_code: upgrade_code.into(),
            version,
            install_directory,
        });
    }
    Ok(Observation {
        products,
        installer_busy: installer_busy()?,
        reboot_pending: reboot_pending()?,
    })
}

fn installer_busy() -> Result<bool, Error> {
    if registry_exists(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress",
        None,
    )? {
        return Ok(true);
    }
    unsafe {
        let handle = match OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE | MUTEX_MODIFY_STATE,
            false,
            windows::core::w!("Global\\_MSIExecute"),
        ) {
            Ok(handle) => handle,
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
                return Ok(false)
            }
            Err(_) => return Err(Error::Inventory),
        };
        let wait = WaitForSingleObject(handle, 0);
        let result = if wait == WAIT_TIMEOUT {
            Ok(true)
        } else if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            ReleaseMutex(handle)
                .map(|_| false)
                .map_err(|_| Error::Inventory)
        } else {
            Err(Error::Inventory)
        };
        let _ = CloseHandle(handle);
        result
    }
}

fn registry_exists(path: &str, value: Option<&str>) -> Result<bool, Error> {
    let path = wide(path);
    let mut key = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if let Err(error) = status {
        return if missing_key(&error) {
            Ok(false)
        } else {
            Err(Error::Inventory)
        };
    }
    let result = if let Some(value) = value {
        let value = wide(value);
        let status =
            unsafe { RegQueryValueExW(key, PCWSTR(value.as_ptr()), None, None, None, None) };
        match status {
            Ok(()) => Ok(true),
            Err(error) if missing_key(&error) => Ok(false),
            Err(_) => Err(Error::Inventory),
        }
    } else {
        Ok(true)
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    result
}

fn missing_key(error: &windows::core::Error) -> bool {
    [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND]
        .iter()
        .any(|code| error.code() == windows::core::HRESULT::from_win32(code.0))
}

fn reboot_pending() -> Result<bool, Error> {
    for (key, value) in [
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            None,
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            None,
        ),
        (
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            Some("PendingFileRenameOperations"),
        ),
    ] {
        if registry_exists(key, value)? {
            return Ok(true);
        }
    }
    Ok(false)
}

struct Ui(INSTALLUILEVEL);
impl Drop for Ui {
    fn drop(&mut self) {
        unsafe {
            MsiSetExternalUIW(None, 0, None);
            MsiSetInternalUI(self.0, None);
        }
    }
}

struct Callback<'a> {
    evidence: &'a mut dyn Evidence,
    remaining: &'a mut usize,
    lost: bool,
}
impl Callback<'_> {
    fn append(&mut self, kind: u32, text: &str) -> Result<(), Error> {
        let size = text.len() + 64;
        if size > *self.remaining {
            return Err(Error::Recording);
        }
        *self.remaining -= size;
        self.evidence.append(kind, text)
    }
}
unsafe extern "system" fn message(context: *mut c_void, kind: u32, text: PCWSTR) -> i32 {
    // MSI may deliver messages through different native threads. Serialize the
    // borrowed recording sink; never form concurrent mutable raw references.
    let mutex = &*context.cast::<Mutex<Callback<'_>>>();
    let mut context = mutex.lock().unwrap_or_else(|error| error.into_inner());
    if context.lost {
        return 0;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Initialize/terminate notifications legitimately carry no text.
        if text.is_null() {
            return context.append(kind, "");
        }
        let mut len = 0;
        while len <= MAX_TEXT && *text.0.add(len) != 0 {
            len += 1;
        }
        if len > MAX_TEXT {
            return Err(Error::Recording);
        }
        let text = String::from_utf16(std::slice::from_raw_parts(text.0, len))
            .map_err(|_| Error::Recording)?;
        context.append(kind, &text)
    }));
    if !matches!(result, Ok(Ok(()))) {
        context.lost = true;
    }
    // Never return IDCANCEL/IDABORT or kill MSI when recording is lost.
    0
}
