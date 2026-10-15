//! Retire superseded startup mechanisms left by pre-native-service installs.
//!
//! Older agent releases started `serve` from a per-logon scheduled task named
//! `kw-agent-serve` (plus an HKCU Run fallback) via a `launch-serve.ps1`
//! launcher. The native service now owns the console worker, so those orphans
//! only compete for the serve port and keep files the MSI no longer ships.
//!
//! `service-configure` runs [`legacy_startup`] on every MSI install/upgrade
//! (deferred, SYSTEM), so an MSI-only update self-heals without the operator
//! re-running `install.ps1`. Nothing here touches enrollment or identity, and
//! every step is idempotent: a missing task, value or file is not an error.

use std::path::Path;

/// Scheduled tasks registered by superseded versions.
pub const LEGACY_TASKS: &[&str] = &["kw-agent-serve", "workspace-agent"];
/// HKCU Run value written by superseded versions.
pub const LEGACY_RUN_VALUE: &str = "kw-agent-serve";
/// Launcher scripts no longer shipped; removed with their scheduled task.
pub const LEGACY_FILES: &[&str] = &["launch-serve.ps1"];

/// Delete leftover launcher scripts the MSI does not own. Missing files are
/// not an error; returns the file names actually removed.
pub fn delete_legacy_files(dir: &Path) -> Result<Vec<String>, String> {
    let mut removed = Vec::new();
    for name in LEGACY_FILES {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push((*name).to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove {}: {error}", path.display())),
        }
    }
    Ok(removed)
}

/// Remove every legacy startup artifact and report each action taken. Used as
/// the MSI `service-configure` installer operation.
#[cfg(windows)]
pub fn legacy_startup(bin_dir: &Path) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    for task in LEGACY_TASKS {
        if delete_scheduled_task(task)? {
            actions.push(format!("removed scheduled task '{task}'"));
        }
    }
    let runs = remove_legacy_run_values()?;
    if runs > 0 {
        actions.push(format!(
            "removed Run value '{LEGACY_RUN_VALUE}' from {runs} hive(s)"
        ));
    }
    for name in delete_legacy_files(bin_dir)? {
        actions.push(format!("deleted leftover launcher '{name}'"));
    }
    Ok(actions)
}

/// Non-Windows builds have no scheduled tasks or Run values; still expose the
/// file cleanup so the logic is exercised by the cross-platform unit tests.
#[cfg(not(windows))]
pub fn legacy_startup(bin_dir: &Path) -> Result<Vec<String>, String> {
    delete_legacy_files(bin_dir)
}

/// Query then delete a scheduled task. `Ok(false)` when it never existed, so a
/// second MSI repair is a no-op rather than an error.
#[cfg(windows)]
fn delete_scheduled_task(name: &str) -> Result<bool, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    // CREATE_NO_WINDOW: a console window must never flash during install.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exists = Command::new("schtasks")
        .args(["/Query", "/TN", name])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("schtasks query '{name}': {error}"))?
        .success();
    if !exists {
        return Ok(false);
    }
    let removed = Command::new("schtasks")
        .args(["/Delete", "/TN", name, "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("schtasks delete '{name}': {error}"))?
        .success();
    if !removed {
        return Err(format!("could not remove scheduled task '{name}'"));
    }
    Ok(true)
}

/// Delete the legacy Run value from every loaded user hive. Logged-out profiles
/// are covered by the per-logon task removal above; leaving a stale value in an
/// unloaded NTUSER.DAT would require mounting it, which the installer does not
/// do to avoid corrupting profiles mid-install.
#[cfg(windows)]
fn remove_legacy_run_values() -> Result<usize, String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::System::Registry::*;
    let value = crate::windows_runtime::wide(LEGACY_RUN_VALUE);
    let mut removed = 0usize;
    unsafe {
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            if RegEnumKeyExW(
                HKEY_USERS,
                index,
                PWSTR(name.as_mut_ptr()),
                &mut len,
                None,
                PWSTR::null(),
                None,
                None,
            )
            .is_err()
            {
                break;
            }
            index += 1;
            let sid = String::from_utf16_lossy(&name[..len as usize]);
            // Skip the per-user class hives and any malformed entry.
            if sid.is_empty() || sid.ends_with("_Classes") {
                continue;
            }
            let sub = format!("{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            let sub = crate::windows_runtime::wide(&sub);
            let mut key = HKEY::default();
            if RegOpenKeyExW(
                HKEY_USERS,
                PCWSTR(sub.as_ptr()),
                0,
                KEY_SET_VALUE | KEY_QUERY_VALUE,
                &mut key,
            )
            .is_ok()
            {
                if RegDeleteValueW(key, PCWSTR(value.as_ptr())).is_ok() {
                    removed += 1;
                }
                let _ = RegCloseKey(key);
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_file_cleanup_is_idempotent_and_scoped() {
        let dir = std::env::temp_dir().join(format!("kw-retire-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let orphan = dir.join(LEGACY_FILES[0]);
        std::fs::write(&orphan, b"legacy").unwrap();
        // A shipped file must never be touched by the cleanup.
        let shipped = dir.join("Start-Serve.ps1");
        std::fs::write(&shipped, b"shipped").unwrap();

        let removed = delete_legacy_files(&dir).unwrap();
        assert_eq!(removed, vec![LEGACY_FILES[0].to_string()]);
        assert!(!orphan.exists());
        assert!(shipped.exists(), "MSI-owned files are not removed");
        // Second run: nothing left to remove, still not an error.
        assert!(delete_legacy_files(&dir).unwrap().is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg(not(windows))]
    fn legacy_startup_reports_file_actions() {
        // Windows uses the full task/Run path (which mutates the machine and is
        // covered by the native-service integration test); here only the file
        // cleanup is exercised off Windows.
        let dir = std::env::temp_dir().join(format!("kw-retire-actions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(LEGACY_FILES[0]), b"legacy").unwrap();
        let actions = legacy_startup(&dir).unwrap();
        assert!(
            actions.iter().any(|a| a.contains(LEGACY_FILES[0])),
            "file removal should be reported: {actions:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
