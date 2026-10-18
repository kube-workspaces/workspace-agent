//! Native Windows process/session boundary. All owned kernel objects use RAII;
//! the desktop worker gets a user token and no inherited SYSTEM handles.
use std::{
    fs::File,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
    sync::Arc,
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, WAIT_OBJECT_0},
        Security::{Authorization::*, *},
        System::{Console::*, Environment::*, JobObjects::*, RemoteDesktop::*, Threading::*},
    },
};

pub fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
pub struct Handle(pub HANDLE);
// Kernel handles may move between threads; each wrapper uniquely owns its handle.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct Environment(*mut std::ffi::c_void);
impl Drop for Environment {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyEnvironmentBlock(self.0);
        }
    }
}

struct Attributes {
    _storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn for_job(job: &Handle) -> Result<Self, String> {
        unsafe {
            let mut size = 0;
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST::default(),
                1,
                0,
                &mut size,
            );
            if size == 0 {
                return Err("process attribute size unavailable".into());
            }
            let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
            let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
            InitializeProcThreadAttributeList(list, 1, 0, &mut size).map_err(|e| e.to_string())?;
            let attributes = Self {
                _storage: storage,
                list,
            };
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some((&job.0 as *const HANDLE).cast()),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
            .map_err(|e| e.to_string())?;
            Ok(attributes)
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

pub fn redirect_logs(dir: &Path, prefix: &str) -> Result<Vec<File>, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    for (suffix, target) in [("log", STD_OUTPUT_HANDLE), ("error.log", STD_ERROR_HANDLE)] {
        let path = dir.join(format!("{prefix}.{suffix}"));
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > 10 * 1024 * 1024) {
            let _ = std::fs::rename(&path, path.with_extension("previous"));
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        unsafe {
            SetStdHandle(target, HANDLE(file.as_raw_handle() as isize))
                .map_err(|e| e.to_string())?;
        }
        files.push(file);
    }
    Ok(files)
}
pub fn background_logs(prefix: &str) -> Result<Vec<File>, String> {
    let local =
        std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing from user environment")?;
    redirect_logs(
        &std::path::PathBuf::from(local).join("workspace-agent"),
        prefix,
    )
}

fn with_descriptor<T>(
    sddl: &str,
    f: impl FnOnce(PSECURITY_DESCRIPTOR) -> windows::core::Result<T>,
) -> Result<T, String> {
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide(sddl).as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .map_err(|e| e.to_string())?;
        let result = f(descriptor);
        let _ = LocalFree(HLOCAL(descriptor.0));
        result.map_err(|e| e.to_string())
    }
}
fn directory_acl(path: &Path, sddl: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    with_descriptor(sddl, |descriptor| unsafe {
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut dacl = std::ptr::null_mut();
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)?;
        SetNamedSecurityInfoW(
            PCWSTR(wide(path).as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    })
}
pub fn protect_data(dir: &Path) -> Result<(), String> {
    directory_acl(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x20;;;BU)")?;
    directory_acl(
        &dir.join("public"),
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
    )
}

pub fn watch_stop(name: &str, stop: Arc<kw_transport::Shutdown>) -> Result<(), String> {
    if !name.starts_with("Global\\KubeWorkspaces.Agent.stop-v1.") {
        return Err("invalid local stop event name".into());
    }
    let handle = Handle(
        unsafe {
            OpenEventW(
                SYNCHRONIZATION_SYNCHRONIZE,
                false,
                PCWSTR(wide(name).as_ptr()),
            )
        }
        .map_err(|e| e.to_string())?,
    );
    std::thread::spawn(move || {
        let result = unsafe { WaitForSingleObject(handle.0, INFINITE) };
        // Capture the owning wrapper, not just its Copy HANDLE field (Rust's
        // disjoint closure capture would otherwise close the handle too soon).
        drop(handle);
        if result == WAIT_OBJECT_0 {
            stop.request();
        } else {
            eprintln!("worker stop event wait failed");
        }
    });
    Ok(())
}

pub fn console_session() -> Option<u32> {
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX || session == 0 {
        return None;
    }
    // Do not capture Winlogon/lock screens or keep broken duplication alive
    // across lock/unlock. Querying also handles service startup while locked.
    let mut buffer = PWSTR::null();
    let mut bytes = 0;
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        )
    }
    .is_err()
    {
        return None;
    }
    let eligible = unsafe {
        let eligible = if !buffer.is_null() && bytes as usize >= std::mem::size_of::<WTSINFOEXW>() {
            let info = &*buffer.0.cast::<WTSINFOEXW>();
            info.Level == 1
                && info.Data.WTSInfoExLevel1.SessionState == WTSActive
                && info.Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_UNLOCK as i32
        } else {
            false
        };
        WTSFreeMemory(buffer.0.cast());
        eligible
    };
    if !eligible {
        return None;
    }
    let mut token = HANDLE::default();
    if unsafe { WTSQueryUserToken(session, &mut token) }.is_err() {
        return None;
    }
    drop(Handle(token));
    Some(session)
}
fn token_sid(token: HANDLE) -> Result<String, String> {
    unsafe {
        let mut needed = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .map_err(|e| e.to_string())?;
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut text).map_err(|e| e.to_string())?;
        let sid = text.to_string().map_err(|e| e.to_string());
        let _ = LocalFree(HLOCAL(text.0.cast()));
        sid
    }
}
/// True when the current process token is LocalSystem (S-1-5-18). The
/// management-exec runner refuses to act as any other identity; a QGA
/// installation that runs the agent as a lesser user fails closed.
pub fn process_is_local_system() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let token = Handle(token);
        matches!(token_sid(token.0), Ok(sid) if sid == "S-1-5-18")
    }
}
fn user_token(session: u32) -> Result<Handle, String> {
    unsafe {
        let mut token = HANDLE::default();
        WTSQueryUserToken(session, &mut token).map_err(|e| e.to_string())?;
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION_TYPE::default();
        let mut needed = 0;
        GetTokenInformation(
            token.0,
            TokenElevationType,
            Some((&mut elevation as *mut TOKEN_ELEVATION_TYPE).cast()),
            std::mem::size_of_val(&elevation) as u32,
            &mut needed,
        )
        .map_err(|e| e.to_string())?;
        if elevation == TokenElevationTypeFull {
            let mut linked = TOKEN_LINKED_TOKEN::default();
            GetTokenInformation(
                token.0,
                TokenLinkedToken,
                Some((&mut linked as *mut TOKEN_LINKED_TOKEN).cast()),
                std::mem::size_of_val(&linked) as u32,
                &mut needed,
            )
            .map_err(|e| e.to_string())?;
            return Ok(Handle(linked.LinkedToken));
        }
        Ok(token)
    }
}

pub struct Worker {
    pub session: u32,
    pub pid: u32,
    pub started: std::time::Instant,
    process: Handle,
    job: Handle,
    stop: Handle,
}
impl Worker {
    pub fn spawn(
        session: u32,
        dir: &Path,
        config: &crate::service_config::Config,
    ) -> Result<Self, String> {
        unsafe {
            let token = user_token(session)?;
            let sid = token_sid(token.0)?;
            if ["S-1-5-18", "S-1-5-19", "S-1-5-20"].contains(&sid.as_str()) {
                return Err(
                    "desktop worker requires an interactive user, not a service account".into(),
                );
            }
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
            let name = format!(
                "Global\\KubeWorkspaces.Agent.stop-v1.{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let stop = with_descriptor(
                &format!("D:P(A;;GA;;;SY)(A;;0x00100000;;;{sid})"),
                |descriptor| {
                    let attrs = SECURITY_ATTRIBUTES {
                        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: descriptor.0,
                        bInheritHandle: false.into(),
                    };
                    CreateEventW(Some(&attrs), true, false, PCWSTR(wide(&name).as_ptr()))
                        .map(Handle)
                },
            )?;
            let job = Handle(CreateJobObjectW(None, PCWSTR::null()).map_err(|e| e.to_string())?);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
            .map_err(|e| e.to_string())?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut args = vec![
                exe.to_string_lossy().into_owned(),
                "serve".into(),
                "--data-dir".into(),
                dir.to_string_lossy().into_owned(),
                "--background".into(),
                "--stop-event".into(),
                name,
                "--bind".into(),
                "0.0.0.0".into(),
                "--port".into(),
                config.port.to_string(),
            ];
            args.extend(config.worker_args.clone());
            args.extend([
                "--log-label".into(),
                format!("worker-{}", crate::service::service_name()),
            ]);
            let command = args
                .iter()
                .map(|a| crate::service_config::quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            let mut command = wide(command);
            let attributes = Attributes::for_job(&job)?;
            let mut environment = std::ptr::null_mut();
            CreateEnvironmentBlock(&mut environment, token.0, false).map_err(|e| e.to_string())?;
            let environment = Environment(environment);
            let mut desktop = wide("winsta0\\default");
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                    lpDesktop: PWSTR(desktop.as_mut_ptr()),
                    ..Default::default()
                },
                lpAttributeList: attributes.list,
            };
            let mut process = PROCESS_INFORMATION::default();
            let created = CreateProcessAsUserW(
                token.0,
                PCWSTR(wide(&exe).as_ptr()),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                Some(environment.0),
                PCWSTR(wide(exe.parent().ok_or("executable parent missing")?).as_ptr()),
                &startup.StartupInfo,
                &mut process,
            );
            drop(environment);
            drop(attributes);
            created.map_err(|e| format!("create console worker: {e}"))?;
            let thread = Handle(process.hThread);
            let worker = Self {
                session,
                pid: process.dwProcessId,
                started: std::time::Instant::now(),
                process: Handle(process.hProcess),
                job,
                stop,
            };
            // Kernel assigns the job atomically at process creation, closing
            // the suspended-orphan window if the supervisor crashes mid-launch.
            if ResumeThread(thread.0) == u32::MAX {
                let _ = TerminateJobObject(worker.job.0, 1);
                return Err("resume worker failed".into());
            }
            Ok(worker)
        }
    }
    pub fn exited(&self) -> bool {
        unsafe { WaitForSingleObject(self.process.0, 0) == WAIT_OBJECT_0 }
    }
    /// Process exit code once the worker has exited; `None` if it is still
    /// running or the code is unavailable. Lets the supervisor distinguish a
    /// port-contention exit from an unexplained crash.
    pub fn exit_code(&self) -> Option<u32> {
        unsafe {
            let mut code = 0u32;
            GetExitCodeProcess(self.process.0, &mut code)
                .is_ok()
                .then_some(code)
        }
    }
    pub fn stop(&self) {
        unsafe {
            let _ = SetEvent(self.stop.0);
            if WaitForSingleObject(self.process.0, 10_000) != WAIT_OBJECT_0 {
                let _ = TerminateJobObject(self.job.0, 1);
                let _ = WaitForSingleObject(self.process.0, 2000);
            }
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_job_is_assigned_before_its_thread_can_run() {
        unsafe {
            let job = Handle(CreateJobObjectW(None, PCWSTR::null()).unwrap());
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
            .unwrap();
            let attributes = Attributes::for_job(&job).unwrap();
            let exe = std::env::current_exe().unwrap();
            // The child is this test binary in list-only mode, never a shell or
            // a desktop operation; its initial thread stays suspended throughout.
            let mut command = wide(format!(
                "{} --list",
                crate::service_config::quote(&exe.to_string_lossy())
            ));
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                    ..Default::default()
                },
                lpAttributeList: attributes.list,
            };
            let mut process = PROCESS_INFORMATION::default();
            CreateProcessW(
                PCWSTR(wide(&exe).as_ptr()),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &startup.StartupInfo,
                &mut process,
            )
            .unwrap();
            let child = Handle(process.hProcess);
            let _thread = Handle(process.hThread);
            let mut member = false.into();
            IsProcessInJob(child.0, job.0, &mut member).unwrap();
            assert!(member.as_bool());
            drop(attributes);
            drop(job);
            assert_eq!(
                WaitForSingleObject(child.0, 2000),
                WAIT_OBJECT_0,
                "closing the supervisor's job must kill even a suspended child"
            );
        }
    }

    #[test]
    fn stop_watcher_keeps_its_handle_alive_until_signaled() {
        let name = format!(
            "Global\\KubeWorkspaces.Agent.stop-v1.test-{}",
            std::process::id()
        );
        let event = Handle(
            unsafe { CreateEventW(None, true, false, PCWSTR(wide(&name).as_ptr())) }.unwrap(),
        );
        let shutdown = Arc::new(kw_transport::Shutdown::default());
        watch_stop(&name, shutdown.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !shutdown.requested(),
            "unsignaled event must not stop a worker"
        );
        unsafe {
            SetEvent(event.0).unwrap();
        }
        for _ in 0..100 {
            if shutdown.requested() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("signaled event did not request shutdown");
    }
}
