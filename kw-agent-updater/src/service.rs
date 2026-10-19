//! Own-process, Session-0 SCM host. Shutdown drops read-only recovery state;
//! this slice never dispatches an installer, reboots or launches a child.

use kw_management::updates::lifetime::{
    self, LaunchBinding, RecoveryAuthority, RuntimeStatus, UnavailableAuthority,
};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{mpsc, Mutex, OnceLock},
    time::Duration,
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        System::{Com::CoTaskMemFree, Services::SetServiceObjectSecurity, Threading::*},
        UI::Shell::*,
    },
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const NAME: &str = "KubeWorkspacesAgentUpdater";

pub struct Config {
    pub name: String,
    pub root: PathBuf,
}
struct Host {
    config: Config,
    authority: Box<dyn RecoveryAuthority>,
}
static HOST: OnceLock<Mutex<Option<Host>>> = OnceLock::new();
define_windows_service!(service_entry, entry);

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn dispatch_default() -> Result<(), String> {
    let image = std::env::current_exe().map_err(|_| "helper image unavailable")?;
    let root = image
        .parent()
        .ok_or("helper image directory unavailable")?
        .to_owned();
    let base = unsafe {
        let path = SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, HANDLE::default())
            .map_err(|_| "machine data directory unavailable")?;
        let value = path.to_string().map_err(|_| "machine data path invalid");
        CoTaskMemFree(Some(path.0.cast()));
        PathBuf::from(value?)
            .join("workspace-agent")
            .join("updates")
    };
    if root
        .parent()
        .ok_or("helper parent unavailable")?
        .canonicalize()
        .map_err(|_| "helper parent unavailable")?
        != base
            .canonicalize()
            .map_err(|_| "machine updater root unavailable")?
    {
        return Err("helper must be staged in its machine attempt directory".into());
    }
    dispatch(
        Config {
            name: NAME.into(),
            root,
        },
        Box::new(UnavailableAuthority),
    )
}

/// Explicit configuration/authority injection is for embedding and isolated SCM
/// tests. The shipped binary accepts no service name, root or authority override.
pub fn dispatch(config: Config, authority: Box<dyn RecoveryAuthority>) -> Result<(), String> {
    if !valid_name(&config.name) || !config.root.is_absolute() {
        return Err("invalid updater service configuration".into());
    }
    let name = config.name.clone();
    HOST.set(Mutex::new(Some(Host { config, authority })))
        .map_err(|_| "service already initialized")?;
    service_dispatcher::start(name, service_entry).map_err(|_| "SCM dispatcher unavailable".into())
}

/// Bootstrap-only configuration, never called under SCM startup's database lock.
/// Two bounded restarts followed by no action; no arbitrary command or reboot.
pub fn configure_recovery(name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err("invalid service name".into());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "SCM unavailable")?;
    let service = manager
        .open_service(name, ServiceAccess::ALL_ACCESS)
        .map_err(|_| "service configuration unavailable")?;
    with_descriptor("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)", |descriptor| unsafe {
        SetServiceObjectSecurity(
            SC_HANDLE(service.raw_handle()),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .map_err(|_| "service DACL update failed".into())
    })?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(15),
                },
                ServiceAction {
                    action_type: ServiceActionType::None,
                    delay: Duration::ZERO,
                },
            ]),
        })
        .map_err(|_| "service recovery configuration failed")?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|_| "service recovery configuration failed".into())
}

fn status(state: ServiceState, failed: bool) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: if failed {
            ServiceExitCode::ServiceSpecific(1)
        } else {
            ServiceExitCode::Win32(0)
        },
        checkpoint: if matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        ) {
            1
        } else {
            0
        },
        wait_hint: if matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        ) {
            Duration::from_secs(20)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

fn entry(_: Vec<OsString>) {
    let Some(host) = HOST
        .get()
        .and_then(|slot| slot.lock().ok())
        .and_then(|mut slot| slot.take())
    else {
        return;
    };
    let Host {
        config,
        mut authority,
    } = host;
    let (tx, rx) = mpsc::sync_channel(1);
    let handle = match service_control_handler::register(&config.name, move |control| match control
    {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.try_send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let _ = handle.set_service_status(status(ServiceState::StartPending, false));
    let result = (|| -> Result<(), String> {
        require_system()?;
        let _ownership = machine_mutex(&config.name)?;
        let image = std::env::current_exe().map_err(|_| "helper image unavailable")?;
        lifetime::validate_host(&config.root, &image)
            .map_err(|_| "unsafe helper image or staging root")?;
        let launch =
            LaunchBinding::read(&config.root).map_err(|_| "invalid protected launch binding")?;
        if config.root.file_name().and_then(|n| n.to_str())
            != Some(launch.binding.attempt_id.as_str())
        {
            return Err("attempt directory binding mismatch".into());
        }
        let mut recovered = launch
            .recover(&config.root, authority.as_mut())
            .map_err(|_| "recovery authority or checkpoint denied")?;
        RuntimeStatus::new(&launch, recovered.as_ref())
            .write(&config.root)
            .map_err(|_| "protected updater status unavailable")?;
        handle
            .set_service_status(status(ServiceState::Running, false))
            .map_err(|_| "SCM status unavailable")?;
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if recovered.is_none() {
                        recovered = launch
                            .recover(&config.root, authority.as_mut())
                            .map_err(|_| "recovery authority or checkpoint denied")?;
                        if recovered.is_some() {
                            RuntimeStatus::new(&launch, recovered.as_ref())
                                .write(&config.root)
                                .map_err(|_| "protected updater status unavailable")?;
                        }
                    }
                }
            }
        }
        handle
            .set_service_status(status(ServiceState::StopPending, false))
            .map_err(|_| "SCM status unavailable")?;
        // Drop the store and machine mutex only after reaching this safe boundary.
        // No installer is reachable from this read-only recovery host.
        Ok(())
    })();
    let _ = handle.set_service_status(status(ServiceState::Stopped, result.is_err()));
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn require_system() -> Result<(), String> {
    unsafe {
        let mut raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)
            .map_err(|_| "process identity unavailable")?;
        let token = Handle(raw);
        let mut size = 0;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut size);
        if size == 0 || size > 65536 {
            return Err("process identity unavailable".into());
        }
        let mut storage = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            size,
            &mut size,
        )
        .map_err(|_| "process identity unavailable")?;
        let user = &*storage.as_ptr().cast::<TOKEN_USER>();
        if !IsWellKnownSid(user.User.Sid, WinLocalSystemSid).as_bool() {
            return Err("updater service requires LocalSystem".into());
        }
        Ok(())
    }
}

fn with_descriptor<T>(
    sddl: &str,
    operation: impl FnOnce(PSECURITY_DESCRIPTOR) -> Result<T, String>,
) -> Result<T, String> {
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .map_err(|_| "security descriptor unavailable")?;
        let result = operation(descriptor);
        let _ = LocalFree(HLOCAL(descriptor.0));
        result
    }
}

struct MachineMutex(Handle);
impl Drop for MachineMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.0 .0);
        }
    }
}
fn machine_mutex(service: &str) -> Result<MachineMutex, String> {
    // The production service name is fixed, so all its attempts share one mutex.
    let name: Vec<u16> = format!("Global\\KubeWorkspaces.AgentUpdater.{service}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    with_descriptor("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)", |descriptor| unsafe {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let handle = Handle(
            CreateMutexW(Some(&attributes), true, PCWSTR(name.as_ptr()))
                .map_err(|_| "machine updater mutex unavailable")?,
        );
        // Never adopt an existing (possibly pre-created) object or silently wait.
        if GetLastError().is_err_and(|error| {
            error.code() == windows::core::HRESULT::from_win32(ERROR_ALREADY_EXISTS.0)
        }) {
            return Err("machine updater already owned".into());
        }
        Ok(MachineMutex(handle))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_machine_ownership_is_exclusive_and_never_adopts_existing_object() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("OwnershipTest-{}-{stamp}", std::process::id());
        let first = machine_mutex(&name).unwrap();
        assert!(machine_mutex(&name).is_err());
        drop(first);
        assert!(machine_mutex(&name).is_ok());
    }
}
