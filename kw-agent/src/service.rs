//! SCM host. Session-0 code owns enrollment and process lifecycle only; all
//! desktop APIs run in a job-owned, unelevated interactive-session worker.
use crate::{
    service_config::{Config, Restart},
    windows_runtime::{self, Worker},
};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

pub const NAME: &str = "KubeWorkspacesAgent";

/// Installer operation, deliberately outside ServiceMain/SCM startup locking.
/// Fixed recovery actions only: no reboot or arbitrary command execution.
pub fn configure() -> Result<(), String> {
    use windows_service::{
        service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions,
            ServiceFailureResetPeriod,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let name = service_name();
    if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid service name".into());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("open SCM: {e:?}"))?;
    let service = manager
        // ChangeServiceConfig2 requires SERVICE_START as well as CHANGE_CONFIG
        // when recovery contains SC_ACTION_RESTART (even though we do not start it).
        .open_service(name, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("open service configuration: {e:?}"))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(
                [5, 15, 60]
                    .into_iter()
                    .map(|s| ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(s),
                    })
                    .collect(),
            ),
        })
        .map_err(|e| format!("set service restart actions: {e:?}"))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| format!("set non-crash recovery: {e:?}"))
}
enum Event {
    Stop,
    Reconcile,
}
define_windows_service!(service_entry, entry);

pub(crate) fn service_name() -> String {
    crate::flag_value(&std::env::args().collect::<Vec<_>>(), "--service-name")
        .unwrap_or_else(|| NAME.into())
}
pub fn dispatch() -> Result<(), String> {
    service_dispatcher::start(service_name(), service_entry).map_err(|e| e.to_string())
}

fn data_dir() -> PathBuf {
    if let Some(dir) = crate::flag_value(&std::env::args().collect::<Vec<_>>(), "--data-dir") {
        return dir.into();
    }
    // Provisioning persists a custom data directory separately from MSI-owned
    // ImagePath, so an MSI repair/upgrade cannot silently reset it.
    unsafe {
        use windows::{core::PCWSTR, Win32::System::Registry::*};
        let mut buffer = vec![0u16; 32768];
        let mut size = (buffer.len() * 2) as u32;
        if RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(windows_runtime::wide("SOFTWARE\\KubeWorkspaces\\Agent").as_ptr()),
            PCWSTR(windows_runtime::wide("DataDir").as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
        .is_ok()
        {
            use std::os::windows::ffi::OsStringExt;
            let count = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
            if count > 0 {
                return OsString::from_wide(&buffer[..count]).into();
            }
        }
    }
    crate::daemon::default_data_dir()
}
fn status(state: ServiceState, failed: bool) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::SESSION_CHANGE
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: if failed {
            ServiceExitCode::ServiceSpecific(1)
        } else {
            ServiceExitCode::Win32(0)
        },
        checkpoint: if state == ServiceState::StartPending || state == ServiceState::StopPending {
            1
        } else {
            0
        },
        wait_hint: if state == ServiceState::StartPending || state == ServiceState::StopPending {
            Duration::from_secs(20)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}
fn entry(_: Vec<OsString>) {
    let (tx, rx) = mpsc::channel();
    let handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(_) => {
            let _ = tx.send(Event::Reconcile);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = match service_control_handler::register(service_name(), handler) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let _ = handle.set_service_status(status(ServiceState::StartPending, false));
    let dir = data_dir();
    let result = (|| {
        // Installer owns SCM configuration. Never change the SCM database
        // during service startup: MSI can hold its configuration lock here.
        windows_runtime::protect_data(&dir)?;
        let _logs = windows_runtime::redirect_logs(&dir.join("logs"), "service")?;
        handle
            .set_service_status(status(ServiceState::Running, false))
            .map_err(|e| e.to_string())?;
        println!("native service started (console-only worker supervision)");
        let result = run(&dir, &rx, || {
            let _ = handle.set_service_status(status(ServiceState::StopPending, false));
        });
        let _ = handle.set_service_status(status(ServiceState::StopPending, result.is_err()));
        if let Err(ref error) = result {
            eprintln!("service failed: {error}");
        }
        result
    })();
    if let Err(ref error) = result {
        // Preserve early setup failures too, before stdout/stderr exist.
        let _ = std::fs::write(dir.join("service-start-error.log"), error);
    }
    let _ = handle.set_service_status(status(ServiceState::Stopped, result.is_err()));
}

fn run(
    dir: &std::path::Path,
    events: &mpsc::Receiver<Event>,
    stopping: impl Fn(),
) -> Result<(), String> {
    let origin = Instant::now();
    let mut retry = Restart::default();
    let mut worker: Option<Worker> = None;
    let mut identity = None;
    let mut enrollment_error = None;
    let mut beat = 0;
    let mut last_beat = None;
    let mut previous_target = None;
    let mut previous_config = None;
    let mut last_status = String::new();
    let mut last_status_at: Option<Instant> = None;
    // Last worker failure worth surfacing; cleared only after a worker has run
    // long enough to have bound and served, never merely because it was spawned.
    let mut worker_error: Option<&'static str> = None;
    let mut console_recovery = crate::console_recovery::Recovery::default();
    let mut console_recovery_error = None;
    loop {
        if console_recovery.due(origin.elapsed().as_secs()) {
            let error = console_recovery.check().err();
            if error != console_recovery_error {
                if let Some(ref error) = error {
                    eprintln!("console recovery: {error}");
                }
                console_recovery_error = error;
            }
        }
        if identity.is_none() {
            match crate::daemon::initialize(dir) {
                Ok(value) => {
                    identity = value;
                    enrollment_error = None;
                }
                Err(error) => {
                    if enrollment_error.as_ref() != Some(&error) {
                        eprintln!("enrollment unavailable: {error}");
                    }
                    enrollment_error = Some(error);
                }
            }
        }
        if let Some(ref identity) = identity {
            if last_beat.map_or(true, |instant: Instant| {
                instant.elapsed() >= Duration::from_secs(60)
            }) {
                beat += 1;
                crate::daemon::write_heartbeat(dir, identity, beat)?;
                last_beat = Some(Instant::now());
            }
        }
        let config = Config::read(dir);
        let target = if identity.is_some() && config.as_ref().is_ok_and(|c| c.worker_enabled) {
            windows_runtime::console_session()
        } else {
            None
        };
        if target != previous_target || config.as_ref().ok() != previous_config.as_ref() {
            drop(worker.take());
            retry.reset();
            previous_target = target;
            previous_config = config.as_ref().ok().cloned();
        }
        if worker.as_ref().is_some_and(|child| child.exited()) {
            let child = worker.take().expect("worker");
            if child.started.elapsed() >= Duration::from_secs(60) {
                retry.reset();
            }
            if child.exit_code() == Some(crate::EXIT_BIND_IN_USE as u32) {
                eprintln!(
                    "worker exited: serve port already in use; another process is holding the configured port"
                );
                worker_error = Some("port-in-use");
                // Back off more when port is held; don't spam restarts
                retry.failed(origin.elapsed().as_secs());
            } else {
                eprintln!("worker exited; bounded restart scheduled");
                worker_error = None;
            }
            drop(child);
            retry.failed(origin.elapsed().as_secs());
        } else if worker
            .as_ref()
            .is_some_and(|child| child.started.elapsed() >= Duration::from_secs(5))
        {
            // Only a worker that has survived long enough to have bound the
            // port clears the error; a brief spawn is not evidence of health.
            worker_error = None;
        }
        if worker.is_none() && retry.ready(origin.elapsed().as_secs()) {
            if let (Some(session), Ok(config)) = (target, &config) {
                match Worker::spawn(session, dir, config) {
                    Ok(child) => {
                        println!("worker started session={} pid={}", child.session, child.pid);
                        worker = Some(child);
                    }
                    Err(error) => {
                        eprintln!("worker launch failed: {error}");
                        retry.failed(origin.elapsed().as_secs());
                    }
                }
            }
        }
        let state = if enrollment_error.is_some() {
            "enrollment-error"
        } else if identity.is_none() {
            "awaiting-enrollment"
        } else if config.is_err() {
            "configuration-error"
        } else if worker_error == Some("port-in-use") && worker.is_none() {
            "port-in-use"
        } else if worker.is_some() {
            "worker-process-running"
        } else if target.is_some() {
            "worker-restart-backoff"
        } else {
            "no-console-worker"
        };
        let mut snapshot = serde_json::json!({"schemaVersion":1,"serviceState":"running","state":state,"workerEnabled":config.as_ref().ok().map(|c| c.worker_enabled),"workerPid":worker.as_ref().map(|w| w.pid),"consoleSession":target,"mediaReady":null,"workerError":worker_error,"configurationError":config.as_ref().err(),"enrollmentError":enrollment_error});
        snapshot["consoleRecoveryError"] = serde_json::json!(console_recovery_error);
        // Status is machine-authored. Process liveness is never labeled as media readiness.
        let text = snapshot.to_string();
        if text != last_status
            || last_status_at.map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
        {
            snapshot["updatedAt"] = serde_json::json!(kw_core::now_secs());
            std::fs::write(dir.join("service-status.json.tmp"), snapshot.to_string())
                .map_err(|e| e.to_string())?;
            std::fs::rename(
                dir.join("service-status.json.tmp"),
                dir.join("service-status.json"),
            )
            .map_err(|e| e.to_string())?;
            last_status = text;
            last_status_at = Some(Instant::now());
        }
        match events.recv_timeout(Duration::from_secs(1)) {
            Ok(Event::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                stopping();
                break;
            }
            Ok(Event::Reconcile) | Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    // No untracked processes: cooperative stop releases input and closes the
    // transport, then the job provides bounded forced cleanup if necessary.
    drop(worker.take());
    std::fs::write(dir.join("service-status.json"), serde_json::json!({"schemaVersion":1,"serviceState":"stopped","workerPid":null,"mediaReady":null}).to_string()).map_err(|e| e.to_string())?;
    Ok(())
}
