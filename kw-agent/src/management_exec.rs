//! Bounded root/SYSTEM command runner for the opt-in QGA pilot transport
//! (`qga-pod-exec/v1`). Invoked as a fixed installed command by the API's
//! Kubernetes-authenticated launcher bridge; it opens no listener.
//!
//! Contract: one staged envelope file → independent guest verification of the
//! signed QGA grant (pinned public keys, enrolled workspace UID, request
//! bounds, single-use) → one bounded process tree under a Windows Job Object
//! or Linux cgroup v2
//! (deadline, combined output cap, process-tree cleanup) → one bounded JSON
//! result on stdout. No interactive stdin, no detached jobs, no shell/PTY.
//! The API must treat this result as the authoritative guest outcome; loss of
//! the result is reported as unknown, never as success.

use base64::{engine::general_purpose::STANDARD, Engine};
use kw_management::{
    digest, split_qga_envelope, QgaCommandRequest, QgaVerifier, QGA_MAX_ENVELOPE_BYTES,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const RESULT_VERSION: u32 = 1;
const MAX_KEYS: usize = 16;
const MAX_KEYS_FILE_BYTES: usize = 16 * 1024;
const MAX_JTIS: usize = 1024;
const MAX_JTI_FILE_BYTES: usize = 1024 * 1024;
const KEYS_FILE_NAME: &str = "management-grant-keys.json";
const JTI_FILE_NAME: &str = "used-jtis.json";

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CommandResult {
    pub version: u32,
    pub outcome: String,
    pub exit_code: Option<i32>,
    pub stdout_b64: String,
    pub stderr_b64: String,
    pub truncated: bool,
    pub duration_ms: u64,
    pub denial: Option<String>,
}

impl CommandResult {
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            version: RESULT_VERSION,
            outcome: "denied".into(),
            exit_code: None,
            stdout_b64: String::new(),
            stderr_b64: String::new(),
            truncated: false,
            duration_ms: 0,
            denial: Some(reason.into()),
        }
    }

    pub fn runner_error(reason: impl Into<String>) -> Self {
        Self {
            outcome: "runner-error".into(),
            denial: Some(reason.into()),
            ..Self::denied("unused")
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub struct CommandSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub deadline: Duration,
    pub output_limit: usize,
}

#[derive(Debug)]
pub struct RunOutcome {
    pub outcome: &'static str,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub duration: Duration,
}

impl RunOutcome {
    #[cfg(not(any(windows, target_os = "linux")))]
    fn unsupported() -> Self {
        Self {
            outcome: "spawn-failed",
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            duration: Duration::ZERO,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct KeysFile {
    version: u32,
    keys: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JtiStore {
    version: u32,
    entries: std::collections::HashMap<String, i64>,
}

pub fn load_keys(path: &Path) -> Result<Vec<[u8; 32]>, String> {
    let data = std::fs::read(path).map_err(|e| format!("keys file unreadable: {e}"))?;
    if data.is_empty() || data.len() > MAX_KEYS_FILE_BYTES {
        return Err("keys file is empty or oversized".into());
    }
    let file: KeysFile =
        serde_json::from_slice(&data).map_err(|_| "keys file malformed".to_string())?;
    if file.version != 1 || file.keys.is_empty() || file.keys.len() > MAX_KEYS {
        return Err("keys file has an unsupported version or key count".into());
    }
    let mut keys = Vec::with_capacity(file.keys.len());
    for entry in &file.keys {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(entry)
            .map_err(|_| "keys file contains a non-base64url key".to_string())?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| "keys file contains a non-32-byte key".to_string())?;
        if keys.contains(&key) {
            return Err("keys file contains a duplicate key".into());
        }
        keys.push(key);
    }
    Ok(keys)
}

/// Claim one grant ID in the bounded persistent single-use store. Fail-closed:
/// any read/parse/write problem denies instead of running the command.
fn claim_jti(state_dir: &Path, jti: &str, expiry: i64, now: i64) -> Result<(), String> {
    std::fs::create_dir_all(state_dir).map_err(|e| format!("state directory: {e}"))?;
    // Separate QGA processes can arrive concurrently. Hold a kernel lock for
    // the complete read/claim/publish transaction, not just the final rename.
    #[cfg(target_os = "linux")]
    let _lock = {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(state_dir.join("replay.lock"))
            .map_err(|e| format!("replay lock: {e}"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err("replay lock unavailable".into());
        }
        file
    };
    #[cfg(windows)]
    let _lock = {
        use std::os::windows::fs::OpenOptionsExt;
        // Exclusive sharing fences the complete read/claim/publish transaction
        // across separate QGA runner processes, including command/script races.
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(state_dir.join("replay.lock"))
            .map_err(|_| "replay lock unavailable".to_string())?
    };
    let path = state_dir.join(JTI_FILE_NAME);
    let mut store = match std::fs::read(&path) {
        Ok(data) => {
            if data.len() > MAX_JTI_FILE_BYTES {
                return Err("grant replay store is oversized".into());
            }
            let store: JtiStore = serde_json::from_slice(&data)
                .map_err(|_| "grant replay store is malformed".to_string())?;
            if store.version != 1 {
                return Err("grant replay store has an unsupported version".into());
            }
            store
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => JtiStore {
            version: 1,
            entries: Default::default(),
        },
        Err(error) => return Err(format!("grant replay store unreadable: {error}")),
    };
    store.entries.retain(|_, exp| *exp > now);
    if store.entries.contains_key(jti) {
        return Err("grant already consumed on this guest".into());
    }
    if store.entries.len() >= MAX_JTIS {
        return Err("grant replay store is at capacity".into());
    }
    store.entries.insert(jti.to_owned(), expiry);
    let raw = serde_json::to_vec(&store).map_err(|_| "grant replay store render".to_string())?;
    let temp = state_dir.join(format!("{JTI_FILE_NAME}.tmp"));
    use std::io::Write;
    let mut file =
        std::fs::File::create(&temp).map_err(|e| format!("grant replay store create: {e}"))?;
    file.write_all(&raw)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("grant replay store write: {e}"))?;
    std::fs::rename(&temp, &path).map_err(|e| format!("grant replay store publish: {e}"))?;
    #[cfg(target_os = "linux")]
    std::fs::File::open(state_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("grant replay store sync: {e}"))?;
    Ok(())
}

/// Verify the staged envelope end to end. On success the grant is consumed
/// in memory and its ID is durably claimed before any process is created.
pub fn verify_envelope(
    envelope: &[u8],
    keys: &[[u8; 32]],
    enrolled_uid: &str,
    state_dir: &Path,
    now_epoch: i64,
) -> Result<(QgaCommandRequest, String), CommandResult> {
    if envelope.is_empty() || envelope.len() > QGA_MAX_ENVELOPE_BYTES {
        return Err(CommandResult::denied("envelope missing or oversized"));
    }
    let (grant, request_raw) =
        split_qga_envelope(envelope).map_err(|_| CommandResult::denied("envelope malformed"))?;
    let request: QgaCommandRequest = serde_json::from_str(request_raw.get())
        .map_err(|_| CommandResult::denied("request malformed"))?;
    if let Err(reason) = request.validate(enrolled_uid) {
        return Err(CommandResult::denied(reason));
    }
    let request_sha256 = digest(request_raw.get().as_bytes());
    let expected = request.expected_binding(request_sha256);
    let mut verifier =
        QgaVerifier::new(keys, MAX_KEYS).map_err(|_| CommandResult::denied("no usable keys"))?;
    let claims = verifier
        .consume(&grant, &expected, now_epoch)
        .map_err(|error| CommandResult::denied(format!("grant verification: {error:?}")))?;
    claim_jti(state_dir, &claims.jti, claims.exp, now_epoch).map_err(CommandResult::denied)?;
    Ok((request, claims.jti))
}

fn result_from_run(outcome: RunOutcome) -> CommandResult {
    CommandResult {
        version: RESULT_VERSION,
        outcome: outcome.outcome.into(),
        exit_code: outcome.exit_code,
        stdout_b64: STANDARD.encode(&outcome.stdout),
        stderr_b64: STANDARD.encode(&outcome.stderr),
        truncated: outcome.truncated,
        duration_ms: outcome.duration.as_millis() as u64,
        denial: None,
    }
}

/// Full runner lifecycle with an injectable spawn for tests. Production uses
/// the platform's bounded process supervisor.
pub fn run_with<F>(
    envelope: &[u8],
    keys: &[[u8; 32]],
    enrolled_uid: &str,
    state_dir: &Path,
    now_epoch: i64,
    spawn: F,
) -> CommandResult
where
    F: FnOnce(&CommandSpec) -> RunOutcome,
{
    let (request, jti) = match verify_envelope(envelope, keys, enrolled_uid, state_dir, now_epoch) {
        Ok(verified) => verified,
        Err(result) => return result,
    };
    let spec = CommandSpec {
        executable: request.executable.clone(),
        args: request.args.clone(),
        cwd: request.cwd.clone(),
        deadline: Duration::from_secs(request.deadline_seconds as u64),
        output_limit: kw_management::QGA_MAX_OUTPUT_BYTES,
    };
    if let Some(script) = &request.script {
        #[cfg(any(target_os = "linux", windows))]
        {
            let mut spec = spec;
            let staged = match scripts::StagedScript::create(state_dir, &jti, script) {
                Ok(staged) => staged,
                Err(reason) => return CommandResult::runner_error(reason),
            };
            staged.configure(&mut spec);
            let result = result_from_run(spawn(&spec));
            if staged.finish().is_err() {
                return CommandResult {
                    outcome: "runner-error".into(),
                    denial: Some("script cleanup failed; do not rerun".into()),
                    ..result
                };
            }
            return result;
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (script, jti);
            return CommandResult::denied("script execution is not supported on this OS");
        }
    }
    result_from_run(spawn(&spec))
}

#[cfg(target_os = "linux")]
#[path = "management_exec_scripts.rs"]
mod scripts;

#[cfg(windows)]
#[path = "management_exec_scripts_windows.rs"]
mod scripts;

/// Production entry: enrolled identity from the agent data dir, pinned keys
/// from the data dir, persistent single-use state beside them.
pub fn run(args: &RunArgs) -> CommandResult {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if unsafe { libc::geteuid() } != 0 {
            return CommandResult::denied("runner is not running as root");
        }
        match std::fs::symlink_metadata(&args.data_dir) {
            Ok(meta) if meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0 => (),
            _ => {
                return CommandResult::denied(
                    "management data directory must be root-owned mode 0700",
                )
            }
        }
        for path in [
            Path::new("/etc/workspace-agent"),
            Path::new("/etc/workspace-agent/public"),
            Path::new("/etc/workspace-agent/public/binding.json"),
        ] {
            match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.uid() == 0 && meta.mode() & 0o022 == 0 && !meta.file_type().is_symlink() => (),
                _ => return CommandResult::denied("management state and binding must be root-owned and not writable by other users"),
            }
        }
    }
    let envelope = match read_bounded(&args.request_file, QGA_MAX_ENVELOPE_BYTES) {
        Ok(envelope) => envelope,
        Err(reason) => return CommandResult::runner_error(reason),
    };
    let keys_path = args
        .keys_file
        .clone()
        .unwrap_or_else(|| args.data_dir.join(KEYS_FILE_NAME));
    let keys = match load_keys(&keys_path) {
        Ok(keys) => keys,
        Err(reason) => return CommandResult::denied(reason),
    };
    #[cfg(not(target_os = "linux"))]
    let enrolled = match kw_core::load(&args.data_dir) {
        Ok(Some(identity)) => identity.workspace_uid,
        Ok(None) => return CommandResult::denied("identity.json missing: guest is not enrolled"),
        Err(error) => return CommandResult::denied(format!("identity unreadable: {error}")),
    };
    #[cfg(target_os = "linux")]
    let enrolled = match super::binding::read(Path::new("/etc/workspace-agent")) {
        Ok(Some(binding)) => binding.workspace_uid,
        _ => return CommandResult::denied("controller workspace binding is missing or unreadable"),
    };
    let state_dir = args
        .state_dir
        .clone()
        .unwrap_or_else(|| args.data_dir.join("management"));
    let now_epoch = kw_core::now_secs() as i64;
    // On Windows the pilot additionally requires the SYSTEM identity: QGA
    // normally runs as LocalSystem, and an installation that runs it as
    // anything else must fail closed rather than silently downgrade.
    #[cfg(windows)]
    if !crate::windows_runtime::process_is_local_system() {
        return CommandResult::denied("runner is not running as SYSTEM");
    }
    // A valid grant for the other OS must never be interpreted as authority
    // for this machine's privileged identity.
    let (_, raw) = match split_qga_envelope(&envelope) {
        Ok(parts) => parts,
        Err(_) => return CommandResult::denied("envelope malformed"),
    };
    let request: QgaCommandRequest = match serde_json::from_str(raw.get()) {
        Ok(request) => request,
        Err(_) => return CommandResult::denied("request malformed"),
    };
    if !platform_identity_matches(&request.os_identity) {
        return CommandResult::denied("target identity does not match the runner OS");
    }
    run_with(
        &envelope,
        &keys,
        &enrolled,
        &state_dir,
        now_epoch,
        spawn_bounded,
    )
}

#[derive(Debug)]
pub struct RunArgs {
    pub request_file: PathBuf,
    pub keys_file: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub state_dir: Option<PathBuf>,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let file = std::fs::File::open(path).map_err(|e| format!("request file unreadable: {e}"))?;
    file.take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("request file read: {e}"))?;
    if data.len() > limit {
        return Err("request file is oversized".into());
    }
    Ok(data)
}

#[cfg(windows)]
fn spawn_bounded(spec: &CommandSpec) -> RunOutcome {
    windows_runner::spawn(spec)
}

fn platform_identity_matches(identity: &str) -> bool {
    if cfg!(windows) {
        identity.eq_ignore_ascii_case("SYSTEM")
    } else {
        cfg!(target_os = "linux") && identity == "root"
    }
}

#[cfg(target_os = "linux")]
#[path = "management_exec_linux.rs"]
mod linux_runner;

#[cfg(target_os = "linux")]
fn spawn_bounded(spec: &CommandSpec) -> RunOutcome {
    linux_runner::spawn(spec)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn spawn_bounded(_spec: &CommandSpec) -> RunOutcome {
    // Other operating systems have no management supervisor.
    RunOutcome::unsupported()
}

/// Windows Job Object supervised process spawn: KILL_ON_JOB_CLOSE, bounded
/// active processes, redirected pipes, combined output cap, deadline
/// termination and process-tree cleanup.
#[cfg(windows)]
mod windows_runner {
    use super::{CommandSpec, RunOutcome};
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::ReadFile;
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOW,
    };

    /// Poll slice: enforces the combined output cap and the deadline while
    /// the child runs instead of only after it exits.
    const POLL_SLICE_MS: u32 = 50;
    const REAP_TIMEOUT_MS: u32 = 5_000;
    // PowerShell and cmd must be able to invoke native commands. All children
    // inherit this job; breakaway stays disabled and the entire tree shares
    // the command's lifetime, output cap and deadline.
    const MAX_ACTIVE_PROCESSES: u32 = 16;

    fn spawn_failed(context: &str, detail: String) -> RunOutcome {
        RunOutcome {
            outcome: "spawn-failed",
            exit_code: None,
            stdout: Vec::new(),
            stderr: format!("{context}: {detail}").into_bytes(),
            truncated: false,
            duration: Duration::ZERO,
        }
    }

    fn wide_null(text: &str) -> Vec<u16> {
        std::ffi::OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Quote one argument for a Windows command line (MSVCRT rules).
    pub fn quote_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_owned();
        }
        let mut quoted = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                    quoted.push('"');
                    backslashes = 0;
                }
                _ => {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    quoted.push(ch);
                }
            }
        }
        quoted.push_str(&"\\".repeat(backslashes * 2));
        quoted.push('"');
        quoted
    }

    fn command_line(spec: &CommandSpec) -> Vec<u16> {
        let mut line = quote_arg(&spec.executable);
        for arg in &spec.args {
            line.push(' ');
            line.push_str(&quote_arg(arg));
        }
        wide_null(&line)
    }

    fn read_pipe(handle: HANDLE, sink: &Arc<PipeSink>, to_stderr: bool) {
        let mut buffer = [0u8; 8192];
        loop {
            let mut read = 0u32;
            let ok = unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut read), None) }.is_ok();
            if !ok || read == 0 {
                break;
            }
            if sink.append(to_stderr, &buffer[..read as usize]) {
                break;
            }
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    }

    /// One combined stdout+stderr budget shared by both reader threads, so
    /// the pilot's 16 KiB cap cannot be doubled by writing to both streams.
    struct PipeSink {
        limit: usize,
        total: AtomicUsize,
        overflow: AtomicBool,
        stdout: Mutex<Vec<u8>>,
        stderr: Mutex<Vec<u8>>,
    }

    impl PipeSink {
        fn new(limit: usize) -> Self {
            Self {
                limit,
                total: AtomicUsize::new(0),
                overflow: AtomicBool::new(false),
                stdout: Mutex::new(Vec::new()),
                stderr: Mutex::new(Vec::new()),
            }
        }

        /// Returns true once the combined cap was exceeded (caller stops).
        fn append(&self, to_stderr: bool, data: &[u8]) -> bool {
            let previous = self.total.fetch_add(data.len(), Ordering::SeqCst);
            let allowed = data
                .len()
                .min(self.limit.saturating_sub(previous.min(self.limit)));
            if allowed > 0 {
                let buffer = if to_stderr {
                    &self.stderr
                } else {
                    &self.stdout
                };
                buffer
                    .lock()
                    .expect("output sink")
                    .extend_from_slice(&data[..allowed]);
            }
            let overflow = previous + data.len() > self.limit;
            if overflow {
                self.overflow.store(true, Ordering::SeqCst);
            }
            overflow
        }
    }

    /// Drop the inherit flag from our own standard handles so the child
    /// receives only the two redirected pipe write ends, never a raw handle
    /// to the guest-exec capture stream that carries the JSON result.
    fn protect_stdio() -> Vec<HANDLE> {
        let mut saved = Vec::new();
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let Ok(handle) = (unsafe { GetStdHandle(id) }) else {
                continue;
            };
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
                .is_ok()
            {
                saved.push(handle);
            }
        }
        saved
    }

    fn restore_stdio(saved: Vec<HANDLE>) {
        for handle in saved {
            unsafe {
                let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT);
            }
        }
    }

    pub fn spawn(spec: &CommandSpec) -> RunOutcome {
        let started = Instant::now();
        let mut stdout_read = INVALID_HANDLE_VALUE;
        let mut stdout_write = INVALID_HANDLE_VALUE;
        let mut stderr_read = INVALID_HANDLE_VALUE;
        let mut stderr_write = INVALID_HANDLE_VALUE;
        let inheritable = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        unsafe {
            if let Err(error) =
                CreatePipe(&mut stdout_read, &mut stdout_write, Some(&inheritable), 0)
            {
                return spawn_failed("stdout pipe", error.to_string());
            }
            if let Err(error) =
                CreatePipe(&mut stderr_read, &mut stderr_write, Some(&inheritable), 0)
            {
                let _ = CloseHandle(stdout_read);
                let _ = CloseHandle(stdout_write);
                return spawn_failed("stderr pipe", error.to_string());
            }
        }
        let sink = Arc::new(PipeSink::new(spec.output_limit));
        let stdout_thread = {
            let sink = sink.clone();
            std::thread::spawn(move || read_pipe(stdout_read, &sink, false))
        };
        let stderr_thread = {
            let sink = sink.clone();
            std::thread::spawn(move || read_pipe(stderr_read, &sink, true))
        };

        // KILL_ON_JOB_CLOSE ties the whole tree's lifetime to this process.
        // A bounded process count permits shell-invoked native utilities while
        // preventing an unbounded tree; no process may break away from the job.
        let job = match unsafe { CreateJobObjectW(None, PCWSTR::null()) } {
            Ok(job) => job,
            Err(error) => {
                unsafe {
                    let _ = CloseHandle(stdout_write);
                    let _ = CloseHandle(stderr_write);
                }
                stdout_thread.join().ok();
                stderr_thread.join().ok();
                return spawn_failed("job object", error.to_string());
            }
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = MAX_ACTIVE_PROCESSES;
        if let Err(error) = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } {
            unsafe {
                let _ = CloseHandle(job);
                let _ = CloseHandle(stdout_write);
                let _ = CloseHandle(stderr_write);
            }
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            return spawn_failed("job limits", error.to_string());
        }

        let mut command = command_line(spec);
        let cwd = spec.cwd.as_ref().map(|cwd| wide_null(cwd));
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = INVALID_HANDLE_VALUE;
        startup.hStdOutput = stdout_write;
        startup.hStdError = stderr_write;
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // Suspended start: the job assignment lands before the child runs,
        // closing the pre-assignment escape window.
        let stdio = protect_stdio();
        let created = unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                true,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                None,
                cwd.as_ref().map_or(PCWSTR::null(), |c| PCWSTR(c.as_ptr())),
                &startup,
                &mut process,
            )
        };
        restore_stdio(stdio);
        unsafe {
            let _ = CloseHandle(stdout_write);
            let _ = CloseHandle(stderr_write);
        }
        if let Err(error) = created {
            unsafe {
                let _ = CloseHandle(job);
            }
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            return spawn_failed("create process", error.to_string());
        }
        if let Err(error) = unsafe { AssignProcessToJobObject(job, process.hProcess) } {
            unsafe {
                let _ = TerminateProcess(process.hProcess, 1);
                let _ = CloseHandle(process.hThread);
                let _ = CloseHandle(process.hProcess);
                let _ = CloseHandle(job);
            }
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            return spawn_failed("job assignment", error.to_string());
        }
        if unsafe { ResumeThread(process.hThread) } == u32::MAX {
            unsafe {
                let _ = TerminateJobObject(job, 1);
                let _ = CloseHandle(process.hThread);
                let _ = CloseHandle(process.hProcess);
                let _ = CloseHandle(job);
            }
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            return spawn_failed("process resume", "ResumeThread failed".into());
        }
        unsafe {
            let _ = CloseHandle(process.hThread);
        }

        // Poll so the output cap and the deadline are enforced while the
        // child runs; a stuck child is terminated promptly, not after 20s of
        // blocked pipe writes.
        let deadline_at = started + spec.deadline;
        let mut outcome = "completed";
        loop {
            if sink.overflow.load(Ordering::SeqCst) {
                outcome = "output-limit";
                break;
            }
            let now = Instant::now();
            if now >= deadline_at {
                outcome = "deadline";
                break;
            }
            let remaining = deadline_at - now;
            let slice = remaining.min(Duration::from_millis(POLL_SLICE_MS as u64));
            let wait_ms = u32::try_from(slice.as_millis())
                .unwrap_or(POLL_SLICE_MS)
                .max(1);
            let waited = unsafe { WaitForSingleObject(process.hProcess, wait_ms) };
            if waited == WAIT_OBJECT_0 {
                break;
            }
            if waited != WAIT_TIMEOUT {
                outcome = "runner-error";
                break;
            }
        }
        // A root that exited successfully may still have descendants holding
        // the redirected pipes. Terminate the entire tree and close the job
        // BEFORE joining readers, or those pipes can block past the deadline.
        // The already-exited root retains its actual exit code.
        let mut exit_code: u32 = 1;
        unsafe {
            let _ = TerminateJobObject(job, 1);
            let _ = WaitForSingleObject(process.hProcess, REAP_TIMEOUT_MS);
            let _ = GetExitCodeProcess(process.hProcess, &mut exit_code);
            let _ = CloseHandle(process.hProcess);
            let _ = CloseHandle(job);
        }
        stdout_thread.join().ok();
        stderr_thread.join().ok();
        if sink.overflow.load(Ordering::SeqCst) {
            outcome = "output-limit";
        }
        let outcome = RunOutcome {
            outcome,
            exit_code: Some(exit_code as i32),
            stdout: sink.stdout.lock().expect("stdout").clone(),
            stderr: sink.stderr.lock().expect("stderr").clone(),
            truncated: sink.overflow.load(Ordering::SeqCst),
            duration: started.elapsed(),
        };
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    pub(super) fn test_key(seed: u8) -> [u8; 32] {
        // The verifier is pinned with public keys; derive the point that
        // matches the throwaway signing seed.
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    pub(super) fn signed_qga_envelope(
        request_json: &str,
        seed: u8,
        binding_from: impl FnOnce(&QgaCommandRequest, String) -> kw_management::QgaBinding,
    ) -> String {
        // Sign with a throwaway key; the test verifier is given the matching
        // public key. Mirrors the kw-management signed() helper.
        use ed25519_dalek::{Signer, SigningKey};
        use serde_json::json;
        let key = SigningKey::from_bytes(&[seed; 32]);
        let request: QgaCommandRequest = serde_json::from_str(request_json).unwrap();
        let request_sha = digest(request_json.as_bytes());
        let binding = binding_from(&request, request_sha);
        let claims = json!({
            "version": 1,
            "iss": kw_management::QGA_ISSUER,
            "aud": kw_management::QGA_AUDIENCE,
            "jti": binding.challenge.clone(),
            "iat": 1_800_000_000i64,
            "exp": 1_800_000_030i64,
            "binding": binding,
        });
        let header = json!({
            "alg": "EdDSA",
            "typ": "kw-management-grant+qga",
            "kid": kw_management::key_id(key.verifying_key().as_bytes()),
        });
        let input = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        );
        let token = format!(
            "{input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key.sign(input.as_bytes()).to_bytes())
        );
        format!("{{\"grant\":\"{token}\",\"request\":{request_json}}}")
    }

    fn valid_request_json(challenge: &str, target_digest: &str) -> String {
        serde_json::json!({
            "version": 1,
            "challenge": challenge,
            "transport_target_sha256": target_digest,
            "actor_uid": "user-1",
            "namespace": "team-a",
            "workspace_name": "vm-1",
            "workspace_uid": "11111111-1111-4111-8111-111111111111",
            "provisioning_generation": "22222222-2222-4222-8222-222222222222",
            "execution_id": "exec-1",
            "recording_id": "rec-1",
            "operation": "command",
            "os_identity": "SYSTEM",
            "elevated": true,
            "policy_version": "1",
            "revocation_epoch": 0,
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "args": ["/c", "echo hi"],
            "cwd": null,
            "deadline_seconds": 20,
        })
        .to_string()
    }

    fn fixture_binding(
        request: &QgaCommandRequest,
        request_sha: String,
    ) -> kw_management::QgaBinding {
        request.expected_binding(request_sha)
    }

    #[cfg(target_os = "linux")]
    fn script_request_json(body: &str) -> String {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let mut request: serde_json::Value =
            serde_json::from_str(&valid_request_json(&challenge, &digest(b"target"))).unwrap();
        request["version"] = 2.into();
        request["operation"] = "script".into();
        request["os_identity"] = "root".into();
        request["executable"] = "".into();
        request["args"] = serde_json::json!([]);
        request["script"] = serde_json::json!({
            "body": body,
            "name": "maintenance.sh",
            "interpreter_policy": "linux-shebang-v1"
        });
        request.to_string()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signed_script_stages_privately_executes_shebang_and_cleans_up() {
        use std::os::unix::fs::MetadataExt;
        let body = "#!/bin/sh\nprintf 'script output\\n'\nprintf 'script stderr\\n' >&2\nexit 7\n";
        let request_json = script_request_json(body);
        let envelope = signed_qga_envelope(&request_json, 0, fixture_binding);
        let dir = temp_dir("script");
        let mut staged_path = None;
        let result = run_with(
            envelope.as_bytes(),
            &[test_key(0)],
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |spec| {
                let path = PathBuf::from(&spec.executable);
                assert_eq!(std::fs::read(&path).unwrap(), body.as_bytes());
                assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
                assert_eq!(
                    std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
                    0o700
                );
                assert!(spec.args.is_empty());
                assert_eq!(spec.deadline, Duration::from_secs(20));
                assert_eq!(spec.output_limit, kw_management::QGA_MAX_OUTPUT_BYTES);
                // Real kernel shebang execution. Supervision is tested separately
                // by the existing privileged cgroup runner suite.
                let output = std::process::Command::new(&path).output().unwrap();
                staged_path = Some(path);
                RunOutcome {
                    outcome: "completed",
                    exit_code: output.status.code(),
                    stdout: output.stdout,
                    stderr: output.stderr,
                    truncated: false,
                    duration: Duration::from_millis(1),
                }
            },
        );
        assert_eq!(result.outcome, "completed");
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(
            STANDARD.decode(result.stdout_b64).unwrap(),
            b"script output\n"
        );
        assert_eq!(
            STANDARD.decode(result.stderr_b64).unwrap(),
            b"script stderr\n"
        );
        assert!(!staged_path.unwrap().exists());
        let replay = run_with(
            envelope.as_bytes(),
            &[test_key(0)],
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |_| panic!("a replayed script must never execute"),
        );
        assert_eq!(replay.outcome, "denied");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn script_body_tampering_denies_without_staging() {
        let original = script_request_json("#!/bin/sh\necho original\n");
        let envelope = signed_qga_envelope(&original, 0, fixture_binding)
            .replace("echo original", "echo tampered");
        let dir = temp_dir("script-tamper");
        let result = run_with(
            envelope.as_bytes(),
            &[test_key(0)],
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |_| panic!("tampered scripts must not spawn"),
        );
        assert_eq!(result.outcome, "denied");
        assert!(!dir.join("scripts").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn script_raw_and_encoded_envelope_limits_are_independent() {
        // Both bodies fit the 64 KiB UTF-8 bound, but JSON escaping makes the
        // second exceed the independent 96 KiB staged-envelope bound.
        for (fill, expected) in [('x', "completed"), ('\t', "denied")] {
            let body = format!(
                "#!/bin/sh\n{}",
                fill.to_string()
                    .repeat(kw_management::QGA_MAX_SCRIPT_BYTES - 10)
            );
            let envelope = signed_qga_envelope(&script_request_json(&body), 0, fixture_binding);
            assert_eq!(
                envelope.len() > QGA_MAX_ENVELOPE_BYTES,
                expected == "denied"
            );
            let dir = temp_dir("script-envelope-limit");
            let result = run_with(
                envelope.as_bytes(),
                &[test_key(0)],
                "11111111-1111-4111-8111-111111111111",
                &dir,
                1_800_000_000,
                |_| {
                    assert_eq!(expected, "completed");
                    RunOutcome {
                        outcome: "completed",
                        exit_code: Some(0),
                        stdout: vec![],
                        stderr: vec![],
                        truncated: false,
                        duration: Duration::ZERO,
                    }
                },
            );
            assert_eq!(result.outcome, expected);
            if expected == "denied" {
                assert!(!dir.join("scripts").exists());
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn script_cleanup_preserves_deadline_output_limit_and_spawn_failure() {
        for outcome in ["deadline", "output-limit", "spawn-failed"] {
            let envelope = signed_qga_envelope(
                &script_request_json("#!/bin/sh\nexit 0\n"),
                0,
                fixture_binding,
            );
            let dir = temp_dir(outcome);
            let mut path = None;
            let result = run_with(
                envelope.as_bytes(),
                &[test_key(0)],
                "11111111-1111-4111-8111-111111111111",
                &dir,
                1_800_000_000,
                |spec| {
                    path = Some(PathBuf::from(&spec.executable));
                    RunOutcome {
                        outcome,
                        exit_code: None,
                        stdout: vec![],
                        stderr: vec![],
                        truncated: outcome == "output-limit",
                        duration: Duration::ZERO,
                    }
                },
            );
            assert_eq!(result.outcome, outcome);
            assert_eq!(result.truncated, outcome == "output-limit");
            assert!(!path.unwrap().exists());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    pub(super) fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kw-mgmt-exec-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn forged_transport_target_denies() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let request_json = valid_request_json(&challenge, &digest(b"target"));
        let envelope = signed_qga_envelope(&request_json, 0, |request, request_sha| {
            let mut binding = request.expected_binding(request_sha);
            binding.transport_target_sha256 = digest(b"different-target");
            binding
        });
        let dir = temp_dir("target");
        let keys = [test_key(0)];
        let result = run_with(
            envelope.as_bytes(),
            &keys,
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |_| panic!("a mismatched transport target must never spawn"),
        );
        assert_eq!(result.outcome, "denied");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn valid_envelope_runs_spawn_and_records_result() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let request_json = valid_request_json(&challenge, &digest(b"target"));
        let envelope = signed_qga_envelope(&request_json, 0, fixture_binding);
        let dir = temp_dir("valid");
        let keys = [test_key(0)];
        let result = run_with(
            envelope.as_bytes(),
            &keys,
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |spec| {
                assert_eq!(spec.executable, "C:\\Windows\\System32\\cmd.exe");
                assert_eq!(spec.deadline, Duration::from_secs(20));
                assert_eq!(spec.output_limit, kw_management::QGA_MAX_OUTPUT_BYTES);
                RunOutcome {
                    outcome: "completed",
                    exit_code: Some(0),
                    stdout: b"hi\r\n".to_vec(),
                    stderr: Vec::new(),
                    truncated: false,
                    duration: Duration::from_millis(3),
                }
            },
        );
        assert_eq!(result.outcome, "completed");
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            STANDARD.decode(&result.stdout_b64).unwrap(),
            b"hi\r\n".to_vec()
        );
        assert_eq!(result.version, RESULT_VERSION);
        assert!(result.denial.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn grant_is_single_use_across_runner_invocations() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let request_json = valid_request_json(&challenge, &digest(b"target"));
        let envelope = signed_qga_envelope(&request_json, 0, fixture_binding);
        let dir = temp_dir("replay");
        let keys = [test_key(0)];
        let spawn = |_: &CommandSpec| RunOutcome {
            outcome: "completed",
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            duration: Duration::ZERO,
        };
        let first = run_with(
            envelope.as_bytes(),
            &keys,
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            spawn,
        );
        assert_eq!(first.outcome, "completed");
        let second = run_with(
            envelope.as_bytes(),
            &keys,
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |_| panic!("a replayed grant must never spawn"),
        );
        assert_eq!(second.outcome, "denied");
        assert!(second
            .denial
            .as_deref()
            .unwrap_or_default()
            .contains("consumed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn grant_is_single_use_under_concurrent_runner_process_claims() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let mut request: serde_json::Value =
            serde_json::from_str(&valid_request_json(&challenge, &digest(b"target"))).unwrap();
        request["os_identity"] = if cfg!(windows) { "SYSTEM" } else { "root" }.into();
        request["executable"] = if cfg!(windows) {
            "whoami.exe"
        } else {
            "/usr/bin/id"
        }
        .into();
        request["args"] = serde_json::json!(["-u"]);
        let envelope = signed_qga_envelope(&request.to_string(), 0, fixture_binding);
        let dir = temp_dir("root-concurrency");
        let barrier = std::sync::Barrier::new(8);
        let count = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    barrier.wait();
                    let result = run_with(
                        envelope.as_bytes(),
                        &[test_key(0)],
                        "11111111-1111-4111-8111-111111111111",
                        &dir,
                        1_800_000_000,
                        |_| {
                            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            RunOutcome {
                                outcome: "completed",
                                exit_code: Some(0),
                                stdout: b"0\n".to_vec(),
                                stderr: Vec::new(),
                                truncated: false,
                                duration: Duration::ZERO,
                            }
                        },
                    );
                    assert!(result.outcome == "completed" || result.outcome == "denied");
                });
            }
        });
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn enrolled_uid_mismatch_denies_before_grant() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let request_json = valid_request_json(&challenge, &digest(b"target"));
        let envelope = signed_qga_envelope(&request_json, 0, fixture_binding);
        let dir = temp_dir("uid");
        let keys = [test_key(0)];
        let result = run_with(
            envelope.as_bytes(),
            &keys,
            "other-uid",
            &dir,
            1_800_000_000,
            |_| panic!("wrong enrolled UID must never spawn"),
        );
        assert_eq!(result.outcome, "denied");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expired_grant_denies() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let request_json = valid_request_json(&challenge, &digest(b"target"));
        let envelope = signed_qga_envelope(&request_json, 0, fixture_binding);
        let dir = temp_dir("expired");
        let keys = [test_key(0)];
        let result = run_with(
            envelope.as_bytes(),
            &keys,
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_030,
            |_| panic!("expired grant must never spawn"),
        );
        assert_eq!(result.outcome, "denied");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn foreign_key_denies() {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let request_json = valid_request_json(&challenge, &digest(b"target"));
        let envelope = signed_qga_envelope(&request_json, 0, fixture_binding);
        let dir = temp_dir("foreign");
        let keys = [test_key(1)];
        let result = run_with(
            envelope.as_bytes(),
            &keys,
            "11111111-1111-4111-8111-111111111111",
            &dir,
            1_800_000_000,
            |_| panic!("foreign key must never spawn"),
        );
        assert_eq!(result.outcome, "denied");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keys_file_parser_is_strict() {
        let dir = temp_dir("keys");
        let path = dir.join(KEYS_FILE_NAME);
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
        std::fs::write(
            &path,
            serde_json::json!({"version": 1, "keys": [key]}).to_string(),
        )
        .unwrap();
        assert_eq!(load_keys(&path).unwrap(), vec![[9u8; 32]]);
        std::fs::write(&path, "{\"version\":2,\"keys\":[]}").unwrap();
        assert!(load_keys(&path).is_err());
        std::fs::write(&path, "not json").unwrap();
        assert!(load_keys(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn command_line_quoting_follows_msvcrt_rules() {
        use super::windows_runner::quote_arg;
        assert_eq!(quote_arg("cmd.exe"), "cmd.exe");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("C:\\dir\\"), "C:\\dir\\");
        assert_eq!(
            quote_arg("C:\\dir with space\\"),
            "\"C:\\dir with space\\\\\""
        );
    }

    #[cfg(windows)]
    static WINDOWS_RUNNER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(windows)]
    fn powershell_spec(script: &str) -> CommandSpec {
        let root = std::env::var("SystemRoot").expect("Windows system directory");
        CommandSpec {
            executable: format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe"),
            args: vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                format!("$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; {script}"),
            ],
            cwd: None,
            deadline: Duration::from_secs(10),
            output_limit: 16 * 1024,
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershell_can_launch_native_commands_inside_job() {
        let _guard = WINDOWS_RUNNER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        for program in ["whoami.exe", "hostname.exe"] {
            let spec = powershell_spec(&format!(
                "& \"$env:SystemRoot\\System32\\{program}\"; exit $LASTEXITCODE"
            ));
            let result = super::windows_runner::spawn(&spec);
            assert_eq!(result.outcome, "completed", "{program}: {result:?}");
            assert_eq!(result.exit_code, Some(0), "{program}: {result:?}");
            assert!(!result.stdout.is_empty(), "{program} produced no output");
            assert!(result.stderr.is_empty(), "{program}: {result:?}");
        }
    }

    #[cfg(windows)]
    fn assert_recorded_child_stopped(result: &RunOutcome) {
        assert_recorded_child_output_stopped(&result.stdout);
    }

    #[cfg(windows)]
    pub(super) fn assert_recorded_child_output_stopped(stdout: &[u8]) {
        use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let output = String::from_utf8_lossy(stdout);
        let pid: u32 = output
            .lines()
            .find_map(|line| line.strip_prefix("child="))
            .expect("spawned child PID was not recorded")
            .trim()
            .parse()
            .expect("child PID");
        // A reaped child may no longer have a process object to open. If it
        // does, its exit code must prove it is no longer running.
        if let Ok(handle) = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            let mut code = 0;
            let status = unsafe { GetExitCodeProcess(handle, &mut code) };
            unsafe {
                let _ = CloseHandle(handle);
            }
            status.expect("child exit code");
            assert_ne!(
                code, STILL_ACTIVE.0 as u32,
                "child survived the command job"
            );
        }
    }

    #[cfg(windows)]
    pub(super) const START_LONG_CHILD: &str = r#"$child = Start-Process -FilePath "$env:SystemRoot\System32\ping.exe" -ArgumentList @('-n','60','127.0.0.1') -NoNewWindow -PassThru; Write-Output "child=$($child.Id)";"#;

    #[cfg(windows)]
    #[test]
    fn root_exit_terminates_descendants_before_draining_pipes() {
        let _guard = WINDOWS_RUNNER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let result = super::windows_runner::spawn(&powershell_spec(START_LONG_CHILD));
        assert_eq!(result.outcome, "completed", "{result:?}");
        assert_eq!(result.exit_code, Some(0), "{result:?}");
        assert!(
            result.duration < Duration::from_secs(10),
            "reader join outlived root: {result:?}"
        );
        assert_recorded_child_stopped(&result);
    }

    #[cfg(windows)]
    #[test]
    fn deadline_terminates_the_entire_command_tree() {
        let _guard = WINDOWS_RUNNER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut spec = powershell_spec(&format!("{START_LONG_CHILD} Start-Sleep -Seconds 60"));
        // A cold hosted Windows runner can spend five seconds starting
        // PowerShell/Start-Process before it records the child. Use the pilot's
        // maximum deadline so this still proves descendant termination rather
        // than accidentally testing only cancellation during interpreter startup.
        spec.deadline = Duration::from_secs(20);
        let result = super::windows_runner::spawn(&spec);
        assert_eq!(result.outcome, "deadline", "{result:?}");
        assert!(result.duration < Duration::from_secs(30), "{result:?}");
        assert_recorded_child_stopped(&result);
    }

    #[cfg(windows)]
    #[test]
    fn output_limit_terminates_the_entire_command_tree() {
        let _guard = WINDOWS_RUNNER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let spec = powershell_spec(&format!(
            "{START_LONG_CHILD} [Console]::Out.Write(('x' * 65536)); Start-Sleep -Seconds 60"
        ));
        let result = super::windows_runner::spawn(&spec);
        assert_eq!(result.outcome, "output-limit", "{result:?}");
        assert!(result.truncated);
        assert!(result.stdout.len() + result.stderr.len() <= spec.output_limit);
        assert_recorded_child_stopped(&result);
    }
}
