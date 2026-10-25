//! Linux bounded pipe runner. Membership is established before exec; unlike
//! process-group killing, cgroup.kill includes children that call setsid().
use super::{CommandSpec, RunOutcome};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Group(PathBuf);

// A tiny independent watchdog holds the cgroup kill handle. It survives runner
// loss and kills the entire group on pipe closure or deadline, including
// descendants whose immediate parent was killed by PR_SET_PDEATHSIG.
struct Watchdog {
    pid: libc::pid_t,
    pipe: Option<File>,
}

impl Watchdog {
    fn start(group: &Group, deadline: Duration) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        let kill = File::options()
            .write(true)
            .open(group.0.join("cgroup.kill"))?;
        let path = std::ffi::CString::new(group.0.as_os_str().as_encoded_bytes())?;
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let read = unsafe { File::from_raw_fd(fds[0]) };
        let write = unsafe { File::from_raw_fd(fds[1]) };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // No allocation, Rust destructors or locks in this post-fork child.
            // Close inherited result pipes: otherwise QGA waits for us to exit.
            unsafe {
                libc::close(write.as_raw_fd());
                libc::close(0);
                libc::close(1);
                libc::close(2);
                let mut event = libc::pollfd {
                    fd: read.as_raw_fd(),
                    events: libc::POLLHUP,
                    revents: 0,
                };
                // Signals may interrupt poll. A monotonic absolute deadline
                // prevents repeated interruptions from extending the lease.
                let mut start: libc::timespec = std::mem::zeroed();
                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut start);
                let budget_ms = deadline.as_millis().min(i32::MAX as u128) as i64;
                loop {
                    let mut now: libc::timespec = std::mem::zeroed();
                    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
                    let elapsed = (now.tv_sec - start.tv_sec) * 1000
                        + (now.tv_nsec - start.tv_nsec) / 1_000_000;
                    let remaining = budget_ms.saturating_sub(elapsed);
                    if remaining <= 0 || libc::poll(&mut event, 1, remaining as i32) >= 0 {
                        break;
                    }
                }
                libc::write(kill.as_raw_fd(), b"1".as_ptr().cast(), 1);
                for _ in 0..100 {
                    if libc::rmdir(path.as_ptr()) == 0 {
                        break;
                    }
                    let delay = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 10_000_000,
                    };
                    libc::nanosleep(&delay, std::ptr::null_mut());
                }
                libc::_exit(0);
            }
        }
        Ok(Self {
            pid,
            pipe: Some(write),
        })
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Closing the pipe signals normal cleanup.
        drop(self.pipe.take());
        unsafe {
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

impl Group {
    fn create() -> io::Result<Self> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
        let name = nonce.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let path = PathBuf::from("/sys/fs/cgroup").join(format!("kw-exec-{name}"));
        fs::create_dir(&path)?;
        let group = Self(path);
        // No unbounded fork tree; fail closed if pids controller or cgroup.kill
        // is unavailable. The parent cgroup must have pids delegated/enabled.
        fs::write(group.0.join("pids.max"), b"16")?;
        File::options()
            .write(true)
            .open(group.0.join("cgroup.kill"))?;
        Ok(group)
    }

    fn kill(&self) -> io::Result<()> {
        fs::write(self.0.join("cgroup.kill"), b"1")
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        let _ = self.kill();
        // cgroup removal can briefly race delivery of SIGKILL to descendants.
        for _ in 0..100 {
            if fs::remove_dir(&self.0).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Read only a bounded amount per tick so continuous output cannot starve the
// deadline or the other stream. Excess bytes are never buffered.
fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, remaining: &mut usize) -> io::Result<bool> {
    let mut buf = [0u8; 4096];
    for _ in 0..8 {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let keep = n.min(*remaining);
                output.extend_from_slice(&buf[..keep]);
                *remaining -= keep;
                if keep != n {
                    return Ok(true);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

pub(super) fn spawn(spec: &CommandSpec) -> RunOutcome {
    let started = Instant::now();
    let mut result = RunOutcome {
        outcome: "spawn-failed",
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        truncated: false,
        duration: Duration::ZERO,
    };
    let run = (|| -> io::Result<()> {
        if !spec.executable.starts_with('/') {
            return Err(io::Error::other(
                "Linux executable must be an absolute path",
            ));
        }
        let group = Group::create()?;
        let _watchdog = Watchdog::start(&group, spec.deadline + Duration::from_secs(1))?;
        let membership = File::options()
            .write(true)
            .open(group.0.join("cgroup.procs"))?;
        let fd = membership.as_raw_fd();
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", "/root")
            .env("USER", "root")
            .env("LOGNAME", "root")
            .env("LANG", "C.UTF-8");
        command.current_dir(spec.cwd.as_deref().unwrap_or("/"));
        // Only async-signal-safe syscalls between fork and exec. Writing 0
        // moves the child itself into the cgroup before any guest code runs.
        unsafe {
            command.pre_exec(move || {
                if libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let supervised = (|| -> io::Result<()> {
            nonblocking(&stdout)?;
            nonblocking(&stderr)?;
            let mut remaining = spec.output_limit;
            result.outcome = "completed";
            loop {
                let overflow = drain(&mut stdout, &mut result.stdout, &mut remaining)?
                    | drain(&mut stderr, &mut result.stderr, &mut remaining)?;
                if overflow {
                    result.truncated = true;
                    result.outcome = "output-limit";
                    break;
                }
                if let Some(status) = child.try_wait()? {
                    // Match the common integer exit-code contract for signals.
                    use std::os::unix::process::ExitStatusExt;
                    result.exit_code =
                        Some(status.code().unwrap_or(128 + status.signal().unwrap_or(0)));
                    break;
                }
                if started.elapsed() >= spec.deadline {
                    result.outcome = "deadline";
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            group.kill()?;
            let status = child.wait()?;
            if result.exit_code.is_none() {
                use std::os::unix::process::ExitStatusExt;
                result.exit_code =
                    Some(status.code().unwrap_or(128 + status.signal().unwrap_or(0)));
            }
            // Pipes are nonblocking even if an authorized root deliberately
            // moved a descendant elsewhere. Never wait indefinitely for EOF.
            result.truncated |= drain(&mut stdout, &mut result.stdout, &mut remaining)?
                | drain(&mut stderr, &mut result.stderr, &mut remaining)?;
            if result.truncated {
                result.outcome = "output-limit";
            }
            Ok(())
        })();
        if supervised.is_err() {
            let _ = group.kill();
            let _ = child.kill();
            let _ = child.wait();
            result.outcome = "runner-error";
        }
        supervised
    })();
    if let Err(error) = run {
        // Infrastructure errors only, never invocation/output in normal logs.
        let detail = format!("Linux process supervision: {error}");
        let remaining = spec
            .output_limit
            .saturating_sub(result.stdout.len() + result.stderr.len());
        result
            .stderr
            .extend_from_slice(&detail.as_bytes()[..detail.len().min(remaining)]);
    }
    result.duration = started.elapsed();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_requires_absolute_executable() {
        let mut command = spec("true");
        command.executable = "true".into();
        let result = spawn(&command);
        assert_eq!(result.outcome, "spawn-failed");
        assert_eq!(result.exit_code, None);
    }

    fn spec(script: &str) -> CommandSpec {
        CommandSpec {
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            cwd: None,
            deadline: Duration::from_secs(1),
            output_limit: 16 * 1024,
        }
    }

    #[test]
    #[ignore = "subprocess helper for linux_runner_loss_kills_descendants"]
    fn runner_loss_child() {
        let Ok(path) = std::env::var("KW_EXEC_TEST_CHILD_FILE") else {
            return;
        };
        let _ = spawn(&spec(&format!("sleep 30 & echo $! > '{path}'; wait")));
    }

    #[test]
    #[ignore = "requires root and writable cgroup v2; see Linux management runbook"]
    fn linux_runner_loss_kills_descendants() {
        let path = std::env::temp_dir().join(format!("kw-exec-loss-{}", std::process::id()));
        let mut runner = Command::new(std::env::current_exe().unwrap())
            .args([
                "management_exec::linux_runner::tests::runner_loss_child",
                "--ignored",
                "--exact",
            ])
            .env("KW_EXEC_TEST_CHILD_FILE", &path)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut pid = None;
        for _ in 0..200 {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(value) = text.trim().parse::<u32>() {
                    pid = Some(value);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        runner.kill().unwrap();
        runner.wait().unwrap();
        let pid = pid.expect("supervised child never started");
        for _ in 0..300 {
            let status = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if status.is_empty() || status.split_whitespace().nth(2) == Some("Z") {
                fs::remove_file(path).unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("descendant survived runner SIGKILL");
    }

    // Run on a disposable Linux host/container with root and writable cgroup
    // v2 (pids controller). Normal unprivileged CI does not claim this proof.
    #[test]
    #[ignore = "requires root and writable cgroup v2; see Linux management runbook"]
    fn linux_real_process_supervision() {
        let mut command = spec("printf '%s' \"$1\"; printf err >&2; pwd; exit 7");
        command.args.extend(["sh".into(), "a b;$(false)".into()]);
        command.cwd = Some("/tmp".into());
        let result = spawn(&command);
        assert_eq!(result.outcome, "completed", "{result:?}");
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stdout, b"a b;$(false)/tmp\n");
        assert_eq!(result.stderr, b"err");

        for (script, outcome) in [
            ("sleep 30 & echo $!; wait", "deadline"),
            ("sleep 30 & echo $!", "completed"),
            (
                "setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $!; wait",
                "deadline",
            ),
            (
                "sleep 30 & echo $!; while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done",
                "output-limit",
            ),
        ] {
            let result = spawn(&spec(script));
            assert_eq!(result.outcome, outcome, "{result:?}");
            assert!(result.duration < Duration::from_secs(3));
            assert!(result.stdout.len() + result.stderr.len() <= 16 * 1024);
            let text = String::from_utf8_lossy(&result.stdout);
            let pid = text.lines().next().unwrap().parse::<u32>().unwrap();
            for _ in 0..100 {
                let status = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                if status.is_empty() || status.split_whitespace().nth(2) == Some("Z") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let status = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            assert!(
                status.is_empty() || status.split_whitespace().nth(2) == Some("Z"),
                "descendant survived: {status}"
            );
        }
    }
}
