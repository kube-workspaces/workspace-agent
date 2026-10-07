//! Platform stubs. Real backends (service/session helpers, capture, input,
//! audio, display/mode management) arrive with the P0-gated implementation.
//! These stubs let packaging, installers and CI verify per-OS builds now.

/// What the binary knows about where it runs.
pub struct PlatformInfo {
    pub os: &'static str,
    pub arch: &'static str,
    /// Session context: service vs console vs unknown. Backends need this to
    /// reach the interactive desktop; the stub only reports it.
    pub context: &'static str,
}

#[cfg(target_os = "windows")]
mod inner {
    use super::PlatformInfo;

    pub fn info() -> PlatformInfo {
        PlatformInfo {
            os: "windows",
            arch: std::env::consts::ARCH,
            context: context(),
        }
    }

    fn context() -> &'static str {
        // Real detection (WTS session / service status) arrives with the
        // Windows service backend. Never assume console here.
        "unknown-service-or-console"
    }
}

#[cfg(target_os = "linux")]
mod inner {
    use super::PlatformInfo;

    pub fn info() -> PlatformInfo {
        PlatformInfo {
            os: "linux",
            arch: std::env::consts::ARCH,
            context: context(),
        }
    }

    fn context() -> &'static str {
        // Real detection (logind session, X11/Wayland presence) arrives with
        // the Linux adapters. Never assume a desktop session here.
        "unknown-session"
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod inner {
    use super::PlatformInfo;

    pub fn info() -> PlatformInfo {
        PlatformInfo {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            context: "unsupported",
        }
    }
}

pub fn info() -> PlatformInfo {
    inner::info()
}

pub fn describe() -> String {
    let info = info();
    format!("{}-{}_{}", info.os, info.arch, info.context)
}
