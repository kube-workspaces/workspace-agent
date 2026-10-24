//! Machine-owned service configuration and restart policy, testable off Windows.
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub worker_enabled: bool,
    pub port: u16,
    pub worker_args: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            worker_enabled: true,
            port: 44787,
            worker_args: [
                "--capture-video",
                "--capture-audio",
                "--clipboard",
                "--input",
                "--resize",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}
impl Config {
    pub fn read(dir: &Path) -> Result<Self, String> {
        let config: Self = match std::fs::read_to_string(dir.join("service.json")) {
            Ok(text) => serde_json::from_str(text.trim_start_matches('\u{feff}'))
                .map_err(|_| "service.json malformed or contains unsupported fields")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => return Err(format!("service.json read: {error}")),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("service port must be non-zero".into());
        }
        let mut args = self.worker_args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--capture-video"
                | "--capture-audio"
                | "--clipboard"
                | "--input"
                | "--resize"
                | "--keep-console-display" => {}
                "--capture-output" | "--capture-fps" | "--capture-bitrate-bps" => {
                    let value = args
                        .next()
                        .and_then(|value| value.parse::<u32>().ok())
                        .ok_or_else(|| format!("{arg} needs an unsigned integer"))?;
                    if arg != "--capture-output" && value == 0 {
                        return Err(format!("{arg} must be non-zero"));
                    }
                    if arg == "--capture-fps" && value > 120 {
                        return Err("capture fps exceeds 120".into());
                    }
                }
                "--capture-output-name" => {
                    let value = args.next().ok_or("capture output name missing")?;
                    if value.is_empty() || value.contains('\0') {
                        return Err("capture output name invalid".into());
                    }
                }
                _ => return Err(format!("unsupported service worker argument: {arg}")),
            }
        }
        if self.worker_args.iter().any(|a| a == "--resize")
            && !self.worker_args.iter().any(|a| a == "--capture-video")
        {
            return Err("resize requires capture video".into());
        }
        Ok(())
    }
}

#[derive(Default)]
#[cfg(any(windows, test))]
pub struct Restart {
    failures: u32,
    next: u64,
}
#[cfg(any(windows, test))]
impl Restart {
    pub fn ready(&self, now: u64) -> bool {
        now >= self.next
    }
    pub fn failed(&mut self, now: u64) {
        let delay = (1u64 << self.failures.min(6)).min(60);
        self.failures = self.failures.saturating_add(1);
        self.next = now.saturating_add(delay);
    }
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Quote argv using the Windows CommandLineToArgv/CRT backslash rules.
#[cfg(any(windows, test))]
pub fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            out.push_str(&"\\".repeat(slashes));
        }
        out.push(ch);
        slashes = 0;
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_cannot_override_identity_or_launch_arbitrary_commands() {
        assert!(Config::default().validate().is_ok());
        for flag in [
            "--workspace-uid",
            "--data-dir",
            "--background",
            "--stop-event",
            "cmd.exe",
        ] {
            let config = Config {
                worker_args: vec![flag.into()],
                ..Config::default()
            };
            assert!(config.validate().is_err());
        }
        assert!(Config {
            worker_args: vec!["--capture-fps".into(), "0".into()],
            ..Config::default()
        }
        .validate()
        .is_err());
    }
    #[test]
    fn backoff_is_bounded_and_can_reset_after_session_change() {
        let mut retry = Restart::default();
        for i in 0..20 {
            let now = i * 100;
            retry.failed(now);
            assert!(!retry.ready(now));
            assert!(retry.ready(now + 60));
        }
        retry.reset();
        assert!(retry.ready(0));
    }
    #[test]
    fn quotes_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote("C:\\a b\\"), "\"C:\\a b\\\\\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
    }
}
