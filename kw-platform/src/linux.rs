//! GNOME/Wayland integration in the ordinary logged-in user's session.
//!
//! The embedded helper uses the distro's introspected Gio/GStreamer bindings;
//! it is never downloaded or evaluated from the network. A private socketpair
//! carries bounded metadata and binary frames. No TCP listener or arbitrary
//! command/argv operation is exposed by the helper.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const MAX_HEADER: usize = 128 * 1024;
const MAX_PAYLOAD: usize = 128 * 1024 * 1024;
const SCRIPT: &str = include_str!("linux_helper.py");

/// Fixed helper roles; media crates cannot supply arbitrary script text.
pub enum Role {
    Desktop,
    Inventory,
    Encoder,
    Audio,
}

/// One bounded request/response helper, owned and reaped with its OS backend.
pub struct Helper {
    child: Child,
    socket: UnixStream,
    failed: bool,
}

impl Helper {
    pub fn new(role: Role) -> Result<Self, String> {
        let (socket, child_socket) = UnixStream::pair().map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(8)))
            .map_err(|e| e.to_string())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(8)))
            .map_err(|e| e.to_string())?;
        let input: OwnedFd = child_socket.try_clone().map_err(|e| e.to_string())?.into();
        let output: OwnedFd = child_socket.into();
        let role = match role {
            Role::Desktop => "desktop",
            Role::Inventory => "inventory",
            Role::Encoder => "encoder",
            Role::Audio => "audio",
        };
        let child = Command::new("/usr/bin/python3")
            .args(["-u", "-c", SCRIPT, role])
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Linux media helper unavailable: {e}"))?;
        Ok(Self {
            child,
            socket,
            failed: false,
        })
    }

    pub fn call(&mut self, mut request: Value, payload: &[u8]) -> Result<(Value, Vec<u8>), String> {
        if self.failed {
            return Err("linux-helper-unavailable".into());
        }
        if payload.len() > MAX_PAYLOAD {
            return Err("linux-helper-payload-too-large".into());
        }
        request["bytes"] = json!(payload.len());
        let header = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        if header.len() > MAX_HEADER {
            return Err("linux-helper-header-too-large".into());
        }
        let result = (|| -> Result<(Value, Vec<u8>), String> {
            self.socket
                .write_all(&(header.len() as u32).to_be_bytes())
                .and_then(|()| self.socket.write_all(&header))
                .and_then(|()| self.socket.write_all(payload))
                .map_err(|e| format!("linux-helper-write: {e}"))?;
            let mut size = [0u8; 4];
            self.socket
                .read_exact(&mut size)
                .map_err(|e| format!("linux-helper-read: {e}"))?;
            let size = u32::from_be_bytes(size) as usize;
            if size > MAX_HEADER {
                return Err("linux-helper-invalid-header".into());
            }
            let mut bytes = vec![0; size];
            self.socket
                .read_exact(&mut bytes)
                .map_err(|e| e.to_string())?;
            let response: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let size = response["bytes"]
                .as_u64()
                .filter(|n| *n <= MAX_PAYLOAD as u64)
                .ok_or("linux-helper-invalid-payload")? as usize;
            let mut payload = vec![0; size];
            self.socket
                .read_exact(&mut payload)
                .map_err(|e| e.to_string())?;
            if let Some(error) = response["error"].as_str() {
                return Err(error.to_owned());
            }
            Ok((response, payload))
        })();
        // A timeout or a corrupt reply cannot leave a live, desynchronized
        // helper handling later requests against the wrong frame/session.
        if result.is_err() {
            self.failed = true;
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        result
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

static DESKTOP: Mutex<Weak<Mutex<Helper>>> = Mutex::new(Weak::new());

/// Share one Mutter remote-desktop session among capture/input/clipboard.
/// Its final owner releases the helper, PipeWire stream and pressed input.
pub fn desktop() -> Result<Arc<Mutex<Helper>>, String> {
    desktop_for(None)
}

pub fn desktop_for(name: Option<&str>) -> Result<Arc<Mutex<Helper>>, String> {
    let mut weak = DESKTOP.lock().map_err(|_| "linux-desktop-lock")?;
    if let Some(helper) = weak.upgrade() {
        let healthy = !helper.lock().map_err(|_| "linux-desktop-lock")?.failed;
        if healthy {
            return Ok(helper);
        }
    }
    let helper = Arc::new(Mutex::new(Helper::new(Role::Desktop)?));
    helper
        .lock()
        .map_err(|_| "linux-desktop-lock")?
        .call(json!({"op":"open", "name":name}), &[])?;
    *weak = Arc::downgrade(&helper);
    Ok(helper)
}

pub fn call(request: Value, payload: &[u8]) -> Result<(Value, Vec<u8>), String> {
    desktop()?
        .lock()
        .map_err(|_| "linux-desktop-lock")?
        .call(request, payload)
}

pub fn inventory() -> Result<super::Inventory, super::Error> {
    let response = Helper::new(Role::Inventory)
        .and_then(|mut h| h.call(json!({"op":"inventory"}), &[]))
        .map_err(|error| {
            if error.contains("console-session-inactive-or-locked") {
                super::Error::SessionLost("console-session-inactive-or-locked")
            } else {
                super::Error::Backend(error)
            }
        })?
        .0;
    let mut inventory: super::Inventory =
        serde_json::from_value(response["inventory"].clone()).map_err(|_| super::Error::Empty)?;
    inventory.agent_version = option_env!("KW_AGENT_VERSION")
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .into();
    inventory.platform = format!(
        "linux-{}",
        match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        }
    );
    Ok(inventory)
}

pub fn selected(output_index: u32, name: Option<&str>) -> Result<super::OutputInfo, String> {
    let inventory = inventory().map_err(|e| e.to_string())?;
    let outputs: Vec<_> = inventory
        .adapters
        .into_iter()
        .flat_map(|a| a.outputs)
        .collect();
    match name {
        Some(name) => outputs.into_iter().find(|o| o.name == name),
        None => outputs.into_iter().nth(output_index as usize),
    }
    .ok_or_else(|| "display-output-unavailable".into())
}
