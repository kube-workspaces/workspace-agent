use super::{pad16, CaptureInfo, CapturedFrame};
use crate::{linux, Error};
use serde_json::json;
use std::sync::{Arc, Mutex};

pub const DXGI_TIMEOUT_DEFAULT_MS: u32 = 100;

// GNOME's screencast session keeps the desktop active; do not change a global
// power policy. Lock/logoff are checked on every acquire and revoke capture.
pub struct DisplayAwake;
impl DisplayAwake {
    pub fn new() -> Result<Self, Error> {
        Ok(Self)
    }
}

pub struct Duplicator {
    helper: Arc<Mutex<linux::Helper>>,
    width: u32,
    height: u32,
    info: CaptureInfo,
}

impl Duplicator {
    pub fn new(index: u32) -> Result<Self, Error> {
        let output = linux::selected(index, None).map_err(Error::Backend)?;
        Self::new_named(&output.name)
    }

    pub fn new_named(name: &str) -> Result<Self, Error> {
        let output = linux::selected(0, Some(name)).map_err(|error| {
            if error.contains("console-session-inactive-or-locked") {
                Error::SessionLost("console-session-inactive-or-locked")
            } else {
                Error::Backend(error)
            }
        })?;
        let helper = linux::desktop_for(Some(name)).map_err(Error::Backend)?;
        helper.lock().map_err(|_| Error::Backend("desktop lock".into()))?
            .call(json!({"op":"captureOpen", "name":name,"width":output.width,"height":output.height}), &[])
            .map_err(Error::Backend)?;
        Ok(Self {
            helper,
            width: output.width,
            height: output.height,
            info: CaptureInfo {
                backend: "GNOME Mutter/PipeWire",
                output: name.into(),
                adapter: "render adapter unobserved".into(),
                vendor_id: 0,
                device_id: 0,
                software: false,
            },
        })
    }

    pub fn info(&self) -> Option<&CaptureInfo> {
        Some(&self.info)
    }
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
    pub fn padded_size(&self) -> (u32, u32) {
        (pad16(self.width), pad16(self.height))
    }

    pub fn capture(&mut self, timeout_ms: u32) -> Result<Option<CapturedFrame>, Error> {
        let (meta, bgra) = self
            .helper
            .lock()
            .map_err(|_| Error::Backend("desktop lock".into()))?
            .call(json!({"op":"frame", "timeoutMs":timeout_ms}), &[])
            .map_err(|_| Error::SessionLost("GNOME session or PipeWire stream unavailable"))?;
        if meta["empty"] == true {
            return Ok(None);
        }
        let width = meta["width"].as_u64().ok_or(Error::Empty)? as u32;
        let height = meta["height"].as_u64().ok_or(Error::Empty)? as u32;
        let stride = meta["stride"].as_u64().ok_or(Error::Empty)? as usize;
        if width != self.width || height != self.height {
            return Err(Error::SessionLost("GNOME display mode changed"));
        }
        if width == 0
            || height == 0
            || width > 8192
            || height > 8192
            || stride < width as usize * 4
            || bgra.len() < stride * height as usize
        {
            return Err(Error::Backend("invalid PipeWire frame geometry".into()));
        }
        Ok(Some(CapturedFrame {
            width,
            height,
            padded_width: pad16(width),
            padded_height: pad16(height),
            nv12: super::bgra_to_nv12_padded(&bgra, width, height, stride),
            accumulated: 1,
        }))
    }
}
