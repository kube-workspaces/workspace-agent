use super::MixFormat;
use crate::Error;
use kw_platform::linux::{Helper, Role};
use serde_json::json;
use std::sync::Mutex;

pub struct LoopbackTap {
    helper: Mutex<Helper>,
    volume: Mutex<(f32, bool)>,
}

impl LoopbackTap {
    pub fn start() -> Result<Self, Error> {
        let mut helper = Helper::new(Role::Audio).map_err(|_| Error::NoEndpoint)?;
        helper
            .call(json!({"op":"open"}), &[])
            .map_err(|_| Error::NoEndpoint)?;
        Ok(Self {
            helper: Mutex::new(helper),
            volume: Mutex::new((1.0, false)),
        })
    }
    pub fn mix_format(&self) -> MixFormat {
        MixFormat {
            rate: 48000,
            channels: 2,
            bits: 32,
            float: true,
        }
    }
    pub fn read(&self, timeout_ms: u32) -> Result<Option<(MixFormat, Vec<u8>, u32)>, Error> {
        let (meta, bytes) = self
            .helper
            .lock()
            .map_err(|_| Error::DeviceLost)?
            .call(json!({"op":"audio", "timeoutMs":timeout_ms}), &[])
            .map_err(|_| Error::DeviceLost)?;
        if meta["empty"] == true {
            return Ok(None);
        }
        if bytes.len() % 8 != 0 {
            return Err(Error::Codec("ragged Linux audio buffer".into()));
        }
        if let Ok(mut volume) = self.volume.lock() {
            *volume = (
                meta["volume"].as_f64().unwrap_or(1.0) as f32,
                meta["muted"].as_bool().unwrap_or(false),
            );
        }
        let frames = bytes.len() as u32 / 8;
        Ok(Some((self.mix_format(), bytes, frames)))
    }
    pub fn master_volume(&self) -> (f32, bool) {
        self.volume.lock().map(|v| *v).unwrap_or((0.0, true))
    }
}
