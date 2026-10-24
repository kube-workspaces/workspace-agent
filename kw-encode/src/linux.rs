//! CPU-only H.264 through GStreamer's x264enc. appsink alignment=au preserves
//! access-unit boundaries and caller timestamps; no stdout Annex-B guessing.
use super::{nal_types, Chunk, Error, Settings};
use kw_platform::linux::{Helper, Role};
use serde_json::json;

pub struct Stream {
    helper: Helper,
    settings: Settings,
}

impl Stream {
    pub fn new(settings: &Settings) -> Result<Self, Error> {
        super::h264_level(settings)?;
        let mut helper = Helper::new(Role::Encoder).map_err(Error::Configure)?;
        helper
            .call(json!({"op":"open", "settings":settings}), &[])
            .map_err(Error::Configure)?;
        Ok(Self {
            helper,
            settings: settings.clone(),
        })
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }
    pub fn frame_bytes(&self) -> usize {
        self.settings.width as usize * self.settings.height as usize * 3 / 2
    }
    pub fn push(
        &mut self,
        frame: &[u8],
        timestamp: i64,
        force_idr: bool,
    ) -> Result<Vec<Chunk>, Error> {
        let (meta, bytes) = self
            .helper
            .call(
                json!({"op":"encode", "timestamp100ns":timestamp, "forceIdr":force_idr}),
                frame,
            )
            .map_err(Error::Stream)?;
        let timestamp = meta["timestamp100ns"]
            .as_i64()
            .ok_or_else(|| Error::Stream("missing encoder timestamp".into()))?;
        let types = nal_types(&bytes);
        if !types.iter().any(|t| *t == 1 || *t == 5) {
            return Err(Error::Stream("encoder returned no H.264 picture".into()));
        }
        Ok(vec![Chunk {
            keyframe: types.contains(&5),
            nal_types: types,
            timestamp_100ns: timestamp,
            bytes,
        }])
    }
    pub fn reconfigure(&mut self, settings: &Settings) -> Result<(), Error> {
        // A fresh x264 instance gives the resized stream SPS/PPS and an IDR.
        *self = Self::new(settings)?;
        Ok(())
    }
    pub fn finish(self) -> Result<Vec<Chunk>, Error> {
        // zerolatency + bframes=0: every push already returned its access unit.
        Ok(Vec::new())
    }
}
