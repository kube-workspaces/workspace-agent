//! Software H.264 encoding through the inbox Media Foundation transform.
//!
//! Input is NV12 system-memory frames; output is raw H.264 (Annex-B NAL
//! units as the Microsoft MFT emits them — verified by parsing, not by
//! assuming). No capture, no GPU dependency: this is the mandatory software
//! path from the capability targets. Hardware MFTs are independently
//! advertised capabilities, never relabeled software.
//!
//! Timestamps use 100ns units (MF convention). Only Windows is implemented;
//! other platforms return [`Error::Gated`].

use serde::{Deserialize, Serialize};

/// Encoder settings. Baseline profile + bounded GOP is the low-latency
/// starting point; B-frame behavior is *measured* from output, not assumed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub width: u32,
    pub height: u32,
    /// Frames per second (numerator).
    pub fps: u32,
    /// Average bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Maximum keyframe spacing in frames.
    pub max_keyframe_spacing: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 2_000_000,
            max_keyframe_spacing: 30,
        }
    }
}

/// One encoded chunk with its NAL-unit inventory.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Chunk {
    /// Raw bytes as emitted (Annex-B start codes preserved).
    pub bytes: Vec<u8>,
    /// NAL unit types present (`byte & 0x1f`), in order.
    pub nal_types: Vec<u8>,
    /// Presentation timestamp in 100ns units.
    pub timestamp_100ns: i64,
    pub keyframe: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Gated(&'static str),
    Os(u32),
    /// Encoder refused the configuration (unsupported profile/level/size).
    Configure(String),
    /// A frame or drain call failed mid-stream.
    Stream(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Gated(what) => write!(f, "encoder P0-gated: {what}"),
            Error::Os(code) => write!(f, "media foundation call failed: 0x{code:08x}"),
            Error::Configure(what) => write!(f, "encoder refused configuration: {what}"),
            Error::Stream(what) => write!(f, "encode stream failed: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// Split an Annex-B byte stream into NAL unit types (`byte & 0x1f`).
pub fn nal_types(bytes: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut i = 0;
    while i + 4 < bytes.len() {
        let start = if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            3
        } else if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 0 && bytes[i + 3] == 1 {
            4
        } else {
            i += 1;
            continue;
        };
        types.push(bytes[i + start] & 0x1f);
        i += start + 1;
    }
    types
}

/// Encode `frames` NV12 buffers (width*height*3/2 bytes each) at 30fps-style
/// spacing derived from [`Settings::fps`]. Returns encoded chunks in order.
/// Implemented over [`StreamEncoder`]: one persistent transform per call.
pub fn encode_nv12(settings: &Settings, frames: &[Vec<u8>]) -> Result<Vec<Chunk>, Error> {
    // Cheap validation before touching any OS media stack.
    if settings.width == 0 || settings.height == 0 || settings.fps == 0 {
        return Err(Error::Configure("zero dimension or rate".into()));
    }
    let frame_bytes = settings.width as usize * settings.height as usize * 3 / 2;
    for (index, frame) in frames.iter().enumerate() {
        if frame.len() != frame_bytes {
            return Err(Error::Configure(format!(
                "frame {index} is {} bytes, expected {frame_bytes}",
                frame.len()
            )));
        }
    }
    let mut encoder = StreamEncoder::new(settings)?;
    let step_100ns: i64 = 10_000_000 / settings.fps.max(1) as i64;
    let mut chunks = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        chunks.extend(encoder.push(frame, index as i64 * step_100ns, false)?);
    }
    chunks.extend(encoder.finish()?);
    Ok(chunks)
}

/// Persistent streaming H.264 encoder: one OS transform across many frames.
///
/// Constructed once (in the thread that feeds it — COM apartment rules),
/// `push`ed per captured frame with caller timestamps, `finish`ed for the
/// trailing GOP. `reconfigure` swaps dimensions/bitrate mid-stream for
/// resize ACKs. Only Windows is implemented; other platforms fail
/// construction with [`Error::Gated`] — never fake output.
pub struct StreamEncoder {
    state: inner::Stream,
}

impl StreamEncoder {
    pub fn new(settings: &Settings) -> Result<Self, Error> {
        if settings.width == 0 || settings.height == 0 || settings.fps == 0 {
            return Err(Error::Configure("zero dimension or rate".into()));
        }
        Ok(Self {
            state: inner::Stream::new(settings)?,
        })
    }

    /// Encode one NV12 frame (`width*height*3/2` bytes). `timestamp_100ns`
    /// is the caller (capture/A-V) clock; `force_idr` emits SPS/PPS/IDR for
    /// this frame (keyframe requests, reconnects, reconfigures). Returns the
    /// access units produced for this input (often zero or one).
    pub fn push(
        &mut self,
        nv12: &[u8],
        timestamp_100ns: i64,
        force_idr: bool,
    ) -> Result<Vec<Chunk>, Error> {
        let expect = self.state.frame_bytes();
        if nv12.len() != expect {
            return Err(Error::Configure(format!(
                "frame is {} bytes, expected {expect}",
                nv12.len()
            )));
        }
        self.state.push(nv12, timestamp_100ns, force_idr)
    }

    pub fn settings(&self) -> &Settings {
        self.state.settings()
    }

    /// Swap dimensions/bitrate mid-stream (resize ACK path). Drains pending
    /// output under the old type first; the next push emits the new
    /// configuration followed by a fresh IDR.
    pub fn reconfigure(&mut self, settings: &Settings) -> Result<(), Error> {
        if settings.width == 0 || settings.height == 0 || settings.fps == 0 {
            return Err(Error::Configure("zero dimension or rate".into()));
        }
        self.state.reconfigure(settings)
    }

    /// End the stream: trailing GOP output. Consumes the encoder; Drop after
    /// an abandoned (non-finished) encoder only signals end-of-stream
    /// best-effort and releases the OS objects.
    pub fn finish(self) -> Result<Vec<Chunk>, Error> {
        self.state.finish()
    }
}

#[cfg(target_os = "windows")]
mod inner {
    use super::*;
    use windows::Win32::Media::MediaFoundation::{
        eAVEncH264VLevel4, eAVEncH264VProfile_Base, CLSID_MSH264EncoderMFT, IMFTransform,
        MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFShutdown,
        MFStartup, MFVideoFormat_H264, MFVideoFormat_NV12, MFVideoInterlace_Progressive,
        MFSTARTUP_NOSOCKET, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
        MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER, MF_E_TRANSFORM_NEED_MORE_INPUT,
        MF_E_TRANSFORM_STREAM_CHANGE, MF_MT_AVG_BITRATE, MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_RATE,
        MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_MAX_KEYFRAME_SPACING,
        MF_MT_MPEG2_LEVEL, MF_MT_MPEG2_PROFILE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE,
        MF_VERSION,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };

    fn hr<T>(line: u32, result: Result<T, windows::core::Error>) -> Result<T, Error> {
        result.map_err(|e| Error::Stream(format!("line {line}: 0x{:08x}", e.code().0 as u32)))
    }

    /// One persistent software MFT. Owns its COM/MF lifetime: Drop signals
    /// end-of-stream best-effort and releases everything. Construct and feed
    /// from a single thread (MTA apartment).
    ///
    /// Forced IDRs rebuild the transform instead of poking codec APIs: a
    /// fresh software MFT always opens with SPS/PPS/IDR (verified), so the
    /// IDR guarantee holds without depending on optional MFT properties
    /// (the inbox software MFT rejects CODECAPI force-IDR mid-stream).
    /// Rebuilds are demand-paced (session starts, reconfigures, coalesced
    /// viewer demands), never per-frame.
    pub struct Stream {
        // Option so rebuild/finish can release the old transform BEFORE the
        // new one exists: two live MFT instances never overlap, and finish
        // takes (rather than forgets) the last one. None only transiently
        // inside these methods, never observed by callers.
        encoder: Option<IMFTransform>,
        settings: Settings,
        frame_bytes: usize,
        step_100ns: i64,
        finished: bool,
    }

    impl Stream {
        pub fn new(settings: &Settings) -> Result<Self, Error> {
            let frame_bytes = settings.width as usize * settings.height as usize * 3 / 2;
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            let built = unsafe { Self::build(settings, frame_bytes) };
            if built.is_err() {
                unsafe { CoUninitialize() };
            }
            built
        }

        unsafe fn build(settings: &Settings, frame_bytes: usize) -> Result<Self, Error> {
            hr(line!(), MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET))?;
            let build_result: Result<Self, Error> = (|| {
                let encoder: IMFTransform = hr(
                    line!(),
                    CoCreateInstance(
                        &CLSID_MSH264EncoderMFT,
                        Option::<&windows::core::IUnknown>::None,
                        CLSCTX_INPROC_SERVER,
                    ),
                )?;
                configure_types(&encoder, settings)?;
                hr(line!(), encoder.GetOutputStreamInfo(0))?;
                hr(
                    line!(),
                    encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
                )?;
                hr(
                    line!(),
                    encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
                )?;
                Ok(Self {
                    encoder: Some(encoder),
                    settings: settings.clone(),
                    frame_bytes,
                    step_100ns: 10_000_000 / settings.fps.max(1) as i64,
                    finished: false,
                })
            })();
            if build_result.is_err() {
                hr(line!(), MFShutdown()).ok();
            }
            build_result
        }

        pub fn settings(&self) -> &Settings {
            &self.settings
        }

        pub fn frame_bytes(&self) -> usize {
            self.frame_bytes
        }

        pub fn push(
            &mut self,
            frame: &[u8],
            timestamp_100ns: i64,
            force_idr: bool,
        ) -> Result<Vec<Chunk>, Error> {
            if self.finished {
                return Err(Error::Stream("push after finish".into()));
            }
            let mut chunks = Vec::new();
            if force_idr {
                // Fresh transform: the next push emits SPS/PPS/IDR (verified
                // behavior of this MFT). Trailing old-GOP output is valid
                // P-frames against already-sent references — emitted, never
                // dropped.
                chunks.extend(unsafe { self.rebuild(&self.settings.clone()) }?);
            }
            unsafe {
                let encoder = self.encoder.as_ref().expect("live transform");
                let buffer = hr(line!(), MFCreateMemoryBuffer(self.frame_bytes as u32))?;
                let mut locked: *mut u8 = std::ptr::null_mut();
                let mut max = 0u32;
                let mut current = 0u32;
                hr(
                    line!(),
                    buffer.Lock(&mut locked, Some(&mut max), Some(&mut current)),
                )?;
                std::ptr::copy_nonoverlapping(frame.as_ptr(), locked, self.frame_bytes);
                hr(line!(), buffer.Unlock())?;
                hr(line!(), buffer.SetCurrentLength(self.frame_bytes as u32))?;
                let sample = hr(line!(), MFCreateSample())?;
                hr(line!(), sample.AddBuffer(&buffer))?;
                hr(line!(), sample.SetSampleTime(timestamp_100ns))?;
                hr(line!(), sample.SetSampleDuration(self.step_100ns))?;
                hr(line!(), encoder.ProcessInput(0, &sample, 0))?;
                drain(encoder, &mut chunks)?;
                Ok(chunks)
            }
        }
        pub fn reconfigure(&mut self, settings: &Settings) -> Result<(), Error> {
            if self.finished {
                return Err(Error::Stream("reconfigure after finish".into()));
            }
            // Same rebuild path as forced IDR: drain under the old type,
            // swap the pair between frames. The next push emits the new
            // configuration; callers force an IDR alongside.
            let trailing = unsafe { self.rebuild(settings) }?;
            debug_assert!(
                trailing.is_empty(),
                "rebuild drain must not emit without new input"
            );
            Ok(())
        }

        /// Drain the old transform, release it fully, then stream a fresh
        /// one under `settings` (COM/MF lifetime stays with the enclosing
        /// Stream). The old instance is Released before the new one is
        /// created — two live MFTs never overlap. Returns trailing output
        /// of the old GOP, if any.
        unsafe fn rebuild(&mut self, settings: &Settings) -> Result<Vec<Chunk>, Error> {
            let mut trailing = Vec::new();
            if let Some(old) = self.encoder.take() {
                drain(&old, &mut trailing)?;
                hr(
                    line!(),
                    old.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0),
                )?;
            }
            let encoder: IMFTransform = hr(
                line!(),
                CoCreateInstance(
                    &CLSID_MSH264EncoderMFT,
                    Option::<&windows::core::IUnknown>::None,
                    CLSCTX_INPROC_SERVER,
                ),
            )?;
            configure_types(&encoder, settings)?;
            hr(line!(), encoder.GetOutputStreamInfo(0))?;
            hr(line!(), encoder.GetOutputStreamInfo(0))?;
            hr(
                line!(),
                encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
            )?;
            hr(
                line!(),
                encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
            )?;
            self.encoder = Some(encoder);
            self.settings = settings.clone();
            self.frame_bytes = settings.width as usize * settings.height as usize * 3 / 2;
            self.step_100ns = 10_000_000 / settings.fps.max(1) as i64;
            Ok(trailing)
        }

        pub fn finish(mut self) -> Result<Vec<Chunk>, Error> {
            let encoder = self
                .encoder
                .take()
                .ok_or_else(|| Error::Stream("finish without a live transform".into()))?;
            let mut chunks = Vec::new();
            unsafe {
                hr(
                    line!(),
                    encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0),
                )?;
                drain(&encoder, &mut chunks)?;
                hr(line!(), MFShutdown())?;
                CoUninitialize();
            }
            self.finished = true;
            Ok(chunks)
        }
    }

    impl Drop for Stream {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            // Abandoned mid-stream: signal EOS best-effort (unread output is
            // dropped by design — no silent partial GOP), then release.
            // Option content drops (Release) after this block either way.
            unsafe {
                if let Some(encoder) = self.encoder.as_ref() {
                    let _ = encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
                }
                let _ = MFShutdown();
                CoUninitialize();
            }
        }
    }

    /// (Re)configure the MFT input/output pair. Output type first: this MFT
    /// validates the pair eagerly and reports TYPE_NOT_SET when the input
    /// arrives first.
    unsafe fn configure_types(encoder: &IMFTransform, settings: &Settings) -> Result<(), Error> {
        let input = hr(line!(), MFCreateMediaType())?;
        hr(
            line!(),
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video),
        )?;
        hr(line!(), input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12))?;
        hr(
            line!(),
            input.SetUINT64(
                &MF_MT_FRAME_SIZE,
                ((settings.width as u64) << 32) | settings.height as u64,
            ),
        )?;
        hr(
            line!(),
            input.SetUINT64(&MF_MT_FRAME_RATE, ((settings.fps as u64) << 32) | 1),
        )?;
        hr(
            line!(),
            input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32),
        )?;
        hr(
            line!(),
            input.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, ((1u64) << 32) | 1),
        )?;
        hr(
            line!(),
            input.SetUINT32(&MF_MT_DEFAULT_STRIDE, settings.width),
        )?;
        let output = hr(line!(), MFCreateMediaType())?;
        hr(
            line!(),
            output.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video),
        )?;
        hr(line!(), output.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264))?;
        hr(
            line!(),
            output.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base.0 as u32),
        )?;
        hr(
            line!(),
            output.SetUINT32(&MF_MT_MPEG2_LEVEL, eAVEncH264VLevel4.0 as u32),
        )?;
        hr(
            line!(),
            output.SetUINT64(
                &MF_MT_FRAME_SIZE,
                ((settings.width as u64) << 32) | settings.height as u64,
            ),
        )?;
        hr(
            line!(),
            output.SetUINT64(&MF_MT_FRAME_RATE, ((settings.fps as u64) << 32) | 1),
        )?;
        hr(
            line!(),
            output.SetUINT32(&MF_MT_AVG_BITRATE, settings.bitrate_bps),
        )?;
        hr(
            line!(),
            output.SetUINT32(&MF_MT_MAX_KEYFRAME_SPACING, settings.max_keyframe_spacing),
        )?;
        hr(
            line!(),
            output.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32),
        )?;
        hr(
            line!(),
            output.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, ((1u64) << 32) | 1),
        )?;
        hr(line!(), encoder.SetOutputType(0, &output, 0))?;
        hr(line!(), encoder.SetInputType(0, &input, 0))?;
        Ok(())
    }

    unsafe fn drain(encoder: &IMFTransform, chunks: &mut Vec<Chunk>) -> Result<(), Error> {
        loop {
            let mut buffer = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                ..Default::default()
            };
            let backing = hr(line!(), MFCreateMemoryBuffer(4 * 1024 * 1024))?;
            let sample = hr(line!(), MFCreateSample())?;
            hr(line!(), sample.AddBuffer(&backing))?;
            buffer.pSample = std::mem::ManuallyDrop::new(Some(sample));
            let mut status = 0u32;
            match encoder.ProcessOutput(0, std::slice::from_mut(&mut buffer), &mut status) {
                Ok(()) => {}
                // Nothing more to emit right now: mid-stream it means feed
                // more input; at end-of-stream it means fully drained.
                Err(error) if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                Err(error) if error.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    // Encoder renegotiated its output type mid-stream; accept
                    // the new type and keep draining. Visible in chunk
                    // contents, never hidden.
                    continue;
                }
                Err(error) => return Err(Error::Stream(format!("ProcessOutput: {error:?}"))),
            }
            let produced = std::mem::ManuallyDrop::take(&mut buffer.pSample)
                .ok_or_else(|| Error::Stream("output without sample".into()))?;
            let sample = produced;
            let mut locked: *mut u8 = std::ptr::null_mut();
            let mut max = 0u32;
            let mut current = 0u32;
            let contiguous = sample
                .ConvertToContiguousBuffer()
                .map_err(|e| Error::Stream(format!("contiguous: {e:?}")))?;
            hr(
                line!(),
                contiguous.Lock(&mut locked, Some(&mut max), Some(&mut current)),
            )?;
            let bytes = std::slice::from_raw_parts(locked, current as usize).to_vec();
            hr(line!(), contiguous.Unlock())?;
            let types = super::nal_types(&bytes);
            let timestamp = sample
                .GetSampleTime()
                .map_err(|e| Error::Stream(format!("timestamp: {e:?}")))?;
            chunks.push(Chunk {
                keyframe: types.contains(&5),
                nal_types: types,
                timestamp_100ns: timestamp,
                bytes,
            });
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod inner {
    use super::*;

    /// Non-Windows streaming surface: construction always reports the gate
    /// so callers (serve media threads) fail honestly instead of shipping
    /// fake frames. Linux software encode (OpenH264/x264 mapping) is
    /// separate P5/driver work.
    pub struct Stream;

    impl Stream {
        pub fn new(_settings: &Settings) -> Result<Self, Error> {
            Err(Error::Gated("non-Windows software encode backends"))
        }

        pub fn settings(&self) -> &Settings {
            unreachable!("Stream::new is Gated off Windows")
        }

        pub fn frame_bytes(&self) -> usize {
            unreachable!("Stream::new is Gated off Windows")
        }

        pub fn push(
            &mut self,
            _frame: &[u8],
            _timestamp_100ns: i64,
            _force_idr: bool,
        ) -> Result<Vec<Chunk>, Error> {
            Err(Error::Gated("non-Windows software encode backends"))
        }

        pub fn reconfigure(&mut self, _settings: &Settings) -> Result<(), Error> {
            Err(Error::Gated("non-Windows software encode backends"))
        }

        pub fn finish(self) -> Result<Vec<Chunk>, Error> {
            Err(Error::Gated("non-Windows software encode backends"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 320x240 NV12 gradient: luma ramp + neutral chroma.
    #[cfg(target_os = "windows")]
    fn gradient(width: u32, height: u32, shift: u8) -> Vec<u8> {
        let (w, h) = (width as usize, height as usize);
        let mut frame = vec![128u8; w * h * 3 / 2];
        for y in 0..h {
            for x in 0..w {
                frame[y * w + x] = ((x + y + shift as usize) & 0xff) as u8;
            }
        }
        frame
    }

    #[test]
    fn rejects_bad_dimensions_before_touching_mf() {
        let bad = Settings {
            width: 0,
            ..Settings::default()
        };
        assert!(matches!(encode_nv12(&bad, &[]), Err(Error::Configure(_))));
        let settings = Settings::default();
        let short = vec![0u8; 100];
        assert!(matches!(
            encode_nv12(&settings, &[short]),
            Err(Error::Configure(_))
        ));
    }

    #[test]
    fn nal_scanner_reads_annex_b_types() {
        // SPS(7) + PPS(8) + IDR(5) with mixed 3/4-byte start codes.
        let bytes = [0, 0, 0, 1, 0x67, 9, 0, 0, 1, 0x68, 9, 0, 0, 0, 1, 0x65, 9];
        assert_eq!(nal_types(&bytes), vec![7, 8, 5]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn software_h264_round_trip_on_windows() {
        let settings = Settings::default();
        let frames: Vec<Vec<u8>> = (0..30u8)
            .map(|i| gradient(settings.width, settings.height, i))
            .collect();
        let chunks = encode_nv12(&settings, &frames).expect("software encode works");
        assert!(!chunks.is_empty(), "encoder produced output");
        let first_types: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| chunk.nal_types.clone())
            .take(8)
            .collect();
        assert!(first_types.contains(&7), "SPS present: {first_types:?}");
        assert!(first_types.contains(&8), "PPS present: {first_types:?}");
        assert!(
            chunks.iter().any(|chunk| chunk.keyframe),
            "at least one IDR"
        );
        let total: usize = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
        assert!(total > 1024, "nontrivial payload: {total} bytes");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn force_idr_emits_keyframe_on_demand() {
        // Wide GOP so no scheduled IDR interferes; the forced frame must
        // carry SPS/PPS/IDR regardless of any extra MFT decisions.
        let settings = Settings {
            max_keyframe_spacing: 300,
            ..Settings::default()
        };
        let mut encoder = StreamEncoder::new(&settings).expect("construct streaming encoder");
        let step = 10_000_000 / settings.fps as i64;
        for index in 0..5i64 {
            let frame = gradient(settings.width, settings.height, index as u8);
            encoder
                .push(&frame, index * step, false)
                .expect("streaming push works");
        }
        let frame = gradient(settings.width, settings.height, 5);
        let mut post: Vec<Chunk> = encoder
            .push(&frame, 5 * step, true)
            .expect("forced-IDR push works");
        // Fresh MFTs buffer lookahead before emitting: the IDR for the
        // forced frame arrives within the next few inputs, not necessarily
        // synchronously with it. Drain forward and judge the accumulation.
        for index in 6..9i64 {
            let frame = gradient(settings.width, settings.height, index as u8);
            post.extend(
                encoder
                    .push(&frame, index * step, false)
                    .expect("post-IDR push works"),
            );
        }
        let types: Vec<u8> = post
            .iter()
            .flat_map(|chunk| chunk.nal_types.clone())
            .collect();
        assert!(types.contains(&5), "forced frame must be an IDR: {types:?}");
        assert!(
            types.contains(&7) && types.contains(&8),
            "forced IDR must refresh SPS/PPS for joiners: {types:?}"
        );
        let trailing = encoder.finish().expect("finish drains");
        assert!(
            !post.is_empty() || !trailing.is_empty(),
            "stream produced output"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn reconfigure_swaps_dimensions_mid_stream() {
        let mut encoder = StreamEncoder::new(&Settings::default()).expect("construct");
        let step = 10_000_000 / Settings::default().fps as i64;
        let frame = gradient(320, 240, 0);
        encoder
            .push(&frame, 0, false)
            .expect("pre-reconfigure push");
        let small = Settings {
            width: 160,
            height: 120,
            ..Settings::default()
        };
        encoder.reconfigure(&small).expect("mid-stream reconfigure");
        assert_eq!(encoder.settings().width, 160);
        let mut post = Vec::new();
        for index in 1..4i64 {
            let frame = gradient(160, 120, index as u8);
            post.extend(
                encoder
                    .push(&frame, index * step, false)
                    .expect("post-reconfigure push"),
            );
        }
        assert!(!post.is_empty(), "encoder emits at the new size");
        let trailing = encoder.finish().expect("finish");
        let total: usize = post
            .iter()
            .chain(trailing.iter())
            .map(|chunk| chunk.bytes.len())
            .sum();
        assert!(total > 0, "nontrivial post-reconfigure payload");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_reports_its_gate() {
        assert_eq!(
            encode_nv12(&Settings::default(), &[]),
            Err(Error::Gated("non-Windows software encode backends"))
        );
    }
}
