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
///
/// Dimensions MUST be multiples of 16 (H.264 macroblocks): the inbox
/// software MFT faults natively on unaligned sizes instead of refusing
/// them, so capture layers pad/crop upstream and constructors of fixed
/// profiles validate before touching the MFT.
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

/// Select a baseline-profile H.264 level for the frame/rate/bitrate, retaining
/// level 4.0 for existing small streams. Values are the MF level identifiers.
pub fn h264_level(settings: &Settings) -> Result<u32, Error> {
    if settings.width == 0 || settings.height == 0 || settings.fps == 0 {
        return Err(Error::Configure("zero dimension or rate".into()));
    }
    let width = (settings.width as u64).div_ceil(16);
    let height = (settings.height as u64).div_ceil(16);
    let frame = width.saturating_mul(height);
    let rate = frame.saturating_mul(settings.fps as u64);
    let levels: [(u32, u64, u64, u64); 6] = [
        (40, 8192, 245_760, 20_000_000),
        (41, 8192, 245_760, 50_000_000),
        (42, 8704, 522_240, 50_000_000),
        (50, 22_080, 589_824, 135_000_000),
        (51, 36_864, 983_040, 240_000_000),
        (52, 36_864, 2_073_600, 240_000_000),
    ];
    for (level, max_frame, max_rate, max_bitrate) in levels {
        if frame <= max_frame
            && rate <= max_rate
            && settings.bitrate_bps as u64 <= max_bitrate
            && width.saturating_mul(width) <= max_frame * 8
            && height.saturating_mul(height) <= max_frame * 8
        {
            return Ok(level);
        }
    }
    Err(Error::Configure(
        "frame/rate/bitrate exceeds supported H.264 levels".into(),
    ))
}

#[cfg(test)]
#[test]
fn h264_levels_cover_large_frames_and_bound_extreme_rates() {
    for (width, height, fps, level) in [
        (320, 240, 30, 40),
        (1920, 1088, 30, 40),
        (1920, 1088, 60, 42),
        (2224, 1360, 30, 50),
        (3840, 2160, 30, 51),
        (3840, 2160, 60, 52),
    ] {
        assert_eq!(
            h264_level(&Settings {
                width,
                height,
                fps,
                ..Settings::default()
            }),
            Ok(level)
        );
    }
    for (width, height, fps) in [
        (8192, 8192, 30),
        (1920, 1088, u32::MAX),
        (u32::MAX, u32::MAX, u32::MAX),
    ] {
        assert!(h264_level(&Settings {
            width,
            height,
            fps,
            ..Settings::default()
        })
        .is_err());
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
        eAVEncH264VProfile_Base, CLSID_MSH264EncoderMFT, IMFTransform, MFCreateMediaType,
        MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFShutdown, MFStartup,
        MFVideoFormat_H264, MFVideoFormat_NV12, MFVideoInterlace_Progressive, MFSTARTUP_NOSOCKET,
        MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
        MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER, MF_E_BUFFERTOOSMALL,
        MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_MT_AVG_BITRATE,
        MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE,
        MF_MT_MAJOR_TYPE, MF_MT_MAX_KEYFRAME_SPACING, MF_MT_MPEG2_LEVEL, MF_MT_MPEG2_PROFILE,
        MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE, MF_VERSION,
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
        // Field drop order is declaration order: the live transform goes
        // first, then MF, then COM — always a legal teardown sequence.
        current: Option<Mft>,
        _mf: MfGuard,
        _com: ComGuard,
        settings: Settings,
        frame_bytes: usize,
        step_100ns: i64,
        finished: bool,
    }

    /// One streaming MFT instance. Replaced (never reconfigured in place):
    /// the inbox software MFT does not survive mid-stream surgery, so a
    /// fresh instance opens every GOP segment with SPS/PPS/IDR.
    struct Mft {
        encoder: IMFTransform,
        /// Minimum output sample size from `GetOutputStreamInfo`, so large
        /// frames (4K IDRs) never hit a fixed small drain buffer.
        output_bytes: u32,
    }

    /// CoInitializeEx owner: Uninitialize on drop. One per Stream.
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    /// MFStartup owner: Shutdown on drop. One per Stream.
    struct MfGuard;
    impl Drop for MfGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = MFShutdown();
            }
        }
    }

    impl Stream {
        pub fn new(settings: &Settings) -> Result<Self, Error> {
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            let com = ComGuard;
            let mf = unsafe {
                match hr(line!(), MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)) {
                    Ok(()) => MfGuard,
                    Err(error) => {
                        drop(com);
                        return Err(error);
                    }
                }
            };
            // `?` below drops guards in reverse order (MFShutdown, then
            // CoUninitialize) — always balanced.
            let current = unsafe { Mft::start(settings) }?;
            Ok(Self {
                current: Some(current),
                _mf: mf,
                _com: com,
                settings: settings.clone(),
                frame_bytes: settings.width as usize * settings.height as usize * 3 / 2,
                step_100ns: 10_000_000 / settings.fps.max(1) as i64,
                finished: false,
            })
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
            if self.finished || self.current.is_none() {
                return Err(Error::Stream("push after finish".into()));
            }
            let mut chunks = Vec::new();
            if force_idr {
                // Fresh transform: the next push emits SPS/PPS/IDR (verified
                // behavior of this MFT). Trailing old-GOP output is valid
                // P-frames against already-sent references — emitted, never
                // dropped.
                chunks.extend(unsafe { self.replace(&self.settings.clone()) }?);
            }
            unsafe {
                let encoder = &self.current.as_ref().expect("live transform").encoder;
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
                let output_bytes = self.current.as_ref().expect("live transform").output_bytes;
                drain(encoder, output_bytes, &mut chunks)?;
                Ok(chunks)
            }
        }
        pub fn reconfigure(&mut self, settings: &Settings) -> Result<(), Error> {
            if self.finished || self.current.is_none() {
                return Err(Error::Stream("reconfigure after finish".into()));
            }
            // Same replacement path as forced IDR: the next push emits the
            // new configuration; callers force an IDR alongside.
            let trailing = unsafe { self.replace(settings) }?;
            debug_assert!(
                trailing.is_empty(),
                "replacement drain must not emit without new input"
            );
            Ok(())
        }

        /// Drain the live transform, release it fully, then stream a fresh
        /// one under `settings`. The old instance (and its EOS signal) is
        /// gone before the new one is created — two live MFTs never
        /// overlap. Returns trailing output of the old GOP, if any.
        unsafe fn replace(&mut self, settings: &Settings) -> Result<Vec<Chunk>, Error> {
            let mut trailing = Vec::new();
            if let Some(old) = self.current.take() {
                drain(&old.encoder, old.output_bytes, &mut trailing)?;
                hr(
                    line!(),
                    old.encoder
                        .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0),
                )?;
                // `old` drops here: Release runs before the new instance.
            }
            let current = Mft::start(settings)?;
            self.current = Some(current);
            self.settings = settings.clone();
            self.frame_bytes = settings.width as usize * settings.height as usize * 3 / 2;
            self.step_100ns = 10_000_000 / settings.fps.max(1) as i64;
            Ok(trailing)
        }

        pub fn finish(mut self) -> Result<Vec<Chunk>, Error> {
            let current = self
                .current
                .take()
                .ok_or_else(|| Error::Stream("finish without a live transform".into()))?;
            let mut chunks = Vec::new();
            unsafe {
                hr(
                    line!(),
                    current
                        .encoder
                        .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0),
                )?;
                drain(&current.encoder, current.output_bytes, &mut chunks)?;
            }
            self.finished = true;
            // Guards drop here: MFShutdown, then CoUninitialize, in order.
            Ok(chunks)
        }
    }

    impl Mft {
        /// Create, configure and start streaming one transform instance.
        /// COM/MF lifetime stays with the enclosing Stream.
        unsafe fn start(settings: &Settings) -> Result<Self, Error> {
            let encoder: IMFTransform = hr(
                line!(),
                CoCreateInstance(
                    &CLSID_MSH264EncoderMFT,
                    Option::<&windows::core::IUnknown>::None,
                    CLSCTX_INPROC_SERVER,
                ),
            )?;
            configure_types(&encoder, settings)?;
            let info = hr(line!(), encoder.GetOutputStreamInfo(0))?;
            hr(
                line!(),
                encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
            )?;
            hr(
                line!(),
                encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
            )?;
            // The MFT reports its per-sample output need; fall back to a
            // frame-proportional floor when it reports none.
            let floor = settings
                .width
                .saturating_mul(settings.height)
                .saturating_mul(3)
                / 2;
            Ok(Self {
                encoder,
                output_bytes: info.cbSize.max(floor).max(1024 * 1024),
            })
        }
    }

    impl Drop for Stream {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            // Abandoned mid-stream: signal EOS best-effort (unread output is
            // dropped by design — no silent partial GOP). Field order drops
            // the transform first, then MF, then COM.
            unsafe {
                if let Some(current) = self.current.as_ref() {
                    let _ = current
                        .encoder
                        .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
                }
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
            output.SetUINT32(&MF_MT_MPEG2_LEVEL, h264_level(settings)?),
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

    unsafe fn drain(
        encoder: &IMFTransform,
        output_bytes: u32,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), Error> {
        loop {
            let mut buffer = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                ..Default::default()
            };
            let backing = hr(line!(), MFCreateMemoryBuffer(output_bytes))?;
            let sample = hr(line!(), MFCreateSample())?;
            hr(line!(), sample.AddBuffer(&backing))?;
            buffer.pSample = std::mem::ManuallyDrop::new(Some(sample));
            let mut status = 0u32;
            let mut result =
                encoder.ProcessOutput(0, std::slice::from_mut(&mut buffer), &mut status);
            // A large IDR can exceed even the stream-info size on some
            // builds: retry once with a quadrupled buffer before failing the
            // session's video. Bounded, never unbounded growth.
            if result.as_ref().err().map(|e| e.code()) == Some(MF_E_BUFFERTOOSMALL)
                && output_bytes <= 16 * 1024 * 1024
            {
                drop(std::mem::ManuallyDrop::take(&mut buffer.pSample));
                drop(std::mem::ManuallyDrop::take(&mut buffer.pEvents));
                let backing = hr(
                    line!(),
                    MFCreateMemoryBuffer(output_bytes.saturating_mul(4)),
                )?;
                let sample = hr(line!(), MFCreateSample())?;
                hr(line!(), sample.AddBuffer(&backing))?;
                buffer.pSample = std::mem::ManuallyDrop::new(Some(sample));
                result = encoder.ProcessOutput(0, std::slice::from_mut(&mut buffer), &mut status);
            }
            // The bindings deliberately use ManuallyDrop for these COM
            // fields. Reclaim ownership BEFORE handling any HRESULT: even
            // NEED_MORE_INPUT must release the caller's sample buffer.
            let produced = std::mem::ManuallyDrop::take(&mut buffer.pSample);
            drop(std::mem::ManuallyDrop::take(&mut buffer.pEvents));
            match result {
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
            let sample = produced.ok_or_else(|| Error::Stream("output without sample".into()))?;
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
    fn sustained_stream_releases_output_buffers() {
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;

        fn private_bytes() -> usize {
            let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
            let size = std::mem::size_of_val(&counters) as u32;
            counters.cb = size;
            unsafe {
                GetProcessMemoryInfo(
                    GetCurrentProcess(),
                    (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
                    size,
                )
                .expect("process memory counters");
            }
            counters.PrivateUsage
        }

        let settings = Settings::default();
        let mut encoder = StreamEncoder::new(&settings).expect("construct");
        let frame = gradient(settings.width, settings.height, 0);
        let step = 10_000_000 / settings.fps as i64;
        for index in 0..30 {
            encoder.push(&frame, index * step, false).expect("warm up");
        }
        let baseline = private_bytes();
        let mut emitted = 0;
        for index in 30..630 {
            emitted += encoder
                .push(&frame, index * step, false)
                .expect("sustained encode")
                .len();
            assert!(
                private_bytes().saturating_sub(baseline) < 128 * 1024 * 1024,
                "output-buffer memory grows during sustained encoding"
            );
        }
        assert!(emitted > 0, "sustained stream emits video");
        encoder.finish().expect("finish");
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
        // forced frame arrives within the next inputs, not necessarily
        // synchronously with it. Drain forward (bounded) and judge the
        // accumulation; stop early once the IDR lands.
        for index in 6..24i64 {
            let frame = gradient(settings.width, settings.height, index as u8);
            post.extend(
                encoder
                    .push(&frame, index * step, false)
                    .expect("post-IDR push works"),
            );
            if post.iter().any(|chunk| chunk.keyframe) {
                break;
            }
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
        // Macroblock-aligned sizes only: the inbox MFT does not survive
        // non-mod-16 dimensions (native fault, not a clean error), so the
        // capture layer must pad/crop to alignment — asserted here, not
        // assumed.
        let small = Settings {
            width: 176,
            height: 144,
            ..Settings::default()
        };
        encoder.reconfigure(&small).expect("mid-stream reconfigure");
        assert_eq!(encoder.settings().width, 176);
        let mut post = Vec::new();
        for index in 1..20i64 {
            let frame = gradient(176, 144, index as u8);
            post.extend(
                encoder
                    .push(&frame, index * step, false)
                    .expect("post-reconfigure push"),
            );
            if !post.is_empty() {
                break;
            }
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
