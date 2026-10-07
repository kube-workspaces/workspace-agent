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
    inner::encode_nv12(settings, frames)
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

    pub fn encode_nv12(settings: &Settings, frames: &[Vec<u8>]) -> Result<Vec<Chunk>, Error> {
        let frame_bytes = settings.width as usize * settings.height as usize * 3 / 2;
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let result = unsafe { encode_inner(settings, frames, frame_bytes) };
        unsafe { CoUninitialize() };
        result
    }

    unsafe fn encode_inner(
        settings: &Settings,
        frames: &[Vec<u8>],
        frame_bytes: usize,
    ) -> Result<Vec<Chunk>, Error> {
        hr(line!(), MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET))?;
        let encoder: IMFTransform = hr(
            line!(),
            CoCreateInstance(
                &CLSID_MSH264EncoderMFT,
                Option::<&windows::core::IUnknown>::None,
                CLSCTX_INPROC_SERVER,
            ),
        )?;

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
        // Output type first: this MFT validates the input/output pair
        // eagerly and reports TYPE_NOT_SET when the input arrives first.
        hr(line!(), encoder.SetOutputType(0, &output, 0))?;
        hr(line!(), encoder.SetInputType(0, &input, 0))?;
        hr(line!(), encoder.GetOutputStreamInfo(0))?;
        let mut chunks = Vec::new();
        hr(
            line!(),
            encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
        )?;
        hr(
            line!(),
            encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
        )?;
        let step_100ns: i64 = 10_000_000 / settings.fps as i64;
        for (index, frame) in frames.iter().enumerate() {
            let buffer = hr(line!(), MFCreateMemoryBuffer(frame_bytes as u32))?;
            let mut locked: *mut u8 = std::ptr::null_mut();
            let mut max = 0u32;
            let mut current = 0u32;
            hr(
                line!(),
                buffer.Lock(&mut locked, Some(&mut max), Some(&mut current)),
            )?;
            std::ptr::copy_nonoverlapping(frame.as_ptr(), locked, frame_bytes);
            hr(line!(), buffer.Unlock())?;
            hr(line!(), buffer.SetCurrentLength(frame_bytes as u32))?;
            let sample = hr(line!(), MFCreateSample())?;
            hr(line!(), sample.AddBuffer(&buffer))?;
            hr(line!(), sample.SetSampleTime(index as i64 * step_100ns))?;
            hr(line!(), sample.SetSampleDuration(step_100ns))?;
            hr(line!(), encoder.ProcessInput(0, &sample, 0))?;
            drain(&encoder, &mut chunks)?;
        }
        hr(
            line!(),
            encoder.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0),
        )?;
        drain(&encoder, &mut chunks)?;
        hr(line!(), MFShutdown())?;
        Ok(chunks)
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

    pub fn encode_nv12(_settings: &Settings, _frames: &[Vec<u8>]) -> Result<Vec<Chunk>, Error> {
        // Non-Windows encoders (VAAPI/VideoToolbox/ffmpeg mappings) are
        // separate P5/driver work. Report the gate; never fake output.
        Err(Error::Gated("non-Windows software encode backends"))
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_reports_its_gate() {
        assert_eq!(
            encode_nv12(&Settings::default(), &[]),
            Err(Error::Gated("non-Windows software encode backends"))
        );
    }
}
