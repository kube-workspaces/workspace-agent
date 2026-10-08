//! Continuous loopback tap: native packets → 48kHz stereo f32 frames.
//!
//! [`LoopbackTap`] streams raw packets from the default render endpoint
//! (Windows). Format normalization is pure and platform-independent:
//! [`pcm_to_f32`] decodes the mix bytes, [`to_stereo`] maps channels,
//! [`FrameAccumulator`] cuts 20ms contract frames for the Opus encoder.

use crate::opus::{CHANNELS, FRAME_SAMPLES};

/// Native mix format of one tap packet batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixFormat {
    pub rate: u32,
    pub channels: u16,
    /// Bits per sample: 16, 24 or 32.
    pub bits: u16,
    /// True for IEEE-float samples, false for signed PCM integers.
    pub float: bool,
}

/// Decode native interleaved samples to normalized f32 (±1.0).
/// Unsupported widths/formats are refused, never guessed.
pub fn pcm_to_f32(bytes: &[u8], format: MixFormat) -> Result<Vec<f32>, crate::Error> {
    let width = (format.bits as usize) / 8;
    if !matches!(format.bits, 16 | 24 | 32) || width == 0 {
        return Err(crate::Error::Codec(format!(
            "unsupported mix width {}",
            format.bits
        )));
    }
    if format.channels == 0 || bytes.len() % (width * format.channels as usize) != 0 {
        return Err(crate::Error::Codec("ragged mix buffer".into()));
    }
    let frames = bytes.len() / (width * format.channels as usize);
    let mut out = Vec::with_capacity(frames * format.channels as usize);
    for frame in 0..frames {
        for channel in 0..format.channels as usize {
            let offset = (frame * format.channels as usize + channel) * width;
            let sample = &bytes[offset..offset + width];
            out.push(if format.float {
                if format.bits != 32 {
                    return Err(crate::Error::Codec("float mixes must be 32-bit".into()));
                }
                f32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]])
            } else {
                match format.bits {
                    16 => i16::from_le_bytes([sample[0], sample[1]]) as f32 / 32768.0,
                    24 => {
                        let sign = if sample[2] & 0x80 != 0 { 0xFF } else { 0x00 };
                        let raw = i32::from_le_bytes([sample[0], sample[1], sample[2], sign]);
                        raw as f32 / 8_388_608.0
                    }
                    32 => {
                        i32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]) as f32
                            / 2_147_483_648.0
                    }
                    _ => unreachable!("width checked above"),
                }
            });
        }
    }
    Ok(out)
}

/// Map interleaved channels to stereo: mono duplicates, stereo passes
/// through, wider mixes take the front pair (documented convention, not a
/// surround downmix — that is separate acoustics work).
pub fn to_stereo(samples: &[f32], channels: u16) -> Vec<f32> {
    if channels == 0 || samples.is_empty() {
        return Vec::new();
    }
    let frames = samples.len() / channels as usize;
    let mut out = Vec::with_capacity(frames * 2);
    for frame in 0..frames {
        let base = frame * channels as usize;
        match channels {
            1 => {
                out.push(samples[base]);
                out.push(samples[base]);
            }
            _ => {
                out.push(samples[base]);
                out.push(samples[base + 1]);
            }
        }
    }
    out
}

/// Accumulates resampled stereo into exact 20ms contract frames.
pub struct FrameAccumulator {
    pending: Vec<f32>,
}

impl FrameAccumulator {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn push(&mut self, stereo_48k: &[f32]) {
        self.pending.extend_from_slice(stereo_48k);
    }

    /// Drain one complete frame when available.
    pub fn pop_frame(&mut self) -> Option<Vec<f32>> {
        const NEED: usize = FRAME_SAMPLES * CHANNELS;
        if self.pending.len() < NEED {
            return None;
        }
        Some(self.pending.drain(..NEED).collect())
    }

    pub fn buffered_frames(&self) -> usize {
        self.pending.len() / (FRAME_SAMPLES * CHANNELS)
    }
}

impl Default for FrameAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
pub use self::platform::LoopbackTap;

#[cfg(not(target_os = "windows"))]
pub use self::platform::LoopbackTap;

#[cfg(target_os = "windows")]
mod platform {
    use super::super::{Error, MixFormat};
    use windows::Win32::Foundation::{BOOL, WAIT_OBJECT_0};
    use windows::Win32::Media::Audio::{
        eConsole, eRender, IAudioCaptureClient, IAudioClient, IMMDeviceEnumerator,
        MMDeviceEnumerator, AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_EVENTCALLBACK, AUDCLNT_STREAMFLAGS_LOOPBACK, WAVEFORMATEX,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_ALL,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    fn os(error: windows::core::Error) -> Error {
        Error::Os(error.code().0 as u32)
    }

    /// Streaming loopback tap on the default render endpoint. Owns COM for
    /// its lifetime (Drop stops the stream). One tap per audio thread.
    pub struct LoopbackTap {
        client: IAudioClient,
        capture: IAudioCaptureClient,
        event: windows::Win32::Foundation::HANDLE,
        format: MixFormat,
        frame_bytes: usize,
    }

    impl LoopbackTap {
        /// Open the default console render endpoint. No endpoint (headless
        /// runner, RDP without audio) is [`Error::NoEndpoint`] — callers
        /// degrade, never fabricate.
        pub fn start() -> Result<Self, Error> {
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            let built = unsafe { Self::build() };
            if built.is_err() {
                unsafe { CoUninitialize() };
            }
            built
        }

        unsafe fn build() -> Result<Self, Error> {
            let enumerator: IMMDeviceEnumerator =
                CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
                    .map_err(|_| Error::NoEndpoint)?;
            let endpoint = enumerator
                .GetDefaultAudioEndpoint(eRender, eConsole)
                .map_err(|_| Error::NoEndpoint)?;
            let client: IAudioClient = endpoint.Activate(CLSCTX_ALL, None).map_err(os)?;
            let mix = client.GetMixFormat().map_err(os)?;
            let format = mix_format_of(&*mix)?;
            let frame_bytes = format.channels as usize * (format.bits as usize / 8).max(1);
            let event =
                CreateEventW(None, BOOL::from(false), BOOL::from(false), None).map_err(os)?;
            client
                .Initialize(
                    AUDCLNT_SHAREMODE_SHARED,
                    AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_LOOPBACK,
                    1_000_000,
                    0,
                    mix,
                    None,
                )
                .map_err(os)?;
            CoTaskMemFree(Some(mix as *const _));
            client.SetEventHandle(event).map_err(os)?;
            let capture: IAudioCaptureClient = client.GetService().map_err(os)?;
            client.Start().map_err(os)?;
            Ok(Self {
                client,
                capture,
                event,
                format,
                frame_bytes,
            })
        }

        pub fn mix_format(&self) -> MixFormat {
            MixFormat {
                rate: self.format.rate,
                channels: self.format.channels,
                bits: self.format.bits,
                float: self.format.float,
            }
        }

        /// Read one engine packet batch: native bytes plus frame count.
        /// `Ok(None)` on wait timeout (silence gap, not an error); device
        /// removal surfaces as [`Error::DeviceLost`] so the host reopens.
        pub fn read(&self, timeout_ms: u32) -> Result<Option<(MixFormat, Vec<u8>, u32)>, Error> {
            // Drain already queued packets before waiting for another event.
            let mut available = unsafe { self.capture.GetNextPacketSize() }.map_err(device_lost)?;
            if available == 0 {
                if unsafe { WaitForSingleObject(self.event, timeout_ms) } != WAIT_OBJECT_0 {
                    return Ok(None);
                }
                available = unsafe { self.capture.GetNextPacketSize() }.map_err(device_lost)?;
            }
            if available == 0 {
                return Ok(None);
            }
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut count = 0u32;
            let mut flags = 0u32;
            if unsafe {
                self.capture
                    .GetBuffer(&mut data, &mut count, &mut flags, None, None)
            }
            .is_err()
            {
                return Err(Error::DeviceLost);
            }
            let length = count as usize * self.frame_bytes;
            let bytes = if flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 || length == 0 {
                // WASAPI may return a null pointer for a silent packet.
                vec![0u8; length]
            } else if data.is_null() {
                let _ = unsafe { self.capture.ReleaseBuffer(count) };
                return Err(Error::Os(0));
            } else {
                unsafe { std::slice::from_raw_parts(data, length).to_vec() }
            };
            if unsafe { self.capture.ReleaseBuffer(count) }.is_err() {
                return Err(Error::Os(0));
            }
            Ok(Some((self.format, bytes, count)))
        }
    }

    /// WAVEFORMATEX (or EXTENSIBLE SubFormat Data1) → mix descriptor.
    /// Data1 1 = PCM integer, 3 = IEEE float.
    unsafe fn mix_format_of(mix: &WAVEFORMATEX) -> Result<MixFormat, Error> {
        const WAVE_FORMAT_PCM: u16 = 1;
        const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
        const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;
        if mix.nChannels == 0 || mix.nSamplesPerSec == 0 {
            return Err(Error::Codec("empty mix format".into()));
        }
        let (bits, float) = match mix.wFormatTag {
            WAVE_FORMAT_PCM => (mix.wBitsPerSample, false),
            WAVE_FORMAT_IEEE_FLOAT => {
                if mix.wBitsPerSample != 32 {
                    return Err(Error::Codec("float mixes must be 32-bit".into()));
                }
                (32, true)
            }
            WAVE_FORMAT_EXTENSIBLE => {
                let ext = &*(mix as *const _ as *const WAVEFORMATEXTENSIBLE_LOCAL);
                match ext.sub_format_data1 {
                    1 => (ext.bits(), false),
                    3 => {
                        if ext.bits() != 32 {
                            return Err(Error::Codec("float mixes must be 32-bit".into()));
                        }
                        (32, true)
                    }
                    other => {
                        return Err(Error::Codec(format!(
                            "unsupported extensible subformat {other}"
                        )))
                    }
                }
            }
            other => return Err(Error::Codec(format!("unsupported mix encoding {other}"))),
        };
        if !matches!(bits, 16 | 24 | 32) {
            return Err(Error::Codec(format!("unsupported mix width {bits}")));
        }
        Ok(MixFormat {
            rate: mix.nSamplesPerSec,
            channels: mix.nChannels,
            bits,
            float,
        })
    }

    /// WAVEFORMATEXTENSIBLE header read without importing the full struct:
    /// SubFormat GUID Data1 sits right after the standard extension fields.
    #[repr(C)]
    struct WAVEFORMATEXTENSIBLE_LOCAL {
        _format_tag: u16,
        _channels: u16,
        _rate: u32,
        _avg_bytes: u32,
        _block_align: u16,
        _bits: u16,
        _extra: u16,
        _valid_bits: u16,
        _channel_mask: u32,
        sub_format_data1: u32,
    }

    impl WAVEFORMATEXTENSIBLE_LOCAL {
        fn bits(&self) -> u16 {
            self._bits
        }
    }

    /// Device removal (unplug, RDP audio reroute, endpoint disable) ends
    /// the tap; the host reopens rather than failing the session.
    fn device_lost(_error: windows::core::Error) -> Error {
        Error::DeviceLost
    }

    impl Drop for LoopbackTap {
        fn drop(&mut self) {
            unsafe {
                let _ = self.client.Stop();
                CoUninitialize();
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::super::Error;
    use super::MixFormat;

    pub struct LoopbackTap;

    impl LoopbackTap {
        pub fn start() -> Result<Self, Error> {
            Err(Error::Gated("non-Windows audio capture backends"))
        }

        pub fn mix_format(&self) -> MixFormat {
            unreachable!("LoopbackTap::start is Gated off Windows")
        }

        pub fn read(&self, _timeout_ms: u32) -> Result<Option<(MixFormat, Vec<u8>, u32)>, Error> {
            Err(Error::Gated("non-Windows audio capture backends"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int16_decodes_at_full_scale() {
        let format = MixFormat {
            rate: 48_000,
            channels: 2,
            bits: 16,
            float: false,
        };
        let bytes = [0x00u8, 0x40, 0x00, 0xC0];
        let samples = pcm_to_f32(&bytes, format).expect("int16 decodes");
        assert_eq!(samples.len(), 2);
        assert!((samples[0] - 0.5).abs() < 1e-4, "0x4000 -> +0.5");
        assert!((samples[1] + 0.5).abs() < 1e-4, "0xC000 -> -0.5");
    }

    #[test]
    fn float32_passes_through() {
        let format = MixFormat {
            rate: 44_100,
            channels: 1,
            bits: 32,
            float: true,
        };
        let bytes = 0.25f32.to_le_bytes();
        let samples = pcm_to_f32(&bytes, format).expect("f32 decodes");
        assert_eq!(samples, vec![0.25]);
    }

    #[test]
    fn int24_sign_extends() {
        let format = MixFormat {
            rate: 48_000,
            channels: 1,
            bits: 24,
            float: false,
        };
        let bytes = [0x00u8, 0x00, 0x40];
        let samples = pcm_to_f32(&bytes, format).expect("int24 decodes");
        assert!((samples[0] - 0.5).abs() < 1e-4, "+0.5 in 24-bit");
    }

    #[test]
    fn channel_map_covers_mono_stereo_quad() {
        assert_eq!(to_stereo(&[0.5], 1), vec![0.5, 0.5]);
        assert_eq!(to_stereo(&[0.1, 0.2], 2), vec![0.1, 0.2]);
        assert_eq!(to_stereo(&[0.1, 0.2, 0.3, 0.4], 4), vec![0.1, 0.2]);
        assert!(to_stereo(&[], 2).is_empty());
    }

    #[test]
    fn accumulator_cuts_exact_frames() {
        let mut accumulator = FrameAccumulator::new();
        accumulator.push(&vec![1.0f32; 1000]);
        assert!(accumulator.pop_frame().is_none());
        accumulator.push(&vec![2.0f32; 920]);
        let frame = accumulator
            .pop_frame()
            .expect("1920 samples drain one frame");
        assert_eq!(frame.len(), FRAME_SAMPLES * CHANNELS);
        assert_eq!(frame[999], 1.0);
        assert_eq!(frame[1000], 2.0);
        assert_eq!(accumulator.buffered_frames(), 0);
    }

    #[test]
    fn ragged_buffers_are_refused() {
        let format = MixFormat {
            rate: 48_000,
            channels: 2,
            bits: 16,
            float: false,
        };
        assert!(pcm_to_f32(&[0u8; 3], format).is_err());
        assert!(pcm_to_f32(&[0u8; 4], MixFormat { bits: 8, ..format }).is_err());
    }

    /// Headless CI runners usually have no render endpoint: opening must
    /// report honestly (working tap or explicit NoEndpoint), never block
    /// forever or fabricate. A tap that opens must also survive a short
    /// read without crashing, whatever the room sounds like.
    #[cfg(target_os = "windows")]
    #[test]
    fn tap_open_is_honest_headless() {
        match super::platform::LoopbackTap::start() {
            Ok(tap) => {
                let format = tap.mix_format();
                assert!(format.rate >= 8000, "sane mix rate");
                assert!(format.channels >= 1, "sane channels");
                let _ = tap.read(500);
            }
            Err(super::super::Error::NoEndpoint) => {}
            Err(other) => panic!("unexpected tap failure: {other}"),
        }
    }

    /// Whole proof chain on synthetic input: 44.1kHz stereo sine →
    /// normalize → stereo → resample → frame → Opus → decode. Runs on
    /// every platform (no endpoint needed); the tap itself is OS-covered.
    #[test]
    fn chain_resamples_frames_encodes_and_decodes() {
        use super::super::opus::{Decoder, Encoder};
        use super::super::resample::Resampler;
        let rate = 44_100u32;
        let frames = 4410usize;
        // 32-bit float stereo sine, native-endian interleaved.
        let mut interleaved = Vec::with_capacity(frames * 2 * 4);
        for i in 0..frames {
            let sample = 0.4 * (2.0 * std::f32::consts::PI * 440.0 * i as f32 / rate as f32).sin();
            interleaved.extend_from_slice(&sample.to_le_bytes());
            interleaved.extend_from_slice(&sample.to_le_bytes());
        }
        let format = MixFormat {
            rate,
            channels: 2,
            bits: 32,
            float: true,
        };
        let pcm = pcm_to_f32(&interleaved, format).expect("native decodes");
        let stereo = to_stereo(&pcm, 2);
        let mut resampler = Resampler::new(rate);
        let converted = resampler.push_stereo(&stereo);
        let mut accumulator = FrameAccumulator::new();
        accumulator.push(&converted);
        let mut encoder = Encoder::new().expect("opus encoder");
        let mut decoder = Decoder::new().expect("opus decoder");
        let mut packets = 0u32;
        let mut energy = 0f64;
        let mut decoded_total = 0usize;
        while let Some(frame) = accumulator.pop_frame() {
            let packet = encoder.encode_frame(&frame).expect("opus encodes");
            let mut out = vec![0f32; 1920 * 2];
            let samples = decoder.decode_into(&packet, &mut out).expect("decodes");
            assert!(samples > 0);
            packets += 1;
            decoded_total += samples;
            for sample in out.iter().take(samples * 2) {
                energy += (*sample as f64) * (*sample as f64);
            }
        }
        assert!(packets >= 4, "440ms yields multiple Opus frames");
        let rms = (energy / decoded_total.max(1) as f64).sqrt();
        assert!(rms > 0.05, "440Hz tone survives the chain (rms {rms})");
    }
}
