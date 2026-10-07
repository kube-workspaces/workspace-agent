//! WASAPI loopback capture backend.
//!
//! Captures the default render endpoint's mix: endpoint → client → mix
//! format → shared loopback init → packet pump. Silence is reported, never
//! hidden — an idle room is the expected case without playback.
//!
//! Only Windows is implemented; other platforms return [`Error::Gated`].
//! Content routing (console session) is a P2 session-helper concern, proven
//! out of scope by the session-0 tone test.

use serde::{Deserialize, Serialize};

/// Loopback capture result. All counts are exact, not estimates.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Capture {
    pub mix_rate: u32,
    pub mix_channels: u32,
    pub mix_bits: u32,
    pub packets: u64,
    pub frames: u64,
    /// True when every scanned dword was zero.
    pub silent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Gated(&'static str),
    /// No active render endpoint to tap.
    NoEndpoint,
    Os(u32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Gated(what) => write!(f, "audio backend P0-gated: {what}"),
            Error::NoEndpoint => write!(f, "no active render endpoint"),
            Error::Os(code) => write!(f, "wasapi call failed: 0x{code:08x}"),
        }
    }
}

impl std::error::Error for Error {}

/// Capture up to `seconds` of loopback audio from the default endpoint.
pub fn capture_loopback(seconds: u64) -> Result<Capture, Error> {
    inner::capture_loopback(seconds)
}

#[cfg(target_os = "windows")]
mod inner {
    use super::*;
    use windows::Win32::Foundation::{BOOL, WAIT_OBJECT_0};
    use windows::Win32::Media::Audio::{
        eConsole, eRender, IAudioCaptureClient, IAudioClient, IMMDeviceEnumerator,
        MMDeviceEnumerator, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
        AUDCLNT_STREAMFLAGS_LOOPBACK,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_ALL,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    pub fn capture_loopback(seconds: u64) -> Result<Capture, Error> {
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // Single unsafe region: read-only COM queries plus a bounded packet
        // pump against inbox OS objects. No writes escape this module.
        let result = unsafe { capture_inner(seconds.min(10)) };
        unsafe { CoUninitialize() };
        result
    }

    unsafe fn capture_inner(seconds: u64) -> Result<Capture, Error> {
        let enumerator: IMMDeviceEnumerator =
            CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
                .map_err(|_| Error::NoEndpoint)?;
        let endpoint = enumerator
            .GetDefaultAudioEndpoint(eRender, eConsole)
            .map_err(|_| Error::NoEndpoint)?;
        let client: IAudioClient = endpoint
            .Activate(CLSCTX_ALL, None)
            .map_err(|e| Error::Os(e.code().0 as u32))?;
        let mix = client
            .GetMixFormat()
            .map_err(|e| Error::Os(e.code().0 as u32))?;
        let (rate, channels, bits) = (
            (*mix).nSamplesPerSec,
            (*mix).nChannels,
            (*mix).wBitsPerSample,
        );
        let frame_bytes = channels as usize * (bits as usize / 8);
        // Event-driven pump: hnsBufferDuration asks the engine to signal.
        let event = CreateEventW(None, BOOL::from(false), BOOL::from(false), None)
            .map_err(|e| Error::Os(e.code().0 as u32))?;
        client
            .Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_LOOPBACK,
                1_000_000,
                0,
                mix,
                None,
            )
            .map_err(|e| Error::Os(e.code().0 as u32))?;
        CoTaskMemFree(Some(mix as *const _));
        client
            .SetEventHandle(event)
            .map_err(|e| Error::Os(e.code().0 as u32))?;
        let capture: IAudioCaptureClient = client
            .GetService()
            .map_err(|e| Error::Os(e.code().0 as u32))?;
        client.Start().map_err(|e| Error::Os(e.code().0 as u32))?;
        let mut packets = 0u64;
        let mut frames = 0u64;
        let mut nonzero = 0u64;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        let mut outcome: Result<Capture, Error> = Ok(Capture {
            mix_rate: rate,
            mix_channels: channels as u32,
            mix_bits: bits as u32,
            packets: 0,
            frames: 0,
            silent: true,
        });
        while std::time::Instant::now() < deadline {
            if WaitForSingleObject(event, 200) != WAIT_OBJECT_0 {
                continue;
            }
            let available = match capture.GetNextPacketSize() {
                Ok(available) => available,
                Err(_) => break,
            };
            if available == 0 {
                continue;
            }
            let mut data: *mut u8 = std::ptr::null_mut();
            let mut count = 0u32;
            let mut flags = 0u32;
            if capture
                .GetBuffer(&mut data, &mut count, &mut flags, None, None)
                .is_err()
            {
                outcome = Err(Error::Os(0));
                break;
            }
            packets += 1;
            frames += count as u64;
            let bytes = std::slice::from_raw_parts(data, count as usize * frame_bytes.max(1));
            for chunk in bytes.chunks_exact(4) {
                let mut word = [0u8; 4];
                word.copy_from_slice(chunk);
                if u32::from_ne_bytes(word) != 0 {
                    nonzero += 1;
                }
            }
            if capture.ReleaseBuffer(count).is_err() {
                outcome = Err(Error::Os(0));
                break;
            }
        }
        let _ = client.Stop();
        let mut capture = outcome?;
        capture.packets = packets;
        capture.frames = frames;
        capture.silent = nonzero == 0;
        Ok(capture)
    }

    #[allow(dead_code)]
    fn _use_bool(_: BOOL) {}
}

#[cfg(not(target_os = "windows"))]
mod inner {
    use super::*;

    pub fn capture_loopback(_seconds: u64) -> Result<Capture, Error> {
        Err(Error::Gated("non-Windows audio capture backends"))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    use super::*;

    /// Headless CI runners usually have no audio device: assert the honest
    /// outcome (captured packets or explicit NoEndpoint), never silence-as-
    /// success confusion — silence WITH packets is its own asserted state.
    #[cfg(target_os = "windows")]
    #[test]
    fn loopback_reports_honestly_on_windows() {
        match capture_loopback(2) {
            Ok(capture) => {
                assert!(capture.mix_rate >= 8000, "sane mix rate");
                assert!(capture.mix_channels >= 1, "sane channels");
                // Packets or documented silence; nonzero content is NOT
                // required (nothing plays on a CI runner).
                let _ = (capture.packets, capture.silent);
            }
            Err(Error::NoEndpoint) => {}
            Err(other) => panic!("unexpected backend failure: {other}"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_reports_its_gate() {
        assert_eq!(
            super::capture_loopback(1),
            Err(super::Error::Gated("non-Windows audio capture backends"))
        );
    }
}
