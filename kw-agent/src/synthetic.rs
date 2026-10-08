//! Synthetic video source for the media proof path.
//!
//! Moving-gradient NV12 frames through the real software encoder. This
//! proves encode → wire → viewer WITHOUT capture hardware: pixels are
//! synthetic but the MFT, Annex-B framing, IDR discipline, timestamps and
//! backpressure path are all production. Capture backends replace ONLY the
//! frame generator (Phase 2); everything downstream stays identical.
//!
//! The encoder is constructed inside this thread (COM apartment rules) and
//! torn down per session, so every session opens with a fresh SPS/PPS/IDR.

use kw_transport::{MediaGate, MediaPacket, MediaStats};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// Luma ramp + neutral chroma, shifted per frame so motion is visible and
/// the encoder cannot collapse the stream to a single static frame.
pub fn gradient_nv12(width: u32, height: u32, shift: u8) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let mut frame = vec![128u8; w * h * 3 / 2];
    for y in 0..h {
        for x in 0..w {
            frame[y * w + x] = ((x + y + shift as usize) & 0xff) as u8;
        }
    }
    frame
}

/// Encoder thread body. Signals construction outcome on `ready`, then paces
/// frames at `fps` once admitted. Exits on session end, feed loss, or an
/// encoder failure (logged, never silent).
pub fn run(
    settings: kw_encode::Settings,
    gate: Arc<MediaGate>,
    feed: mpsc::Sender<MediaPacket>,
    stats: Arc<MediaStats>,
    ready: mpsc::Sender<Result<(), String>>,
) {
    let mut encoder = match kw_encode::StreamEncoder::new(&settings) {
        Ok(encoder) => {
            let _ = ready.send(Ok(()));
            encoder
        }
        Err(error) => {
            let _ = ready.send(Err(format!("synthetic encoder unavailable: {error}")));
            return;
        }
    };
    let (width, height, fps) = (settings.width, settings.height, settings.fps.max(1));
    // Wait for admission: no anonymous bytes before the ticket gate.
    while !gate.admitted.load(Ordering::SeqCst) {
        if gate.ended.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let anchor = Instant::now();
    let cadence = Duration::from_nanos(1_000_000_000 / fps as u64);
    let mut index: u64 = 0;
    loop {
        if gate.ended.load(Ordering::SeqCst) {
            break;
        }
        let tick = anchor + cadence * (index as u32 + 1);
        let now = Instant::now();
        if tick > now {
            std::thread::sleep(tick - now);
        }
        // First frame of every session forces SPS/PPS/IDR: joiners always
        // land on a decodable GOP without waiting a full spacing.
        let force = index == 0 || gate.force_idr.swap(false, Ordering::SeqCst);
        let frame = gradient_nv12(width, height, (index & 0xff) as u8);
        let timestamp_100ns = u128::min(anchor.elapsed().as_nanos(), i64::MAX as u128) as i64 / 100;
        match encoder.push(&frame, timestamp_100ns, force) {
            Ok(chunks) => {
                for chunk in chunks {
                    if chunk.keyframe {
                        stats.keyframes_sent.fetch_add(1, Ordering::SeqCst);
                    }
                    let packet = MediaPacket {
                        kind: kw_transport::MediaKind::H264,
                        payload: chunk.bytes,
                    };
                    if feed.send(packet).is_err() {
                        return;
                    }
                }
            }
            Err(error) => {
                eprintln!("synthetic encoder failed at frame {index}: {error}");
                return;
            }
        }
        index += 1;
    }
    // Trailing GOP, best-effort: the socket may already be gone.
    if let Ok(trailing) = encoder.finish() {
        for chunk in trailing {
            if chunk.keyframe {
                stats.keyframes_sent.fetch_add(1, Ordering::SeqCst);
            }
            let _ = feed.send(MediaPacket {
                kind: kw_transport::MediaKind::H264,
                payload: chunk.bytes,
            });
        }
    }
}
