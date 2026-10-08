//! Console capture source: DXGI duplication → encoder → wire.
//!
//! Same session contract as the synthetic source (fresh GOP per session,
//! caller clock, forced IDR on demand), but pixels come from the real
//! desktop. Session loss rebuilds the duplicator (and reconfigures the
//! encoder when the mode changed); fatal capture errors stop video for
//! the session while control continues — degraded, never silent.

use kw_transport::{MediaGate, MediaPacket, MediaStats};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// Open the console output now (fail-fast): a serve that cannot see the
/// desktop must not sit listening until the first viewer discovers it.
/// Returns the desktop size for encoder configuration.
pub fn open_output(output_index: u32) -> Result<kw_platform::capture::Duplicator, String> {
    kw_platform::capture::Duplicator::new(output_index)
        .map_err(|error| format!("console capture unavailable: {error}"))
}

/// Capture thread body: open, acquire → encode → feed until the session
/// ends. The duplicator opens per session (fresh mode read every time);
/// construction failure reports through `ready` so serve exits loudly
/// instead of serving a blind session.
#[allow(clippy::too_many_arguments)]
pub fn run(
    output_index: u32,
    fps: u32,
    bitrate_bps: u32,
    gate: Arc<MediaGate>,
    feed: mpsc::Sender<MediaPacket>,
    stats: Arc<MediaStats>,
    ready: mpsc::Sender<Result<(), String>>,
) {
    let fps = fps.max(1);
    let mut duplicator = match open_output(output_index) {
        Ok(duplicator) => duplicator,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let mut encoder = match kw_encode::StreamEncoder::new(&kw_encode::Settings {
        width: duplicator.padded_size().0,
        height: duplicator.padded_size().1,
        fps,
        bitrate_bps,
        max_keyframe_spacing: 60,
    }) {
        Ok(encoder) => {
            let _ = ready.send(Ok(()));
            encoder
        }
        Err(error) => {
            let _ = ready.send(Err(format!("capture encoder unavailable: {error}")));
            return;
        }
    };
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
    let mut next_tick = anchor;
    loop {
        if gate.ended.load(Ordering::SeqCst) {
            break;
        }
        let frame = match duplicator.capture(kw_platform::capture::DXGI_TIMEOUT_DEFAULT_MS) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(kw_platform::Error::SessionLost(_)) => {
                eprintln!("capture: session lost, rebuilding duplicator");
                match kw_platform::capture::Duplicator::new(0) {
                    Ok(fresh) => {
                        duplicator = fresh;
                        let (w, h) = duplicator.padded_size();
                        if w != encoder.settings().width || h != encoder.settings().height {
                            if let Err(error) = encoder.reconfigure(&kw_encode::Settings {
                                width: w,
                                height: h,
                                fps,
                                bitrate_bps,
                                max_keyframe_spacing: 60,
                            }) {
                                eprintln!("capture: reconfigure failed: {error}");
                                return;
                            }
                        }
                        gate.force_idr.store(true, Ordering::SeqCst);
                        continue;
                    }
                    Err(error) => {
                        eprintln!("capture: rebuild failed: {error}");
                        return;
                    }
                }
            }
            Err(error) => {
                eprintln!("capture: {error}");
                return;
            }
        };
        // Pacing: present-driven would burst on activity; cadence keeps the
        // encoder (and viewers) at the negotiated frame rate.
        next_tick += cadence;
        let now = Instant::now();
        if next_tick > now {
            std::thread::sleep(next_tick - now);
        } else {
            next_tick = now;
        }
        let force = index == 0 || gate.force_idr.swap(false, Ordering::SeqCst);
        let timestamp_100ns = u128::min(anchor.elapsed().as_nanos(), i64::MAX as u128) as i64 / 100;
        match encoder.push(&frame.nv12, timestamp_100ns, force) {
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
                eprintln!("capture encoder failed at frame {index}: {error}");
                return;
            }
        }
        index += 1;
    }
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
