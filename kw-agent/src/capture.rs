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
pub fn open_output(
    output_index: u32,
    name: Option<&str>,
) -> Result<kw_platform::capture::Duplicator, String> {
    match name {
        Some(name) => kw_platform::capture::Duplicator::new_named(name),
        None => kw_platform::capture::Duplicator::new(output_index),
    }
    .map_err(|error| format!("console capture unavailable: {error}"))
}

/// Capture thread body: open, acquire → encode → feed until the session
/// ends. The duplicator opens per session (fresh mode read every time);
/// construction failure reports through `ready` so serve exits loudly
/// instead of serving a blind session. Timestamps come from the shared
/// session `anchor` (one clock for audio + video).
#[allow(clippy::too_many_arguments)]
pub fn run(
    output_index: u32,
    output_name: Option<String>,
    fps: u32,
    bitrate_bps: u32,
    gate: Arc<MediaGate>,
    feed: mpsc::SyncSender<MediaPacket>,
    stats: Arc<MediaStats>,
    ready: mpsc::Sender<Result<(), String>>,
    anchor: Instant,
    resize: mpsc::Receiver<crate::resize::Request>,
) {
    let fps = fps.max(1);
    let mut duplicator = Some(match open_output(output_index, output_name.as_deref()) {
        Ok(duplicator) => duplicator,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    });
    gate.capture_width.store(
        duplicator.as_ref().expect("opened output").size().0,
        Ordering::SeqCst,
    );
    gate.capture_height.store(
        duplicator.as_ref().expect("opened output").size().1,
        Ordering::SeqCst,
    );
    let mut encoder = match kw_encode::StreamEncoder::new(&kw_encode::Settings {
        width: duplicator.as_ref().expect("opened output").padded_size().0,
        height: duplicator.as_ref().expect("opened output").padded_size().1,
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
    let cadence = Duration::from_nanos(1_000_000_000 / fps as u64);
    let _awake = match kw_platform::capture::DisplayAwake::new() {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("capture: display idle request failed: {error}");
            return;
        }
    };
    let mut index: u64 = 0;
    let mut next_tick = anchor;
    let mut last_frame = None;
    let mut pending_resize: Option<(crate::resize::Request, kw_platform::display::Size)> = None;
    loop {
        if gate.ended.load(Ordering::SeqCst) {
            break;
        }
        if pending_resize
            .as_ref()
            .is_some_and(|(request, _)| Instant::now() >= request.deadline)
        {
            if let Some((request, _)) = pending_resize.take() {
                let _ = request.reply.send(Err("display-idr-timeout".into()));
            }
        }
        if pending_resize.is_none() {
            if let Ok(request) = resize.try_recv() {
                if Instant::now() >= request.deadline {
                    let _ = request.reply.send(Err("display-resize-expired".into()));
                    continue;
                }
                // Verify a prospective encoder before touching the guest mode.
                // A codec size/level refusal must leave the current stream usable.
                let mut prepared = match kw_encode::StreamEncoder::new(&kw_encode::Settings {
                    width: kw_platform::capture::pad16(request.width),
                    height: kw_platform::capture::pad16(request.height),
                    fps,
                    bitrate_bps,
                    max_keyframe_spacing: 60,
                }) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let _ = request
                            .reply
                            .send(Err(format!("display-encoder-preflight:{error}")));
                        continue;
                    }
                };
                if Instant::now() >= request.deadline {
                    let _ = request.reply.send(Err("display-resize-expired".into()));
                    continue;
                }
                let changed = kw_platform::display::resize_selected(
                    output_index,
                    output_name.as_deref(),
                    kw_platform::display::Size {
                        width: request.width,
                        height: request.height,
                    },
                )
                .and_then(|actual| {
                    // DXGI allows one duplication per output per process;
                    // release the old interface before opening its replacement.
                    let _ = duplicator.take();
                    let fresh = loop {
                        match open_output(output_index, output_name.as_deref()) {
                            Ok(fresh) => break fresh,
                            Err(error) if Instant::now() >= request.deadline => return Err(error),
                            Err(_) => std::thread::sleep(Duration::from_millis(50)),
                        }
                    };
                    if fresh.size() != (actual.width, actual.height) {
                        return Err("display-capture-mode-mismatch".into());
                    }
                    let (width, height) = fresh.padded_size();
                    if prepared.settings().width != width || prepared.settings().height != height {
                        prepared
                            .reconfigure(&kw_encode::Settings {
                                width,
                                height,
                                fps,
                                bitrate_bps,
                                max_keyframe_spacing: 60,
                            })
                            .map_err(|error| format!("display-encoder-reconfigure:{error}"))?;
                    }
                    encoder = prepared;
                    duplicator = Some(fresh);
                    last_frame = None;
                    Ok(actual)
                });
                match changed {
                    Ok(actual) => {
                        pending_resize = Some((request, actual));
                        gate.force_idr.store(true, Ordering::SeqCst);
                    }
                    Err(reason) => {
                        let _ = request.reply.send(Err(reason));
                        if duplicator.is_none() {
                            return;
                        }
                    }
                }
            }
        }
        match duplicator
            .as_mut()
            .expect("opened output")
            .capture(kw_platform::capture::DXGI_TIMEOUT_DEFAULT_MS)
        {
            Ok(Some(frame)) => last_frame = Some(frame),
            // A fresh MFT buffers input before emitting its first access unit.
            // An idle desktop must still give new viewers decodable pixels;
            // reuse the last real capture at the bounded DXGI timeout cadence.
            Ok(None) if last_frame.is_some() => {}
            Ok(None) => continue,
            Err(kw_platform::Error::SessionLost(_)) => {
                eprintln!("capture: session lost, rebuilding duplicator");
                let _ = duplicator.take();
                match open_output(output_index, output_name.as_deref()) {
                    Ok(fresh) => {
                        duplicator = Some(fresh);
                        last_frame = None;
                        let (w, h) = duplicator.as_ref().expect("rebuilt output").padded_size();
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
        }
        let frame = last_frame.as_ref().expect("real capture before encoding");
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
                    let confirmation = if chunk.keyframe && pending_resize.is_some() {
                        let (written, received) = mpsc::channel();
                        Some((written, received))
                    } else {
                        None
                    };
                    let packet = MediaPacket {
                        kind: kw_transport::MediaKind::H264,
                        payload: chunk.bytes,
                        written: confirmation.as_ref().map(|(written, _)| written.clone()),
                    };
                    if feed.send(packet).is_err() {
                        return;
                    }
                    if let Some((_, received)) = confirmation {
                        if let Some((request, actual)) = pending_resize.take() {
                            let remaining =
                                request.deadline.saturating_duration_since(Instant::now());
                            let result = received.recv_timeout(remaining)
                                .map_err(|_| "display-idr-write-failed".to_owned())
                                .map(|()| serde_json::json!({
                                    "requested": {"width": request.width, "height": request.height},
                                    "actual": {"width": actual.width, "height": actual.height},
                                    "codecReconfigured": true, "idrSent": true,
                                }));
                            let _ = request.reply.send(result);
                        }
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
                written: None,
            });
        }
    }
}
