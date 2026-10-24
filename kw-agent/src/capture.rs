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

/// Open the console output. Returns the typed platform error so callers can
/// tell a genuinely unusable desktop (no outputs, non-Windows) apart from one
/// that is merely *temporarily* unavailable — Windows owns the secure desktop
/// while a UAC prompt is up — and recover instead of aborting the session.
pub fn open_output(
    output_index: u32,
    name: Option<&str>,
) -> Result<kw_platform::capture::Duplicator, kw_platform::Error> {
    match name {
        Some(name) => kw_platform::capture::Duplicator::new_named(name),
        None => kw_platform::capture::Duplicator::new(output_index),
    }
}

/// Build a fresh duplicator + encoder for the current desktop, waiting out a
/// temporary loss (secure desktop) instead of ending the capture thread.
/// `Ok(None)` means the session ended while waiting.
fn attempt_establish(
    output_index: u32,
    output_name: Option<&str>,
    fps: u32,
    bitrate_bps: u32,
    gate: &MediaGate,
    resize: &mpsc::Receiver<crate::resize::Request>,
) -> Result<Option<(kw_platform::capture::Duplicator, kw_encode::StreamEncoder)>, String> {
    match reopen(&gate.ended, Duration::from_millis(250), || {
        // Reject resize promptly while capture is suspended rather than
        // leaving the control thread blocked on a dead owner.
        while let Ok(request) = resize.try_recv() {
            let _ = request
                .reply
                .send(Err("display-desktop-unavailable".into()));
        }
        open_output(output_index, output_name)
    }) {
        Ok(Some(fresh)) => {
            gate.capture_width.store(fresh.size().0, Ordering::SeqCst);
            gate.capture_height.store(fresh.size().1, Ordering::SeqCst);
            let (width, height) = fresh.padded_size();
            // Recreate even at the same size: old buffered GOP references
            // must not survive a desktop access loss.
            match kw_encode::StreamEncoder::new(&kw_encode::Settings {
                width,
                height,
                fps,
                bitrate_bps,
                max_keyframe_spacing: 60,
            }) {
                Ok(encoder) => Ok(Some((fresh, encoder))),
                Err(error) => Err(format!("capture recovery encoder failed: {error}")),
            }
        }
        Ok(None) => Ok(None),
        Err(error) => Err(format!("console capture rebuild failed: {error}")),
    }
}

/// Publish only the capture and encoder objects that were actually opened.
fn report_video(
    capture: &kw_platform::capture::Duplicator,
    encoder: &kw_encode::StreamEncoder,
    gate: &MediaGate,
) {
    if let Ok(mut video) = gate.video.lock() {
        *video = capture.info().map(|info| {
            serde_json::json!({
                "capture": info,
                "encoder": encoder.info(),
            })
        });
    }
}

/// Keep the admitted transport alive while Windows owns the secure desktop.
/// Polling is bounded and cancellable, including repeated access-denied errors.
fn reopen<T>(
    ended: &std::sync::atomic::AtomicBool,
    delay: Duration,
    mut open: impl FnMut() -> Result<T, kw_platform::Error>,
) -> Result<Option<T>, kw_platform::Error> {
    loop {
        if ended.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match open() {
            Ok(value) => return Ok(Some(value)),
            Err(error) if kw_platform::capture::recoverable(&error) => std::thread::sleep(delay),
            Err(error) => return Err(error),
        }
    }
}

/// GDI mode readback can lead DXGI topology by several frames. A successful
/// duplication open is not sufficient: release stale-size duplicators and wait
/// for the selected output to converge within the resize transaction's budget.
fn reopen_resized<T>(
    ended: &std::sync::atomic::AtomicBool,
    deadline: Instant,
    delay: Duration,
    expected: (u32, u32),
    mut open: impl FnMut() -> Result<T, String>,
    size: impl Fn(&T) -> (u32, u32),
) -> Result<T, String> {
    loop {
        if ended.load(Ordering::SeqCst) {
            return Err("display-session-ended".into());
        }
        let reason = match open() {
            Ok(fresh) if size(&fresh) == expected => return Ok(fresh),
            Ok(_) => "display-capture-mode-mismatch".into(),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(reason);
        }
        std::thread::sleep(delay.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Capture thread body: open, acquire → encode → feed until the session
/// ends. The duplicator opens per session (fresh mode read every time);
/// a genuinely unusable desktop reports through `ready` so serve exits
/// loudly instead of serving a blind session, while a temporary denial
/// (secure desktop) starts suspended and recovers. Timestamps come from the
/// shared session `anchor` (one clock for audio + video).
#[allow(clippy::too_many_arguments)]
pub fn run(
    output_index: u32,
    output_name: Option<String>,
    fps: u32,
    bitrate_bps: u32,
    isolate_display: bool,
    gate: Arc<MediaGate>,
    feed: mpsc::SyncSender<MediaPacket>,
    stats: Arc<MediaStats>,
    ready: mpsc::Sender<Result<(), String>>,
    anchor: Instant,
    resize: mpsc::Receiver<crate::resize::Request>,
) {
    let fps = fps.max(1);
    // Open now when the desktop is reachable. A *temporary* denial — Windows
    // owns the secure desktop while a UAC prompt is up — must not end the
    // session: start with capture suspended, report readiness, and recover in
    // the loop once access returns. A genuinely unusable desktop (no outputs,
    // non-Windows) still fails readiness loudly rather than serving blind.
    let (mut duplicator, mut encoder) = match open_output(output_index, output_name.as_deref()) {
        Ok(duplicator) => {
            let settings = kw_encode::Settings {
                width: duplicator.padded_size().0,
                height: duplicator.padded_size().1,
                fps,
                bitrate_bps,
                max_keyframe_spacing: 60,
            };
            match kw_encode::StreamEncoder::new(&settings) {
                Ok(encoder) => (Some(duplicator), Some(encoder)),
                Err(error) => {
                    let _ = ready.send(Err(format!("capture encoder unavailable: {error}")));
                    return;
                }
            }
        }
        Err(error) if kw_platform::capture::recoverable(&error) => {
            eprintln!(
                "capture: console temporarily unavailable at startup ({error}); \
                     serving suspended until access returns"
            );
            gate.capture_suspended.store(true, Ordering::SeqCst);
            (None, None)
        }
        Err(error) => {
            let _ = ready.send(Err(format!("console capture unavailable: {error}")));
            return;
        }
    };
    if let Some(duplicator) = duplicator.as_ref() {
        if let Some(encoder) = encoder.as_ref() {
            report_video(duplicator, encoder, &gate);
        }
        gate.capture_width
            .store(duplicator.size().0, Ordering::SeqCst);
        gate.capture_height
            .store(duplicator.size().1, Ordering::SeqCst);
    }
    let _ = ready.send(Ok(()));
    // Wait for admission: no anonymous bytes before the ticket gate.
    while !gate.admitted.load(Ordering::SeqCst) {
        if gate.ended.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if gate.control_only.load(Ordering::SeqCst) {
        return; // Drop duplication/encoder; the admitted watcher needs status only.
    }
    // Construct only after admission, and never for a telemetry-only helper.
    // Drop restores the console on disconnect/takeover/service stop and on
    // every capture failure return. Reopen duplication after the topology edit.
    let _display_session = if isolate_display && gate.display_session.load(Ordering::SeqCst) {
        match output_name
            .as_deref()
            .map(kw_platform::display::VirtualDisplaySession::begin)
        {
            Some(Ok(session)) => {
                duplicator = None;
                encoder = None;
                Some(session)
            }
            Some(Err(error)) => {
                eprintln!("capture: display isolation failed: {error}");
                None
            }
            None => None,
        }
    } else {
        None
    };
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
    // One-time grace per pending resize: a slow encoder warmup (large
    // software modes) can miss the first confirmation deadline with frames
    // flowing but no keyframe emitted yet. Extend once with a fresh
    // force-IDR pulse before NACKing; a truly wedged encoder still fails,
    // just ~IDR_GRACE_SECS later.
    let mut resize_grace_used = false;
    loop {
        if gate.ended.load(Ordering::SeqCst) {
            break;
        }
        // Suspended (never established, or access lost): wait out the secure
        // desktop, then build a fresh duplicator + encoder before resuming.
        if duplicator.is_none() {
            if let Some((request, _)) = pending_resize.take() {
                resize_grace_used = false;
                let _ = request
                    .reply
                    .send(Err("display-desktop-unavailable".into()));
            }
            match attempt_establish(
                output_index,
                output_name.as_deref(),
                fps,
                bitrate_bps,
                &gate,
                &resize,
            ) {
                Ok(Some((fresh, fresh_encoder))) => {
                    report_video(&fresh, &fresh_encoder, &gate);
                    duplicator = Some(fresh);
                    encoder = Some(fresh_encoder);
                    last_frame = None;
                    next_tick = Instant::now();
                    gate.capture_recoveries.fetch_add(1, Ordering::SeqCst);
                    gate.force_idr.store(true, Ordering::SeqCst);
                    eprintln!("capture: normal desktop access restored");
                }
                Ok(None) => break,
                Err(error) => {
                    eprintln!("capture: {error}");
                    return;
                }
            }
        }
        if pending_resize
            .as_ref()
            .is_some_and(|(request, _)| Instant::now() >= request.deadline)
        {
            if !resize_grace_used {
                resize_grace_used = true;
                if let Some((request, _)) = pending_resize.as_mut() {
                    request.deadline =
                        Instant::now() + Duration::from_secs(crate::resize::IDR_GRACE_SECS);
                }
                gate.force_idr.store(true, Ordering::SeqCst);
                eprintln!("capture: resize confirmation slow, extended with fresh IDR pulse");
            } else if let Some((request, _)) = pending_resize.take() {
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
                    let fresh = reopen_resized(
                        &gate.ended,
                        request.deadline,
                        Duration::from_millis(50),
                        (actual.width, actual.height),
                        || {
                            open_output(output_index, output_name.as_deref())
                                .map_err(|e| e.to_string())
                        },
                        |fresh| fresh.size(),
                    )?;
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
                    report_video(&fresh, &prepared, &gate);
                    encoder = Some(prepared);
                    duplicator = Some(fresh);
                    last_frame = None;
                    Ok(actual)
                });
                match changed {
                    Ok(actual) => {
                        pending_resize = Some((request, actual));
                        resize_grace_used = false;
                        gate.force_idr.store(true, Ordering::SeqCst);
                    }
                    Err(reason) => {
                        let _ = request.reply.send(Err(reason));
                        if duplicator.is_none() {
                            // The OS may already have changed modes. Rebuild at
                            // its actual size rather than leaving control alive
                            // with a permanently dead capture thread.
                            gate.capture_suspended.store(true, Ordering::SeqCst);
                            if let Ok(mut video) = gate.video.lock() {
                                *video = None;
                            }
                            encoder = None;
                            last_frame = None;
                            continue;
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
            Err(error) if kw_platform::capture::recoverable(&error) => {
                eprintln!("capture: desktop temporarily unavailable ({error}); waiting to recover");
                gate.capture_suspended.store(true, Ordering::SeqCst);
                if let Ok(mut video) = gate.video.lock() {
                    *video = None;
                }
                let _ = duplicator.take();
                encoder = None;
                last_frame = None;
                if let Some((request, _)) = pending_resize.take() {
                    resize_grace_used = false;
                    let _ = request
                        .reply
                        .send(Err("display-desktop-unavailable".into()));
                }
                // The top of the loop re-establishes a fresh duplicator +
                // encoder once access returns (see attempt_establish).
                continue;
            }
            Err(error) => {
                eprintln!("capture: {error}");
                return;
            }
        }
        let frame = last_frame.as_ref().expect("real capture before encoding");
        gate.capture_suspended.store(false, Ordering::SeqCst);
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
        let encoder = encoder
            .as_mut()
            .expect("encoder with an established output");
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
    if let Some(encoder) = encoder.take() {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    #[test]
    fn resize_waits_for_dxgi_size_after_gdi_readback() {
        let ended = AtomicBool::new(false);
        let mut attempts = 0;
        let fresh = reopen_resized(
            &ended,
            Instant::now() + Duration::from_secs(1),
            Duration::ZERO,
            (2560, 1440),
            || {
                attempts += 1;
                match attempts {
                    1 => Ok((1920, 1080)),
                    2 => Err("transient access loss".into()),
                    _ => Ok((2560, 1440)),
                }
            },
            |size| *size,
        )
        .unwrap();
        assert_eq!(fresh, (2560, 1440));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn resize_topology_wait_is_bounded_and_cancellable() {
        let ended = AtomicBool::new(false);
        let result = reopen_resized(
            &ended,
            Instant::now(),
            Duration::ZERO,
            (2560, 1440),
            || Ok((1920, 1080)),
            |size| *size,
        );
        assert_eq!(result.unwrap_err(), "display-capture-mode-mismatch");
        ended.store(true, Ordering::SeqCst);
        let result = reopen_resized::<()>(
            &ended,
            Instant::now() + Duration::from_secs(30),
            Duration::ZERO,
            (2560, 1440),
            || panic!("must not open after cancellation"),
            |_| (0, 0),
        );
        assert_eq!(result.unwrap_err(), "display-session-ended");
    }
    #[test]
    fn repeated_secure_desktop_denials_do_not_end_capture() {
        let ended = AtomicBool::new(false);
        let mut attempts = 0;
        let restored = reopen(&ended, Duration::ZERO, || {
            attempts += 1;
            if attempts < 4 {
                Err(kw_platform::Error::Os(0x80070005))
            } else {
                Ok("fresh-desktop")
            }
        })
        .unwrap();
        assert_eq!(restored, Some("fresh-desktop"));
        assert_eq!(attempts, 4);
    }
    #[test]
    fn desktop_wait_is_cancellable_and_fatal_errors_stay_fatal() {
        let ended = AtomicBool::new(false);
        let cancelled = reopen::<()>(&ended, Duration::ZERO, || {
            ended.store(true, Ordering::SeqCst);
            Err(kw_platform::Error::Os(0x80070005))
        })
        .unwrap();
        assert!(cancelled.is_none());
        let fatal = reopen::<()>(&AtomicBool::new(false), Duration::ZERO, || {
            Err(kw_platform::Error::Os(0x80070057))
        });
        assert_eq!(fatal.unwrap_err(), kw_platform::Error::Os(0x80070057));
    }
}
