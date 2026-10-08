//! Console audio source: WASAPI loopback → 48kHz stereo → Opus.
//!
//! Same session contract as video (admission-gated, shared session clock,
//! fail-fast when the endpoint is missing). Silence encodes to tiny
//! packets — the clock never stalls on a quiet console. Device loss
//! reopens the tap boundedly; anything else ends audio for the session
//! while video/control continue (degraded, never silent).

use kw_transport::{MediaGate, MediaPacket, MediaStats};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// Consecutive tap reopen attempts before giving up audio for the session.
const MAX_REOPENS: u32 = 10;

/// Audio thread body: tap → normalize → resample → 20ms Opus → feed.
/// Reports readiness once the first tap opens; serve exits loudly when it
/// never does. Shares the session `anchor` clock with video for A/V
/// linkage (residual pipeline offsets are measured, not assumed).
pub fn run(
    gate: Arc<MediaGate>,
    feed: mpsc::Sender<MediaPacket>,
    stats: Arc<MediaStats>,
    ready: mpsc::Sender<Result<(), String>>,
    anchor: Instant,
) {
    let mut announced = false;
    let mut reopens = 0u32;
    loop {
        match pump(
            &gate,
            &feed,
            &stats,
            anchor,
            &mut announced,
            &ready,
            reopens,
        ) {
            PumpEnd::Done => return,
            PumpEnd::Reopen => {
                reopens += 1;
                if reopens > MAX_REOPENS {
                    eprintln!("capture audio: endpoint keeps disappearing, stopping audio");
                    return;
                }
                eprintln!("capture audio: reopening tap (attempt {reopens})");
                std::thread::sleep(Duration::from_secs(1));
            }
            PumpEnd::Fatal(error) => {
                eprintln!("capture audio: {error}");
                return;
            }
        }
    }

    enum PumpEnd {
        Done,
        Reopen,
        Fatal(String),
    }

    #[allow(clippy::too_many_arguments)]
    fn pump(
        gate: &Arc<MediaGate>,
        feed: &mpsc::Sender<MediaPacket>,
        stats: &Arc<MediaStats>,
        anchor: Instant,
        announced: &mut bool,
        ready: &mpsc::Sender<Result<(), String>>,
        reopens: u32,
    ) -> PumpEnd {
        let tap = match kw_audio::tap::LoopbackTap::start() {
            Ok(tap) => {
                let format = tap.mix_format();
                if !*announced {
                    println!(
                        "capture audio {}Hz {}ch {}bit{}",
                        format.rate,
                        format.channels,
                        format.bits,
                        if format.float { "f" } else { "" },
                    );
                    let _ = ready.send(Ok(()));
                    *announced = true;
                }
                tap
            }
            Err(error) => {
                let message = format!("audio tap unavailable: {error}");
                if reopens == 0 {
                    let _ = ready.send(Err(message.clone()));
                }
                return PumpEnd::Fatal(message);
            }
        };
        let format = tap.mix_format();
        let mut resampler = kw_audio::resample::Resampler::new(format.rate);
        let mut opus = match kw_audio::opus::Encoder::new() {
            Ok(encoder) => encoder,
            Err(error) => {
                let message = format!("opus encoder unavailable: {error}");
                if reopens == 0 {
                    let _ = ready.send(Err(message.clone()));
                }
                return PumpEnd::Fatal(message);
            }
        };
        let mut accumulator = kw_audio::tap::FrameAccumulator::new();
        let mut sequence = 0u64;
        loop {
            if gate.ended.load(Ordering::SeqCst) {
                return PumpEnd::Done;
            }
            let batch = match tap.read(200) {
                Ok(Some(batch)) => batch,
                Ok(None) => continue,
                Err(kw_audio::Error::DeviceLost | kw_audio::Error::NoEndpoint) => {
                    return PumpEnd::Reopen;
                }
                Err(error) => return PumpEnd::Fatal(format!("tap read failed: {error}")),
            };
            let (packet_format, bytes, _) = batch;
            debug_assert_eq!(packet_format, format, "mix format is per-tap stable");
            let pcm = match kw_audio::tap::pcm_to_f32(&bytes, format) {
                Ok(pcm) => pcm,
                Err(error) => return PumpEnd::Fatal(format!("mix decode failed: {error}")),
            };
            let stereo = kw_audio::tap::to_stereo(&pcm, format.channels);
            accumulator.push(&resampler.push_stereo(&stereo));
            while let Some(frame) = accumulator.pop_frame() {
                let packet = match opus.encode_frame(&frame) {
                    Ok(packet) => packet,
                    Err(error) => return PumpEnd::Fatal(format!("opus encode failed: {error}")),
                };
                sequence += 1;
                if sequence % 750 == 0 {
                    eprintln!(
                        "capture audio: {} packets ({:.1}s session clock)",
                        sequence,
                        anchor.elapsed().as_secs_f64()
                    );
                }
                stats.frames_sent.fetch_add(1, Ordering::SeqCst);
                stats
                    .bytes_sent
                    .fetch_add(packet.len() as u64, Ordering::SeqCst);
                if feed
                    .send(MediaPacket {
                        kind: kw_transport::MediaKind::Opus,
                        payload: packet,
                    })
                    .is_err()
                {
                    return PumpEnd::Done;
                }
            }
        }
    }
}
