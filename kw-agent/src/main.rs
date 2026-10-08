//! Workspace agent service entry point (v0.1).
//!
//! Capture/display/audio backends are **P0-gated**: capability inventory,
//! enrollment and the heartbeat daemon always exist. `serve` picks up the
//! console-session clipboard (`--clipboard`) and interactive input injection
//! (`--input`, only usable from the active console session) when available;
//! the rest of this binary performs no capture, mode changes or privileged
//! operations.

mod audio;
mod capture;
mod daemon;
mod platform;
mod synthetic;

fn usage(code: i32) -> ! {
    eprintln!(
        "kw-agent {} ({})",
        kw_protocol::AGENT_VERSION,
        platform::describe()
    );
    eprintln!("usage:");
    eprintln!("  kw-agent --version|--platform|--hello");
    eprintln!("  kw-agent daemon --workspace-uid UID --workspace-generation GEN [--data-dir DIR] [--interval-secs N] [--beats N]");
    eprintln!("  kw-agent serve --workspace-uid UID --workspace-generation GEN [--port PORT] [--bind ADDR] [--max-sessions N] [--max-idle-secs N] [--clipboard] [--input] [--synthetic-video [--synthetic-fps N] [--synthetic-size WxH] [--synthetic-bitrate-bps N] | --capture-video [--capture-output N] [--capture-fps N] [--capture-bitrate-bps N]] [--capture-audio]");
    eprintln!(
        "  kw-agent connect-test --server ADDR --workspace-uid UID --workspace-generation GEN [--media-seconds N] [--save-video PATH] [--save-audio PATH]"
    );
    eprintln!("  kw-agent encode-test [--width W] [--height H] [--frames N] [--bitrate-bps B]");
    eprintln!("  kw-agent audio-test [--seconds N] [--require-endpoint]");
    std::process::exit(code);
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("kw-agent {}", kw_protocol::AGENT_VERSION);
        }
        Some("--platform") => {
            let info = platform::info();
            println!("os={} arch={} context={}", info.os, info.arch, info.context);
        }
        Some("--hello") => match kw_platform::inventory() {
            Ok(inventory) => {
                let envelope = serde_json::json!({
                    "protocol": kw_protocol::PROTOCOL,
                    "protocolVersion": kw_protocol::PROTOCOL_VERSION,
                    "sessionId": "unassigned",
                    "generation": 0,
                    "sequence": 0,
                    "sentAtNs": 0,
                    "channel": "control",
                    "type": "hello",
                    "payload": inventory,
                });
                // Shape-check before printing: never emit what we reject.
                let parsed: kw_protocol::Envelope = match serde_json::from_value(envelope.clone()) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        eprintln!("hello failed self-validation: {error}");
                        std::process::exit(1);
                    }
                };
                if let Err(error) = kw_protocol::check_envelope(&parsed) {
                    eprintln!("hello failed self-validation: {error}");
                    std::process::exit(1);
                }
                println!("{envelope}");
            }
            Err(error) => {
                eprintln!("inventory unavailable: {error}");
                std::process::exit(1);
            }
        },
        Some("daemon") => {
            let workspace_uid = flag_value(&args, "--workspace-uid").unwrap_or_else(|| {
                eprintln!("daemon: --workspace-uid is required");
                usage(2);
            });
            let workspace_generation =
                flag_value(&args, "--workspace-generation").unwrap_or_else(|| {
                    eprintln!("daemon: --workspace-generation is required");
                    usage(2);
                });
            let options = daemon::Options {
                data_dir: flag_value(&args, "--data-dir")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(daemon::default_data_dir),
                interval_secs: flag_value(&args, "--interval-secs")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(daemon::DEFAULT_INTERVAL_SECS),
                beats: flag_value(&args, "--beats")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
                workspace_uid,
                workspace_generation,
            };
            if options.interval_secs == 0 {
                eprintln!("daemon: --interval-secs must be at least 1");
                usage(2);
            }
            match daemon::run(&options) {
                Ok(beats) => println!("daemon exited after {beats} beats"),
                Err(error) => {
                    eprintln!("daemon: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("serve") => {
            let workspace_uid = flag_value(&args, "--workspace-uid").unwrap_or_else(|| {
                eprintln!("serve: --workspace-uid is required");
                usage(2);
            });
            let workspace_generation =
                flag_value(&args, "--workspace-generation").unwrap_or_else(|| {
                    eprintln!("serve: --workspace-generation is required");
                    usage(2);
                });
            let port: u16 = flag_value(&args, "--port")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let max_sessions: u64 = flag_value(&args, "--max-sessions")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let max_idle_secs: u64 = flag_value(&args, "--max-idle-secs")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            // Bind loopback by default (safe for loopback diagnostics); the
            // cluster data path reaches the guest on its pod-network address,
            // so proof/product serve passes --bind 0.0.0.0 explicitly.
            let bind = flag_value(&args, "--bind").unwrap_or_else(|| "127.0.0.1".into());
            let server = kw_transport::Server::bind(
                (bind.as_str(), port),
                workspace_uid,
                workspace_generation,
            )
            .unwrap_or_else(|error| {
                eprintln!("serve: bind failed: {error}");
                std::process::exit(1);
            });
            let server = if args.iter().any(|arg| arg == "--clipboard") {
                if !cfg!(target_os = "windows") {
                    eprintln!("serve: clipboard backend unavailable on this platform");
                    std::process::exit(2);
                }
                struct ConsoleClipboard;
                impl kw_transport::Clipboard for ConsoleClipboard {
                    fn read_text(&self) -> Result<Option<String>, String> {
                        kw_platform::clipboard::read_text()
                    }
                    fn write_text(&self, text: &str) -> Result<(), String> {
                        kw_platform::clipboard::write_text(text)
                    }
                }
                server.with_clipboard(std::sync::Arc::new(ConsoleClipboard))
            } else {
                server
            };
            // Interactive input injection. Windows confines SendInput to the
            // caller's session, so only wire the backend when this process
            // shares the active console session; otherwise fail fast instead
            // of advertising capability we cannot deliver.
            let server = if args.iter().any(|arg| arg == "--input") {
                let state = kw_platform::input::session_state();
                if !state.can_inject() {
                    eprintln!(
                        "serve: --input unavailable: process session {:?}, active console session {:?} (needs the interactive console session)",
                        state.current, state.active_console
                    );
                    std::process::exit(2);
                }
                let injector = kw_platform::input::Injector::new().unwrap_or_else(|error| {
                    eprintln!("serve: input backend unavailable: {error}");
                    std::process::exit(2);
                });
                struct InjectorInput(std::sync::Mutex<kw_platform::input::Injector>);
                impl kw_transport::Input for InjectorInput {
                    fn key(&self, keysym: u32, down: bool) -> Result<(), String> {
                        self.0
                            .lock()
                            .map_err(|e| format!("input lock: {e}"))?
                            .key(keysym, down)
                    }
                    fn pointer(&self, x: i32, y: i32, buttons: u8) -> Result<(), String> {
                        self.0
                            .lock()
                            .map_err(|e| format!("input lock: {e}"))?
                            .pointer(x, y, buttons)
                    }
                    fn wheel(&self, dx: i32, dy: i32) -> Result<(), String> {
                        self.0
                            .lock()
                            .map_err(|e| format!("input lock: {e}"))?
                            .wheel(dx, dy)
                    }
                    fn reset(&self) {
                        if let Ok(mut injector) = self.0.lock() {
                            injector.release();
                        }
                    }
                }
                println!("input injection enabled (session {:?})", state.current);
                server.with_input(std::sync::Arc::new(InjectorInput(std::sync::Mutex::new(
                    injector,
                ))))
            } else {
                server
            };
            let address = server.local_address().unwrap_or_else(|error| {
                eprintln!("serve: no local address: {error}");
                std::process::exit(1);
            });
            println!("listening {address}");
            // Synthetic video (media proof without capture hardware):
            // per-session encoder thread through the real software MFT.
            // Absent by default: pure control plane, exactly as before.
            // Boolean flag (no value): present anywhere in argv enables it.
            let synthetic = args.iter().any(|arg| arg == "--synthetic-video");
            let capture_video = args.iter().any(|arg| arg == "--capture-video");
            if synthetic && capture_video {
                eprintln!("serve: --synthetic-video and --capture-video are exclusive");
                usage(2);
            }
            let video = synthetic || capture_video;
            let synth_settings = kw_encode::Settings {
                width: 320,
                height: 240,
                fps: flag_value(&args, "--synthetic-fps")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(30),
                bitrate_bps: flag_value(&args, "--synthetic-bitrate-bps")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(2_000_000),
                max_keyframe_spacing: 60,
            };
            let synth_settings = match flag_value(&args, "--synthetic-size").as_deref() {
                Some(size) => {
                    let mut parts = size.splitn(2, 'x');
                    let width: u32 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                    let height: u32 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                    if width == 0 || height == 0 {
                        eprintln!("serve: --synthetic-size must be WxH (e.g. 640x480)");
                        usage(2);
                    }
                    if width % 16 != 0 || height % 16 != 0 {
                        eprintln!("serve: --synthetic-size must be macroblock-aligned (multiples of 16); the software MFT faults otherwise");
                        usage(2);
                    }
                    kw_encode::Settings {
                        width,
                        height,
                        ..synth_settings
                    }
                }
                None => synth_settings,
            };
            if synthetic {
                println!(
                    "synthetic video {}x{}@{}fps {}bps",
                    synth_settings.width,
                    synth_settings.height,
                    synth_settings.fps,
                    synth_settings.bitrate_bps
                );
                // Fail fast: a proof serve that cannot encode must not sit
                // listening until the first viewer arrives to discover it.
                if let Err(error) = kw_encode::StreamEncoder::new(&synth_settings) {
                    eprintln!("serve: synthetic encoder unavailable: {error}");
                    std::process::exit(2);
                }
            }
            let capture_fps: u32 = flag_value(&args, "--capture-fps")
                .and_then(|value| value.parse().ok())
                .unwrap_or(30);
            let capture_bitrate_bps: u32 = flag_value(&args, "--capture-bitrate-bps")
                .and_then(|value| value.parse().ok())
                .unwrap_or(2_000_000);
            let capture_output: u32 = flag_value(&args, "--capture-output")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let capture_audio = args.iter().any(|arg| arg == "--capture-audio");
            if capture_video {
                println!(
                    "capture video output {capture_output}@{capture_fps}fps {capture_bitrate_bps}bps"
                );
                // Fail fast on console visibility (not on pixels: the screen
                // may legitimately be static at startup).
                if let Err(error) = kw_platform::capture::Duplicator::new(capture_output) {
                    eprintln!("serve: {error}");
                    std::process::exit(2);
                }
            }
            if capture_audio {
                println!("capture audio loopback → 48kHz stereo Opus");
            }
            let mut served = 0u64;
            let mut idle_since = std::time::Instant::now();
            // Non-blocking accept would need polling scaffolding; instead the
            // listener inherits no timeout and serve_one blocks, so max-idle
            // is enforced between sessions only. Documented, not silent.
            loop {
                if max_sessions != 0 && served >= max_sessions {
                    break;
                }
                if max_idle_secs != 0
                    && served > 0
                    && idle_since.elapsed().as_secs() >= max_idle_secs
                {
                    break;
                }
                // Per-session media feed: fresh encoder, fresh GOP, fresh
                // timestamps every session (joiners land on SPS/PPS/IDR).
                // Video and audio threads share one feed and one session
                // clock (anchor); each fails its own readiness loudly.
                let media = video || capture_audio;
                let (gate, feed_rx, stats, media_threads) = if media {
                    use std::sync::{mpsc, Arc};
                    let gate = Arc::new(kw_transport::MediaGate::default());
                    let stats = Arc::new(kw_transport::MediaStats::default());
                    // Bounded backpressure: never accumulate minutes of media
                    // while a viewer's network stops draining the socket.
                    let (feed_tx, feed_rx) = mpsc::sync_channel(64);
                    let anchor = std::time::Instant::now();
                    let mut threads = Vec::new();
                    if video {
                        let (ready_tx, ready_rx) = mpsc::channel();
                        let thread_gate = Arc::clone(&gate);
                        let thread_stats = Arc::clone(&stats);
                        let thread_settings = synth_settings.clone();
                        let thread_feed = feed_tx.clone();
                        let thread_anchor = anchor;
                        let source = if capture_video {
                            "capture"
                        } else {
                            "synthetic"
                        };
                        threads.push(std::thread::spawn(move || {
                            if capture_video {
                                capture::run(
                                    capture_output,
                                    capture_fps,
                                    capture_bitrate_bps,
                                    thread_gate,
                                    thread_feed,
                                    thread_stats,
                                    ready_tx,
                                    thread_anchor,
                                )
                            } else {
                                synthetic::run(
                                    thread_settings,
                                    thread_gate,
                                    thread_feed,
                                    thread_stats,
                                    ready_tx,
                                    thread_anchor,
                                )
                            }
                        }));
                        match ready_rx.recv_timeout(std::time::Duration::from_secs(15)) {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                eprintln!("serve: {error}");
                                std::process::exit(2);
                            }
                            Err(_) => {
                                eprintln!("serve: {source} video did not report readiness");
                                std::process::exit(2);
                            }
                        }
                    }
                    if capture_audio {
                        let (ready_tx, ready_rx) = mpsc::channel();
                        let thread_gate = Arc::clone(&gate);
                        let thread_feed = feed_tx;
                        threads.push(std::thread::spawn(move || {
                            audio::run(thread_gate, thread_feed, ready_tx, anchor)
                        }));
                        match ready_rx.recv_timeout(std::time::Duration::from_secs(15)) {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                eprintln!("serve: {error}");
                                std::process::exit(2);
                            }
                            Err(_) => {
                                eprintln!("serve: capture audio did not report readiness");
                                std::process::exit(2);
                            }
                        }
                    }
                    (Some(gate), Some(feed_rx), Some(stats), threads)
                } else {
                    (None, None, None, Vec::new())
                };
                let result = match (gate, feed_rx, stats) {
                    (Some(gate), Some(feed_rx), Some(stats)) => {
                        server.serve_one_media(gate, feed_rx, stats)
                    }
                    _ => server.serve_one(),
                };
                for thread in media_threads {
                    let _ = thread.join();
                }
                match result {
                    Ok(outcome) => {
                        served += 1;
                        idle_since = std::time::Instant::now();
                        println!(
                            "session ended={} control={} media_bytes={} resize_acks={} keyframes={} video_frames={} video_bytes={} video_keyframes={} audio_frames={} audio_bytes={} input_events={} input_dropped={}",
                            outcome.ended,
                            outcome.control_frames,
                            outcome.media_bytes,
                            outcome.resize_acks,
                            outcome.keyframes_forwarded,
                            outcome.video_frames_sent,
                            outcome.video_bytes_sent,
                            outcome.video_keyframes_sent,
                            outcome.audio_frames_sent,
                            outcome.audio_bytes_sent,
                            outcome.input_events,
                            outcome.input_dropped,
                        );
                    }
                    Err(error) => {
                        eprintln!("serve: {error}");
                        std::process::exit(1);
                    }
                }
            }
            println!("serve exited after {served} sessions");
        }
        Some("connect-test") => {
            let server = flag_value(&args, "--server").unwrap_or_else(|| {
                eprintln!("connect-test: --server ADDR is required");
                usage(2);
            });
            let workspace_uid = flag_value(&args, "--workspace-uid").unwrap_or_else(|| {
                eprintln!("connect-test: --workspace-uid is required");
                usage(2);
            });
            let workspace_generation =
                flag_value(&args, "--workspace-generation").unwrap_or_else(|| {
                    eprintln!("connect-test: --workspace-generation is required");
                    usage(2);
                });
            // Media phase (optional): capture stream bytes after admission.
            // Absent by default: pure control exchange, exactly as before.
            let media_seconds: u64 = flag_value(&args, "--media-seconds")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let print_outcome = |outcome: &kw_transport::ClientOutcome| {
                println!(
                    "admitted={} resize_paired={} resize_reason={} server_hello={} media_frames={} media_bytes={}",
                    outcome.admitted,
                    outcome.resize_paired,
                    outcome.resize_reason,
                    outcome.server_hello_ok,
                    outcome.media_frames,
                    outcome.media_bytes,
                );
            };
            if media_seconds == 0 {
                match kw_transport::client::run(&server, &workspace_uid, &workspace_generation) {
                    Ok(outcome) => {
                        print_outcome(&outcome);
                        if !(outcome.admitted && outcome.resize_paired && outcome.server_hello_ok) {
                            std::process::exit(1);
                        }
                    }
                    Err(error) => {
                        eprintln!("connect-test: {error}");
                        std::process::exit(1);
                    }
                }
            } else {
                let capture = kw_transport::client::MediaCapture {
                    seconds: media_seconds,
                    save_video: flag_value(&args, "--save-video"),
                    save_audio: flag_value(&args, "--save-audio"),
                };
                match kw_transport::client::run_with_media(
                    &server,
                    &workspace_uid,
                    &workspace_generation,
                    &capture,
                ) {
                    Ok(outcome) => {
                        print_outcome(&outcome);
                        if !(outcome.admitted
                            && outcome.resize_paired
                            && outcome.server_hello_ok
                            && outcome.media_frames > 0)
                        {
                            eprintln!("connect-test: no media flowed");
                            std::process::exit(1);
                        }
                    }
                    Err(error) => {
                        eprintln!("connect-test: {error}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Some("audio-check") => {
            // Decode a framed Opus capture (u32be len + packet records, as
            // written by connect-test --save-audio) and report what actually
            // decodes: packet count, decoded samples, signal energy. An
            // all-silent capture decodes cleanly with ~zero energy — silence
            // is a valid outcome, undecodable bytes are not.
            let file = flag_value(&args, "--file").unwrap_or_else(|| {
                eprintln!("audio-check: --file PATH is required");
                usage(2);
            });
            let raw = std::fs::read(&file).unwrap_or_else(|error| {
                eprintln!("audio-check: cannot read {file}: {error}");
                std::process::exit(1);
            });
            let mut packets = Vec::new();
            let mut cursor = 0usize;
            while cursor + 4 <= raw.len() {
                let length = u32::from_be_bytes([
                    raw[cursor],
                    raw[cursor + 1],
                    raw[cursor + 2],
                    raw[cursor + 3],
                ]) as usize;
                cursor += 4;
                if length == 0 || cursor + length > raw.len() {
                    eprintln!("audio-check: truncated record at offset {}", cursor - 4);
                    std::process::exit(1);
                }
                packets.push(raw[cursor..cursor + length].to_vec());
                cursor += length;
            }
            if packets.is_empty() {
                eprintln!("audio-check: no packets in {file}");
                std::process::exit(1);
            }
            let mut decoder = kw_audio::opus::Decoder::new().unwrap_or_else(|error| {
                eprintln!("audio-check: decoder unavailable: {error}");
                std::process::exit(1);
            });
            let mut decoded_frames = 0u64;
            let mut decoded_samples = 0u64;
            let mut energy = 0f64;
            for packet in &packets {
                let mut pcm =
                    vec![0f32; kw_audio::opus::FRAME_SAMPLES * kw_audio::opus::CHANNELS * 2];
                match decoder.decode_into(packet, &mut pcm) {
                    Ok(samples) if samples > 0 => {
                        decoded_frames += 1;
                        decoded_samples += samples as u64;
                        for sample in pcm.iter().take(samples * kw_audio::opus::CHANNELS) {
                            energy += (*sample as f64) * (*sample as f64);
                        }
                    }
                    _ => {
                        eprintln!("audio-check: undecodable packet ({} bytes)", packet.len());
                        std::process::exit(1);
                    }
                }
            }
            let rms =
                (energy / (decoded_samples.max(1) * kw_audio::opus::CHANNELS as u64) as f64).sqrt();
            println!(
                "packets={} decoded_frames={} decoded_samples={} rms={:.6}",
                packets.len(),
                decoded_frames,
                decoded_samples,
                rms
            );
        }
        Some("encode-test") => {
            // Synthetic NV12 gradient through the real software encoder.
            // Proves the media pipeline without capture hardware or a session.
            let settings = kw_encode::Settings {
                width: flag_value(&args, "--width")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(320),
                height: flag_value(&args, "--height")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(240),
                fps: 30,
                bitrate_bps: flag_value(&args, "--bitrate-bps")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(2_000_000),
                max_keyframe_spacing: 30,
            };
            let frames: u32 = flag_value(&args, "--frames")
                .and_then(|value| value.parse().ok())
                .unwrap_or(30);
            let (width, height) = (settings.width as usize, settings.height as usize);
            let mut input = Vec::with_capacity(frames as usize);
            for index in 0..frames {
                let mut frame = vec![128u8; width * height * 3 / 2];
                for y in 0..height {
                    for x in 0..width {
                        frame[y * width + x] = (x + y + index as usize) as u8;
                    }
                }
                input.push(frame);
            }
            match kw_encode::encode_nv12(&settings, &input) {
                Ok(chunks) => {
                    let total: usize = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
                    let keyframes = chunks.iter().filter(|chunk| chunk.keyframe).count();
                    let first_types: Vec<u8> = chunks
                        .iter()
                        .flat_map(|chunk| chunk.nal_types.clone())
                        .take(8)
                        .collect();
                    println!(
                        "chunks={n} bytes={total} keyframes={keyframes} first_nals={first_types:?}",
                        n = chunks.len()
                    );
                    if !(first_types.contains(&7)
                        && first_types.contains(&8)
                        && keyframes > 0
                        && total > 1024)
                    {
                        eprintln!("encode-test: output missing SPS/PPS/IDR or trivial");
                        std::process::exit(1);
                    }
                }
                Err(error) => {
                    eprintln!("encode-test: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("audio-test") => {
            // Loopback capture trial plus Opus self-check. Silence is an
            // honest outcome (nothing plays); a missing endpoint is
            // environmental unless --require-endpoint is given. Only backend
            // failure exits nonzero.
            let seconds: u64 = flag_value(&args, "--seconds")
                .and_then(|value| value.parse().ok())
                .unwrap_or(2);
            let require = args.iter().any(|arg| arg == "--require-endpoint");
            match kw_audio::capture_loopback(seconds) {
                Ok(capture) => {
                    println!(
                        "rate={} channels={} bits={} packets={} frames={} silent={}",
                        capture.mix_rate,
                        capture.mix_channels,
                        capture.mix_bits,
                        capture.packets,
                        capture.frames,
                        capture.silent
                    );
                }
                Err(kw_audio::Error::NoEndpoint) if !require => {
                    println!("no active render endpoint (environment)");
                }
                Err(error) => {
                    eprintln!("audio-test: {error}");
                    std::process::exit(1);
                }
            }
            // Opus self-check needs no hardware: silence + tone round-trip.
            let mut encoder = kw_audio::opus::Encoder::new().unwrap_or_else(|error| {
                eprintln!("audio-test: {error}");
                std::process::exit(1);
            });
            let mut decoder = kw_audio::opus::Decoder::new().unwrap_or_else(|error| {
                eprintln!("audio-test: {error}");
                std::process::exit(1);
            });
            let mut opus_bytes = 0usize;
            for index in 0..5u32 {
                let mut pcm =
                    vec![0.0f32; kw_audio::opus::FRAME_SAMPLES * kw_audio::opus::CHANNELS];
                if index > 0 {
                    for (i, sample) in pcm.iter_mut().enumerate() {
                        let t = (i / kw_audio::opus::CHANNELS) as f32;
                        *sample = 0.5 * (2.0 * std::f32::consts::PI * 440.0 * t / 48_000.0).sin();
                    }
                }
                let packet = encoder.encode_frame(&pcm).unwrap_or_else(|error| {
                    eprintln!("audio-test: {error}");
                    std::process::exit(1);
                });
                let mut back =
                    vec![0.0f32; kw_audio::opus::FRAME_SAMPLES * kw_audio::opus::CHANNELS];
                decoder
                    .decode_into(&packet, &mut back)
                    .unwrap_or_else(|error| {
                        eprintln!("audio-test: {error}");
                        std::process::exit(1);
                    });
                opus_bytes += packet.len();
            }
            println!("opus=selfcheck-ok bytes={opus_bytes}");
        }
        _ => usage(2),
    }
}
