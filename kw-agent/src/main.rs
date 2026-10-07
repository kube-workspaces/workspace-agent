//! Workspace agent service entry point (v0.1).
//!
//! Platform capture/input/display/audio backends are **P0-gated**: only
//! capability inventory, enrollment and the heartbeat daemon exist. This
//! binary performs no capture, networking, input injection, mode changes or
//! privileged operations.

mod daemon;
mod platform;

fn usage(code: i32) -> ! {
    eprintln!(
        "kw-agent {} ({})",
        env!("CARGO_PKG_VERSION"),
        platform::describe()
    );
    eprintln!("usage:");
    eprintln!("  kw-agent --version|--platform|--hello");
    eprintln!("  kw-agent daemon --workspace-uid UID --workspace-generation GEN [--data-dir DIR] [--interval-secs N] [--beats N]");
    eprintln!("  kw-agent serve --workspace-uid UID --workspace-generation GEN [--port PORT] [--max-sessions N] [--max-idle-secs N]");
    eprintln!(
        "  kw-agent connect-test --server ADDR --workspace-uid UID --workspace-generation GEN"
    );
    eprintln!("  kw-agent encode-test [--width W] [--height H] [--frames N] [--bitrate-bps B]");
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
            println!("kw-agent {}", env!("CARGO_PKG_VERSION"));
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
            let server = kw_transport::Server::bind(
                ("127.0.0.1", port),
                workspace_uid,
                workspace_generation,
            )
            .unwrap_or_else(|error| {
                eprintln!("serve: bind failed: {error}");
                std::process::exit(1);
            });
            let address = server.local_address().unwrap_or_else(|error| {
                eprintln!("serve: no local address: {error}");
                std::process::exit(1);
            });
            println!("listening {address}");
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
                match server.serve_one() {
                    Ok(outcome) => {
                        served += 1;
                        idle_since = std::time::Instant::now();
                        println!(
                            "session ended={} control={} media_bytes={} resize_acks={} keyframes={}",
                            outcome.ended,
                            outcome.control_frames,
                            outcome.media_bytes,
                            outcome.resize_acks,
                            outcome.keyframes_forwarded
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
            match kw_transport::client::run(&server, &workspace_uid, &workspace_generation) {
                Ok(outcome) => {
                    println!(
                        "admitted={} resize_paired={} resize_reason={} server_hello={}",
                        outcome.admitted,
                        outcome.resize_paired,
                        outcome.resize_reason,
                        outcome.server_hello_ok
                    );
                    if !(outcome.admitted && outcome.resize_paired && outcome.server_hello_ok) {
                        std::process::exit(1);
                    }
                }
                Err(error) => {
                    eprintln!("connect-test: {error}");
                    std::process::exit(1);
                }
            }
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
        _ => usage(2),
    }
}
