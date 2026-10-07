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
        _ => usage(2),
    }
}
