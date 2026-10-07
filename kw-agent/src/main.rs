//! Workspace agent service entry point (scaffold).
//!
//! Platform capture/input/display/audio backends are **P0-gated**: only
//! capability inventory exists. This binary performs no capture, networking,
//! input injection, mode changes or privileged operations.

mod platform;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
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
        _ => {
            eprintln!(
                "kw-agent {} ({})",
                env!("CARGO_PKG_VERSION"),
                platform::describe()
            );
            eprintln!(
                "backends are P0-gated: no capture, network, input or display changes in this build"
            );
            eprintln!("usage: kw-agent [--version|--platform|--hello]");
            std::process::exit(2);
        }
    }
}
