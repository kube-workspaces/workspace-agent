//! Workspace agent service entry point (scaffold).
//!
//! Platform capture/input/display/audio backends are **P0-gated**: they do
//! not exist yet, and this binary performs no capture, networking, input
//! injection, mode changes or privileged operations. It reports its build
//! identity and the active platform stub so installers and CI can smoke-test
//! packaging long before backends land.

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
        _ => {
            eprintln!(
                "kw-agent {} ({})",
                env!("CARGO_PKG_VERSION"),
                platform::describe()
            );
            eprintln!("backends are P0-gated: no capture, network, input or display changes in this build");
            eprintln!("usage: kw-agent [--version|--platform]");
            std::process::exit(2);
        }
    }
}
