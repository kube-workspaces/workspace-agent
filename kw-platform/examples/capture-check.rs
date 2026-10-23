//! Read-only console-session output-selection/capture diagnostic. No pixels saved.
//! Run on Windows: capture-check.exe [DISPLAY_NAME]
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() > 1 {
        return Err("usage: capture-check.exe [DISPLAY_NAME]".into());
    }
    let requested = args.first().map(String::as_str);
    let selected = kw_platform::display::selected_name(0, requested)?;
    let modes = kw_platform::display::modes(0, requested);
    let mut capture = kw_platform::capture::Duplicator::new_named(&selected)?;
    let size = capture.size();
    let started = Instant::now();
    let mut frames = 0u64;
    while started.elapsed() < Duration::from_secs(5) {
        if capture.capture(100)?.is_some() {
            frames += 1;
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "schemaVersion": 1,
            "selectedOutput": selected,
            "modeCount": modes.len(),
            "captureWidth": size.0,
            "captureHeight": size.1,
            "frames": frames,
            "inventory": kw_platform::inventory()?,
            "limitations": [
                "A static captured frame does not prove animated rendering or streaming",
                "Hardware encoding is not tested; software encoder names are inventory only"
            ]
        })
    );
    if frames == 0 {
        return Err("no captured frames during five-second diagnostic".into());
    }
    Ok(())
}
