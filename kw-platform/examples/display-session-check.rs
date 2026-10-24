//! Live Windows topology lifecycle check. Temporarily isolates the selected IDD
//! and restores it; no pixels, credentials or machine identities are saved.
//! Run only in an operator-approved, unlocked interactive console session.
use std::time::{Duration, Instant};

fn attached() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let inventory = kw_platform::inventory()?;
    let mut names: Vec<_> = inventory
        .adapters
        .iter()
        .flat_map(|a| &a.outputs)
        .filter(|output| output.attached)
        .map(|output| output.name.clone())
        .collect();
    names.sort();
    Ok(names)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let before = attached()?;
    if before.len() < 2 {
        return Err("requires an attached console and virtual output".into());
    }
    let selected = kw_platform::display::selected_name(0, None)?;
    for cycle in 1..=3 {
        let session = kw_platform::display::VirtualDisplaySession::begin(&selected)?;
        std::thread::sleep(Duration::from_millis(500));
        let isolated = attached()?;
        if isolated != [selected.clone()] {
            return Err(format!("isolation failed: {isolated:?}").into());
        }
        let captured = {
            let mut capture = kw_platform::capture::Duplicator::new_named(&selected)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut captured = false;
            while Instant::now() < deadline {
                if capture.capture(100)?.is_some() {
                    captured = true;
                    break;
                }
            }
            captured
        };
        if !captured {
            return Err("no captured frame after display isolation".into());
        }
        drop(session);
        std::thread::sleep(Duration::from_millis(500));
        let restored = attached()?;
        if restored != before {
            return Err(format!("restore failed: {restored:?} expected {before:?}").into());
        }
        println!("cycle {cycle}: isolation, capture and restoration passed");
    }
    // Simulate a process exit without RAII cleanup; managed startup recovery
    // must reattach the console without relying on an in-memory snapshot.
    let session = kw_platform::display::VirtualDisplaySession::begin(&selected)?;
    // Keep the guard alive solely for cleanup if the check fails; recovery
    // itself has no access to its saved paths, just as in a replacement worker.
    if !kw_platform::display::recover_console_topology()? {
        return Err("interrupted-worker recovery did not find detached console".into());
    }
    std::thread::sleep(Duration::from_millis(500));
    if attached()?.len() < 2 {
        return Err("interrupted-worker recovery left console detached".into());
    }
    println!("interrupted-worker topology recovery passed");
    drop(session);
    Ok(())
}
