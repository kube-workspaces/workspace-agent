//! Bounded real-session Linux acceptance diagnostic. Run as the logged-in
//! console user in a disposable GNOME guest; temporarily opens a test window,
//! changes clipboard/display and plays a known tone. No user pixels are saved.
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut desktop = Command::new("/usr/bin/python3")
        .args(["-u", "-c", include_str!("linux-test-desktop.py")])
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut output = BufReader::new(desktop.stdout.take().ok_or("desktop stdout missing")?);
        let mut line = String::new();
        output.read_line(&mut line)?;
        if line.trim() != "ready" {
            return Err("GTK desktop did not start".into());
        }
        let selected = kw_platform::display::selected_name(0, None)?;
        let mut capture = kw_platform::capture::Duplicator::new_named(&selected)?;
        let initial = capture.size();
        let mut input = kw_platform::input::Injector::for_output(Some(selected.clone()))?;
        // GNOME starts in the overview and can retain its first-login welcome
        // dialog. Activate the disposable test window through real user input;
        // Wayland correctly refuses clipboard access to background windows.
        input.key(0xff1b, true)?;
        input.key(0xff1b, false)?;
        std::thread::sleep(Duration::from_millis(200));
        input.key(0xffe9, true)?;
        input.key(0xff09, true)?;
        input.key(0xff09, false)?;
        input.key(0xffe9, false)?;
        std::thread::sleep(Duration::from_millis(300));
        input.pointer((initial.0 / 2) as i32, 70, 1)?;
        input.pointer((initial.0 / 2) as i32, 70, 0)?;
        std::thread::sleep(Duration::from_millis(150));
        for key in [b'k' as u32, b'w' as u32] {
            input.key(key, true)?;
            input.key(key, false)?;
        }
        kw_platform::clipboard::write_text("agent→GNOME λ")?;
        desktop
            .stdin
            .as_mut()
            .ok_or("desktop stdin missing")?
            .write_all(b"check\n")?;
        let mut hashes = HashSet::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(frame) = capture.capture(100)? {
                let mut hash = DefaultHasher::new();
                frame.nv12.hash(&mut hash);
                hashes.insert(hash.finish());
            }
        }
        if hashes.len() < 5 {
            return Err("animated desktop did not produce distinct captured frames".into());
        }
        line.clear();
        output.read_line(&mut line)?;
        let gtk: serde_json::Value = serde_json::from_str(&line)?;
        if gtk["text"] != "kw" || gtk["clipboard"] != "agent→GNOME λ" {
            return Err(format!("GTK input/clipboard check failed: {gtk}").into());
        }
        let clipboard_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if kw_platform::clipboard::read_text()?.as_deref() == Some("GNOME→agent λ") {
                break;
            }
            if Instant::now() >= clipboard_deadline {
                return Err("GNOME-to-agent clipboard check failed".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let modes = kw_platform::display::modes(0, Some(&selected));
        let mode = modes
            .iter()
            .find(|m| (m.width, m.height) != initial && m.width <= 1280 && m.height <= 800)
            .ok_or("no alternate guest display mode")?;
        let requested = kw_platform::display::Size {
            width: mode.width,
            height: mode.height,
        };
        let actual = kw_platform::display::resize_selected(0, Some(&selected), requested)?;
        if actual != requested {
            return Err("guest resize readback mismatch".into());
        }
        drop(capture);
        let capture_result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut resized = kw_platform::capture::Duplicator::new_named(&selected)?;
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if let Ok(Some(frame)) = resized.capture(100) {
                    if (frame.width, frame.height) == (actual.width, actual.height) {
                        return Ok(());
                    }
                }
            }
            #[cfg(target_os = "linux")]
            eprintln!(
                "resized capture metadata: {}",
                kw_platform::linux::call(serde_json::json!({"op":"frame", "timeoutMs":200}), &[])?
                    .0
            );
            Err("capture did not follow the guest mode change".into())
        })();
        let restored = kw_platform::display::resize_selected(
            0,
            Some(&selected),
            kw_platform::display::Size {
                width: initial.0,
                height: initial.1,
            },
        );
        capture_result?;
        restored?;
        let tap = kw_audio::tap::LoopbackTap::start()?;
        let mut samples = 0;
        let mut energy = 0f64;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some((format, bytes, _)) = tap.read(200)? {
                for value in kw_audio::tap::pcm_to_f32(&bytes, format)? {
                    energy += (value as f64).powi(2);
                    samples += 1;
                }
            }
        }
        let rms = (energy / samples.max(1) as f64).sqrt();
        if samples < 48000 || rms < 0.01 {
            return Err("loopback did not capture the known desktop tone".into());
        }
        println!(
            "{}",
            serde_json::json!({"distinctFrames":hashes.len(), "input":"passed", "clipboard":"bidirectional Unicode passed",
            "resize":{"width":actual.width,"height":actual.height}, "audioSamples":samples,"audioRms":rms})
        );
        Ok(())
    })();
    let _ = desktop.kill();
    let _ = desktop.wait();
    result
}
