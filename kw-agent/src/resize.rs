//! Bounded bridge from the control thread to the capture/encoder owner.
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

pub struct Request {
    pub width: u32,
    pub height: u32,
    pub deadline: Instant,
    pub reply: mpsc::Sender<Result<serde_json::Value, String>>,
}

#[derive(Default)]
pub struct Bridge(pub Mutex<Option<mpsc::SyncSender<Request>>>);

/// Seconds budgeted for a mode change plus encoder rebuild plus delivered
/// IDR, scaled by frame area. 8s covers 1080p and below (observed ~3s
/// round trips); 4K software-encoder warmup measured 6.6s and timed out
/// twice at 8s, so larger frames earn two extra seconds per megapixel
/// over 1080p, capped at 30s.
fn deadline_secs(width: u32, height: u32) -> u64 {
    const BASE_SECS: u64 = 8;
    const BASE_PIXELS: u64 = 1920 * 1080;
    const CAP_SECS: u64 = 30;
    let pixels = width as u64 * height as u64;
    if pixels <= BASE_PIXELS {
        return BASE_SECS;
    }
    (BASE_SECS + (pixels - BASE_PIXELS) / 1_000_000 * 2).min(CAP_SECS)
}

impl kw_transport::Resize for Bridge {
    fn resize(&self, width: u32, height: u32) -> Result<serde_json::Value, String> {
        let (reply, result) = mpsc::channel();
        // The reply wait must outlive the capture deadline it reports
        // through, or the control thread times out first and masks the
        // real outcome.
        let budget = Duration::from_secs(deadline_secs(width, height));
        self.0
            .lock()
            .map_err(|_| "display-bridge-lock")?
            .as_ref()
            .ok_or("display-capture-unavailable")?
            .try_send(Request {
                width,
                height,
                reply,
                deadline: Instant::now() + budget,
            })
            .map_err(|error| match error {
                // The capture thread owns the receiver: a disconnect means
                // video already ended, not a momentary queue-full.
                mpsc::TrySendError::Full(_) => "display-resize-busy",
                mpsc::TrySendError::Disconnected(_) => "display-capture-unavailable",
            })?;
        result
            .recv_timeout(budget + Duration::from_secs(2))
            .map_err(|_| "display-resize-timeout".to_owned())?
    }
}

#[cfg(test)]
mod tests {
    use super::deadline_secs;

    #[test]
    fn deadline_covers_1080p_and_below() {
        assert_eq!(deadline_secs(800, 600), 8);
        assert_eq!(deadline_secs(1280, 800), 8);
        assert_eq!(deadline_secs(1920, 1080), 8);
    }

    #[test]
    fn deadline_scales_with_area_and_caps() {
        // 3840x2136 ~= 8.2MP: 8 + 2*(8.2-2.07) ~= 20s.
        assert_eq!(deadline_secs(3840, 2136), 20);
        assert_eq!(deadline_secs(8192, 8192), 30);
    }
}
