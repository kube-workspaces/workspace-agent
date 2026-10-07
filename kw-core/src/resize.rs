//! Resize coalescing: the 500ms debounce from the resize contract.
//!
//! Window/client resize, maximize, fullscreen and monitor-scale events are
//! coalesced: only the newest desired mode is sent, 500ms after the last
//! event. The agent answers with requested/actual dimensions or a reason.

/// Debounce window in milliseconds (spec contract).
pub const DEBOUNCE_MS: u64 = 500;

/// A desired display mode with a monotonic identity. Only the newest applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResizeRequest {
    /// Monotonic per session; the agent applies the highest seen.
    pub request_id: u64,
    pub width: u32,
    pub height: u32,
}

/// Coalesces rapid resize events into debounced requests.
#[derive(Debug, Default)]
pub struct ResizePolicy {
    next_id: u64,
    pending: Option<(u32, u32)>,
    last_event_ms: u64,
    /// Last emitted request (for ACK matching in tests).
    pub last_emitted: Option<ResizeRequest>,
}

impl ResizePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a desired size at `now_ms`. Returns `Some` only when a request
    /// should be emitted — i.e. this call is at least [`DEBOUNCE_MS`] after
    /// the previous *emitted* request and the size differs from it.
    ///
    /// Callers invoke [`ResizePolicy::flush`] once the line has been quiet
    /// for the debounce window; `offer` itself never emits mid-burst.
    pub fn offer(&mut self, width: u32, height: u32, now_ms: u64) -> Option<ResizeRequest> {
        self.pending = Some((width, height));
        self.last_event_ms = now_ms;
        None
    }

    /// Emit the newest pending mode if the line has been quiet for the
    /// debounce window and it differs from the last emitted request.
    pub fn flush(&mut self, now_ms: u64) -> Option<ResizeRequest> {
        let (width, height) = self.pending?;
        if now_ms.saturating_sub(self.last_event_ms) < DEBOUNCE_MS {
            return None;
        }
        if self
            .last_emitted
            .as_ref()
            .is_some_and(|last| last.width == width && last.height == height)
        {
            self.pending = None;
            return None;
        }
        self.next_id += 1;
        let request = ResizeRequest {
            request_id: self.next_id,
            width,
            height,
        };
        self.last_emitted = Some(request.clone());
        self.pending = None;
        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_burst_into_newest() {
        let mut policy = ResizePolicy::new();
        assert_eq!(policy.offer(1280, 720, 0), None);
        assert_eq!(policy.offer(1600, 900, 100), None);
        assert_eq!(policy.offer(1920, 1080, 200), None);
        // Still inside the window: nothing emitted.
        assert_eq!(policy.flush(400), None);
        // Quiet for 500ms: newest wins with the first id.
        let request = policy.flush(700).expect("emits after debounce");
        assert_eq!(
            request,
            ResizeRequest {
                request_id: 1,
                width: 1920,
                height: 1080
            }
        );
        // Nothing pending afterwards.
        assert_eq!(policy.flush(2000), None);
    }

    #[test]
    fn suppresses_unchanged_modes() {
        let mut policy = ResizePolicy::new();
        policy.offer(1920, 1080, 0);
        assert!(policy.flush(600).is_some());
        policy.offer(1920, 1080, 1000);
        assert_eq!(policy.flush(1600), None);
    }

    #[test]
    fn ids_increase_monotonically() {
        let mut policy = ResizePolicy::new();
        policy.offer(800, 600, 0);
        let first = policy.flush(600).unwrap();
        policy.offer(1024, 768, 700);
        let second = policy.flush(1300).unwrap();
        assert!(second.request_id > first.request_id);
    }
}
