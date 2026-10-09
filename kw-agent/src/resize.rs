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

impl kw_transport::Resize for Bridge {
    fn resize(&self, width: u32, height: u32) -> Result<serde_json::Value, String> {
        let (reply, result) = mpsc::channel();
        self.0
            .lock()
            .map_err(|_| "display-bridge-lock")?
            .as_ref()
            .ok_or("display-capture-unavailable")?
            .try_send(Request {
                width,
                height,
                reply,
                deadline: Instant::now() + Duration::from_secs(8),
            })
            .map_err(|error| match error {
                // The capture thread owns the receiver: a disconnect means
                // video already ended, not a momentary queue-full.
                mpsc::TrySendError::Full(_) => "display-resize-busy",
                mpsc::TrySendError::Disconnected(_) => "display-capture-unavailable",
            })?;
        result
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "display-resize-timeout".to_owned())?
    }
}
