//! Ordered session handshake: hello → attach → admitted.
//!
//! Enforces message order, per-channel fences, resize request/ACK pairing
//! and keyframe-request coalescing. No transport, no clock source, no OS:
//! callers supply messages and nanosecond timestamps, making every rule a
//! unit test. Malformed input is rejected with [`Reject`], never silently
//! reinterpreted.

use kw_protocol::{check_envelope, Channel, Envelope, Reject, Ticket};

use crate::Session;

/// Outcome of a resize ACK: paired with a pending request or stale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ack {
    /// ACK matches the pending request id. `complete` is true only when the
    /// agent also reported codec reconfig + fresh IDR.
    Paired { complete: bool },
    /// No matching pending request (duplicate or unsolicited). Not an error
    /// by itself — the sender may have missed our earlier ACK.
    Stale,
}

/// One media/control socket group's handshake state.
#[derive(Debug)]
pub struct Handshake {
    session: Session,
    helloed: bool,
    admitted: bool,
    media_fence: kw_protocol::ChannelFence,
    control_fence: kw_protocol::ChannelFence,
    pending_resize: Option<String>,
    keyframe_pending: bool,
}

impl Handshake {
    pub fn new(session_id: String, generation: u64) -> Self {
        Self {
            session: Session::new(session_id, generation),
            helloed: false,
            admitted: false,
            media_fence: kw_protocol::ChannelFence::new(),
            control_fence: kw_protocol::ChannelFence::new(),
            pending_resize: None,
            keyframe_pending: false,
        }
    }

    fn control(&mut self, message: &Envelope) -> Result<(), Reject> {
        check_envelope(message)?;
        if message.channel != Channel::Control {
            return Err(Reject::UnknownType);
        }
        self.control_fence
            .admit(message.generation, message.sent_at_ns)?;
        Ok(())
    }

    /// First message on a new socket group: capability advertisement.
    pub fn hello(&mut self, message: &Envelope) -> Result<(), Reject> {
        if self.helloed {
            return Err(Reject::Replay);
        }
        if message.message_type != "hello" {
            return Err(Reject::UnknownType);
        }
        self.control(message)?;
        self.helloed = true;
        Ok(())
    }

    /// Admit the controller after hello. Binds seat, role, epoch, expiry.
    pub fn attach(
        &mut self,
        message: &Envelope,
        ticket: &Ticket,
        workspace_uid: &str,
        now_ns: u64,
    ) -> Result<crate::Role, Reject> {
        if !self.helloed {
            return Err(Reject::UnknownType);
        }
        if message.message_type != "attach" {
            return Err(Reject::UnknownType);
        }
        self.control(message)?;
        let role = self.session.attach(ticket, workspace_uid, now_ns)?;
        self.admitted = true;
        Ok(role)
    }

    /// A resize request after admission. Records the wire request id as the
    /// single pending mode; only the newest applies (see [`crate::ResizePolicy`]).
    pub fn resize_request(&mut self, message: &Envelope) -> Result<String, Reject> {
        if !self.admitted {
            return Err(Reject::UnknownType);
        }
        if message.message_type != "resizeRequest" {
            return Err(Reject::UnknownType);
        }
        self.control(message)?;
        let id = message.payload["requestId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or(Reject::UnknownType)?
            .to_owned();
        self.pending_resize = Some(id.clone());
        Ok(id)
    }

    /// Pair an ACK against the pending request. Returns [`Ack::Stale`] for
    /// duplicates/unsolicited ACKs instead of failing the session.
    pub fn resize_ack(&mut self, message: &Envelope) -> Result<Ack, Reject> {
        if !self.admitted {
            return Err(Reject::UnknownType);
        }
        if message.message_type != "resizeAck" {
            return Err(Reject::UnknownType);
        }
        self.control(message)?;
        let id = message.payload["requestId"].as_str().unwrap_or("");
        if self.pending_resize.as_deref() == Some(id) && !id.is_empty() {
            self.pending_resize = None;
            let complete =
                message.payload["codecReconfigured"] == true && message.payload["idrSent"] == true;
            Ok(Ack::Paired { complete })
        } else {
            Ok(Ack::Stale)
        }
    }

    /// Keyframe demand. Returns true when the encoder should be poked;
    /// repeated demands coalesce until [`Handshake::keyframe_sent`].
    pub fn keyframe_request(&mut self, message: &Envelope) -> Result<bool, Reject> {
        if !self.admitted {
            return Err(Reject::UnknownType);
        }
        if message.message_type != "keyframeRequest" {
            return Err(Reject::UnknownType);
        }
        self.control(message)?;
        if self.keyframe_pending {
            Ok(false)
        } else {
            self.keyframe_pending = true;
            Ok(true)
        }
    }

    /// The encoder emitted an IDR for the pending demand.
    pub fn keyframe_sent(&mut self) {
        self.keyframe_pending = false;
    }

    /// Fence a media frame (ordering only; GOP discipline is media-layer).
    pub fn media(&mut self, message: &Envelope) -> Result<(), Reject> {
        check_envelope(message)?;
        if message.channel != Channel::Media {
            return Err(Reject::UnknownType);
        }
        self.media_fence
            .admit(message.generation, message.sent_at_ns)?;
        Ok(())
    }

    /// Orderly teardown: release held input, forget pending state. The socket
    /// group must re-hello before any new attach.
    pub fn close(&mut self) {
        self.session.release();
        self.helloed = false;
        self.admitted = false;
        self.pending_resize = None;
        self.keyframe_pending = false;
    }

    pub fn admitted(&self) -> bool {
        self.admitted
    }

    pub fn holder(&self) -> Option<&str> {
        self.session.holder()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope(
        channel: &str,
        message_type: &str,
        sequence: u64,
        payload: serde_json::Value,
    ) -> Envelope {
        serde_json::from_value(json!({
            "protocol": "kw-agent-v1",
            "protocolVersion": 1,
            "sessionId": "sess",
            "generation": 7,
            "sequence": sequence,
            "sentAtNs": 1000 + sequence,
            "channel": channel,
            "type": message_type,
            "payload": payload,
        }))
        .expect("envelope")
    }

    fn ticket() -> Ticket {
        Ticket {
            workspace_uid: "ws".into(),
            workspace_generation: "gen".into(),
            session_id: "sess".into(),
            participant: "c1".into(),
            role: "controller".into(),
            control_epoch: 1,
            audience: "workspace-agent".into(),
            expires_at_ns: 9000,
        }
    }

    fn admitted() -> Handshake {
        let mut handshake = Handshake::new("sess".into(), 7);
        handshake
            .hello(&envelope("control", "hello", 1, json!({})))
            .expect("hello");
        let attach = envelope("control", "attach", 2, json!({}));
        handshake
            .attach(&attach, &ticket(), "ws", 100)
            .expect("attach");
        handshake
    }

    #[test]
    fn happy_path_pairs_resize_and_coalesces_keyframes() {
        let mut handshake = admitted();
        let id = handshake
            .resize_request(&envelope(
                "control",
                "resizeRequest",
                3,
                json!({"requestId": "r-1"}),
            ))
            .expect("request");
        assert_eq!(id, "r-1");
        // A newer request supersedes the older one.
        handshake
            .resize_request(&envelope(
                "control",
                "resizeRequest",
                4,
                json!({"requestId": "r-2"}),
            ))
            .expect("request");
        assert_eq!(
            handshake.resize_ack(&envelope(
                "control",
                "resizeAck",
                5,
                json!({"requestId": "r-1", "codecReconfigured": true, "idrSent": true})
            )),
            Ok(Ack::Stale)
        );
        assert_eq!(
            handshake.resize_ack(&envelope(
                "control",
                "resizeAck",
                6,
                json!({"requestId": "r-2", "codecReconfigured": true, "idrSent": true})
            )),
            Ok(Ack::Paired { complete: true })
        );
        // Incomplete reconfig still pairs, flagged incomplete.
        handshake
            .resize_request(&envelope(
                "control",
                "resizeRequest",
                7,
                json!({"requestId": "r-3"}),
            ))
            .expect("request");
        assert_eq!(
            handshake.resize_ack(&envelope(
                "control",
                "resizeAck",
                8,
                json!({"requestId": "r-3", "codecReconfigured": false, "idrSent": true})
            )),
            Ok(Ack::Paired { complete: false })
        );
        let key = envelope("control", "keyframeRequest", 9, json!({}));
        assert_eq!(handshake.keyframe_request(&key), Ok(true));
        let key2 = envelope("control", "keyframeRequest", 10, json!({}));
        assert_eq!(handshake.keyframe_request(&key2), Ok(false));
        handshake.keyframe_sent();
        let key3 = envelope("control", "keyframeRequest", 11, json!({}));
        assert_eq!(handshake.keyframe_request(&key3), Ok(true));
    }

    #[test]
    fn attach_before_hello_is_rejected() {
        let mut handshake = Handshake::new("sess".into(), 7);
        let attach = envelope("control", "attach", 1, json!({}));
        assert!(handshake.attach(&attach, &ticket(), "ws", 100).is_err());
        assert!(!handshake.admitted());
    }

    #[test]
    fn double_hello_is_replay() {
        let mut handshake = Handshake::new("sess".into(), 7);
        handshake
            .hello(&envelope("control", "hello", 1, json!({})))
            .expect("hello");
        assert_eq!(
            handshake.hello(&envelope("control", "hello", 2, json!({}))),
            Err(Reject::Replay)
        );
    }

    #[test]
    fn control_actions_require_admission() {
        let mut handshake = Handshake::new("sess".into(), 7);
        handshake
            .hello(&envelope("control", "hello", 1, json!({})))
            .expect("hello");
        let request = envelope("control", "resizeRequest", 2, json!({"requestId": "r-1"}));
        assert!(handshake.resize_request(&request).is_err());
        assert!(handshake
            .keyframe_request(&envelope("control", "keyframeRequest", 3, json!({})))
            .is_err());
    }

    #[test]
    fn close_releases_and_requires_fresh_hello() {
        let mut handshake = admitted();
        assert_eq!(handshake.holder(), Some("c1"));
        handshake.close();
        assert_eq!(handshake.holder(), None);
        let attach = envelope("control", "attach", 9, json!({}));
        assert!(handshake.attach(&attach, &ticket(), "ws", 100).is_err());
        handshake
            .hello(&envelope("control", "hello", 10, json!({})))
            .expect("re-hello");
        let attach = envelope("control", "attach", 11, json!({}));
        assert!(handshake.attach(&attach, &ticket(), "ws", 100).is_ok());
    }
}
