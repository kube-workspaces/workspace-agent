//! `kw-agent-v1` wire protocol types and validation.
//!
//! Mirrors `docs/protocol/kw-agent-v1.md`. The JSON conformance vectors in
//! `protocol/v1/vectors/` are the shared fixtures: [`tests::vectors`] parses
//! every one of them through these types, so spec, fixtures and code cannot
//! drift apart silently.
//!
//! Out of scope here: transport, capture, encoding, guest identity storage.
//! Those live behind the P0 decision record.

use serde::{Deserialize, Serialize};

/// Wire protocol identifier. Never reuse another product's advert.
pub const PROTOCOL: &str = "kw-agent-v1";
/// Currently accepted protocol version. Unknown versions are rejected.
pub const PROTOCOL_VERSION: u32 = 1;

/// Message channel. Media and control are separately bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Media,
    Control,
}

/// Control message types (spec section "Control messages").
pub const CONTROL_TYPES: &[&str] = &[
    "hello",
    "capabilities",
    "attach",
    "keyframeRequest",
    "resizeRequest",
    "resizeAck",
    "clipboardGet",
    "clipboardSet",
    "clipboardResult",
    "displayOwnership",
    "telemetry",
    "bye",
];

/// Media frame types.
pub const MEDIA_TYPES: &[&str] = &["video", "audio"];

/// Message envelope. Every frame on either channel carries this.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Envelope {
    pub protocol: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub generation: u64,
    pub sequence: u64,
    #[serde(rename = "sentAtNs")]
    pub sent_at_ns: u64,
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: String,
    pub payload: serde_json::Value,
}

/// Short-lived attach ticket bound to one session claim.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ticket {
    #[serde(rename = "workspaceUid")]
    pub workspace_uid: String,
    #[serde(rename = "workspaceGeneration")]
    pub workspace_generation: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub participant: String,
    pub role: String,
    #[serde(rename = "controlEpoch")]
    pub control_epoch: u64,
    pub audience: String,
    #[serde(rename = "expiresAtNs")]
    pub expires_at_ns: u64,
}

/// What the validator rejected, without leaking secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Wrong protocol name or unsupported version.
    Protocol,
    /// Unknown message type for the channel.
    UnknownType,
    /// `(generation, sequence)` already seen or regressed.
    Replay,
    /// Ticket expired, wrong audience/session, or demoted epoch.
    Ticket,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::Protocol => write!(f, "unsupported protocol or version"),
            Reject::UnknownType => write!(f, "unknown message type for channel"),
            Reject::Replay => write!(f, "replayed or regressed sequence"),
            Reject::Ticket => write!(f, "ticket rejected"),
        }
    }
}

impl std::error::Error for Reject {}

/// Check envelope shape: protocol, version, channel/type pairing.
pub fn check_envelope(message: &Envelope) -> Result<(), Reject> {
    if message.protocol != PROTOCOL || message.protocol_version != PROTOCOL_VERSION {
        return Err(Reject::Protocol);
    }
    let known = match message.channel {
        Channel::Control => CONTROL_TYPES.contains(&message.message_type.as_str()),
        Channel::Media => MEDIA_TYPES.contains(&message.message_type.as_str()),
    };
    if !known {
        return Err(Reject::UnknownType);
    }
    Ok(())
}

/// Per-channel ordering fence. Accepts strictly increasing
/// `(generation, clock)` pairs; anything else is a replay or regression.
///
/// Clocks are sender-monotonic nanoseconds; generations reset only on
/// re-enrolment. Receivers drop and count rejections — they never stall.
#[derive(Debug, Default)]
pub struct ChannelFence {
    last: Option<(u64, u64)>,
    /// Rejected frames so far (telemetry counter, not a log).
    pub rejected: u64,
}

impl ChannelFence {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one frame. Updates the fence on success.
    pub fn admit(&mut self, generation: u64, sent_at_ns: u64) -> Result<(), Reject> {
        if let Some((last_gen, last_clock)) = self.last {
            if (generation, sent_at_ns) <= (last_gen, last_clock) {
                self.rejected += 1;
                return Err(Reject::Replay);
            }
        }
        self.last = Some((generation, sent_at_ns));
        Ok(())
    }
}

/// Scope an attach ticket is admitted into.
pub struct Scope<'a> {
    pub workspace_uid: &'a str,
    pub session_id: &'a str,
    pub audience: &'a str,
    /// Minimum accepted control epoch (demotions fence old tickets).
    pub min_control_epoch: u64,
}

/// Admit an attach ticket: binding, audience, epoch fence and expiry.
///
/// `now_ns` uses the verifier's clock. Expiry comparison is `<=`: a ticket
/// expiring exactly now is already expired.
pub fn admit_ticket(ticket: &Ticket, scope: &Scope<'_>, now_ns: u64) -> Result<(), Reject> {
    if ticket.workspace_uid != scope.workspace_uid
        || ticket.session_id != scope.session_id
        || ticket.audience != scope.audience
        || ticket.control_epoch < scope.min_control_epoch
        || ticket.expires_at_ns <= now_ns
    {
        return Err(Reject::Ticket);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
