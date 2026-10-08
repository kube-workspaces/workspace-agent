//! TCP transport for the agent (v0.2): framing, ticket-gated sessions.
//!
//! One TCP connection carries one socket group: length-prefixed JSON control
//! frames (`u32` big-endian length, 1MiB cap) multiplexed with binary media
//! frames (1-byte kind + `u32` length + payload, 8MiB cap). The server speaks
//! first (`hello`), then admits exactly one exclusive controller via a
//! validated ticket. Media ingest is accepted, counted and bounded — there
//! is no encoder yet, so video payloads are currently rejected with a reason
//! rather than silently swallowed.
//!
//! Security scope: plain TCP. TLS termination and upstream agent-trust belong
//! to the proxy hop (P2); this listener binds the guest loopback or the
//! pod network, never the public internet. Tickets are still fully validated.

pub mod client;
pub mod frame;
pub mod server;

pub use client::ClientOutcome;
pub use frame::{MediaKind, MAX_CONTROL_BYTES, MAX_MEDIA_BYTES};
pub use server::{
    Clipboard, Input, MediaGate, MediaPacket, MediaStats, Server, ServerEvent, SessionOutcome,
};
