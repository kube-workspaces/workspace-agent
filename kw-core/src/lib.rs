//! Platform-neutral agent core: sessions, bounded queues, resize policy.
//!
//! No capture, encoding, transport or OS calls here. Those are platform
//! backends, gated on the P0 decision record. This crate is pure logic with
//! unit tests, so it runs on every host including CI.

pub mod handshake;
pub mod identity;
pub mod queue;
pub mod resize;
pub mod session;

pub use handshake::{Ack, Handshake};
pub use identity::{check_token, enroll, load, now_secs, EnrollError, EnrollmentToken, Identity};
pub use queue::BoundedQueue;
pub use resize::{ResizePolicy, ResizeRequest};
pub use session::{Role, Session};
