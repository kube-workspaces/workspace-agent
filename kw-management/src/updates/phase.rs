//! Short-lived, exact-action phase permits. No listener or permissive current
//! authority source is supplied. A signature is not a substitute for live
//! identity/lifecycle/policy/recording checks at the dispatch boundary.

use super::{
    installer::{Error as DispatchError, PhaseAuthority},
    inventory::valid_nonce,
    journal::{Action, Plan, MAX_JOURNAL_SEQUENCE},
    key_id, valid_digest,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DOMAIN: &[u8] = b"kw-agent-upgrade-phase/v1\0";
pub const MAX_BYTES: usize = 4096;
pub const MAX_SECONDS: i64 = 15;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Untrusted,
    Signature,
    Binding,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub version: u32,
    pub audience: String,
    pub plan_sha256: String,
    pub action: Action,
    pub owner_fence: u64,
    pub challenge: String,
    pub peer_sha256: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl Permit {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("phase schema serialization is infallible")
    }

    fn valid(&self) -> bool {
        self.version == 1
            && self.audience == "agent-upgrade.phase.v1"
            && valid_digest(&self.plan_sha256)
            && valid_digest(&self.peer_sha256)
            && valid_nonce(&self.challenge)
            && self.owner_fence > 0
            && self.owner_fence <= MAX_JOURNAL_SEQUENCE
            && self.action.sequence > 0
            && self.action.sequence <= MAX_JOURNAL_SEQUENCE
            && super::identifier(&self.action.boot_id)
            && matches!(
                self.action.kind.as_str(),
                "stop_agent"
                    | "start_agent"
                    | "install_target_msi"
                    | "uninstall_target_msi"
                    | "install_previous_msi"
                    | "install_target_driver"
                    | "restore_previous_driver"
                    | "verify_target"
                    | "verify_previous"
                    | "reboot"
            )
            && self.issued_at > 0
            && self.expires_at > self.issued_at
            && self.expires_at - self.issued_at <= MAX_SECONDS
    }
}

/// Independently obtained from a live authenticated management exchange. The
/// challenge is 32 random bytes, base64url without padding, minted by the guest
/// for this action, never taken from the returned permit. peer_sha256 is the
/// authenticated management peer's certificate digest, never a request header.
pub struct LiveContext {
    pub challenge: String,
    pub peer_sha256: String,
    pub now: i64,
}

pub fn verify(
    raw: &[u8],
    signature: &[u8],
    id: &str,
    keys: &HashMap<String, [u8; 32]>,
    expected: &Permit,
    now: i64,
) -> Result<(), Error> {
    if raw.is_empty() || raw.len() > MAX_BYTES || std::str::from_utf8(raw).is_err() {
        return Err(Error::Invalid);
    }
    if keys.is_empty() || keys.len() > 16 || keys.iter().any(|(id, key)| id != &key_id(key)) {
        return Err(Error::Untrusted);
    }
    let key = VerifyingKey::from_bytes(keys.get(id).ok_or(Error::Untrusted)?)
        .map_err(|_| Error::Untrusted)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::Signature)?;
    let permit: Permit = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
    if !permit.valid() || permit.encode() != raw {
        return Err(Error::Invalid);
    }
    // Timestamps come from the signed issuer; all other fields are independently
    // expected. Never compare against values reconstructed from the permit.
    let mut binding = expected.clone();
    binding.issued_at = permit.issued_at;
    binding.expires_at = permit.expires_at;
    if binding != permit {
        return Err(Error::Binding);
    }
    if now < permit.issued_at || now >= permit.expires_at {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Must recheck current enrolled workspace/VM/epoch and boot identity, lease,
/// cancellation, deadline, policy, and exact durable intent acknowledgment.
/// Outages deny; no stale cached status or journal-only implementation is safe.
/// Implementations must also consume the outstanding challenge durably, so a
/// process restart or a second adapter cannot replay a signed response.
pub trait CurrentAuthority {
    fn check(
        &mut self,
        plan: &Plan,
        action: &Action,
        fence: u64,
    ) -> Result<LiveContext, DispatchError>;
}

/// One response can be attempted once, including denial or a transport outage.
/// This does not create a CommittedAction or bypass the journal/recording gate.
pub struct SignedPhaseAuthority<S> {
    response: Option<(Vec<u8>, Vec<u8>, String)>,
    keys: HashMap<String, [u8; 32]>,
    current: S,
}

impl<S: CurrentAuthority> SignedPhaseAuthority<S> {
    pub fn new(
        raw: Vec<u8>,
        signature: Vec<u8>,
        id: String,
        keys: HashMap<String, [u8; 32]>,
        current: S,
    ) -> Self {
        Self {
            response: Some((raw, signature, id)),
            keys,
            current,
        }
    }
}

impl<S: CurrentAuthority> PhaseAuthority for SignedPhaseAuthority<S> {
    fn authorize(&mut self, plan: &Plan, action: &Action, fence: u64) -> Result<(), DispatchError> {
        let (raw, signature, id) = self.response.take().ok_or(DispatchError::Authority)?;
        if !plan.valid() {
            return Err(DispatchError::Authority);
        }
        let live = self.current.check(plan, action, fence)?;
        let expected = Permit {
            version: 1,
            audience: "agent-upgrade.phase.v1".into(),
            plan_sha256: plan.sha256(),
            action: action.clone(),
            owner_fence: fence,
            challenge: live.challenge,
            peer_sha256: live.peer_sha256,
            issued_at: 0,
            expires_at: 0,
        };
        verify(&raw, &signature, &id, &self.keys, &expected, live.now)
            .map_err(|_| DispatchError::Authority)
    }
}
