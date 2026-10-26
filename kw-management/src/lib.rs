//! Management-v1 asymmetric grant verifier. Independent from display tickets.
//! This library opens no network listener and creates no process. Enrollment,
//! mTLS and authenticated current identity/epoch synchronization remain required.
//!
//! Also home to the approved QGA pilot transport contract (`qga-pod-exec/v1`):
//! a distinct grant audience/type plus the bounded command request envelope the
//! installed runner verifies before any process is created. The runner itself
//! lives in `kw-agent`; this crate only defines and verifies the contract.

/// Offline publisher-signed update manifest contract; no installation/dispatch.
pub mod updates;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const AUDIENCE: &str = "kube-workspaces/management/v1";
const ISSUER: &str = "kube-workspaces-api/management/v1";
const GRANT_TYPE: &str = "kw-management-grant+jwt";
const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Expired,
    Binding,
    Replay,
    Capacity,
    Entropy,
}

/// Expected binding must come from guest enrollment, authenticated current
/// state, the validated mTLS peer, this connection's challenge and actual framed
/// request bytes. Never populate expected values from the untrusted token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub actor_uid: String,
    pub namespace: String,
    pub workspace_name: String,
    pub workspace_uid: String,
    pub provisioning_generation: String,
    pub execution_id: String,
    pub recording_id: String,
    pub operation: String,
    pub os_identity: String,
    pub elevated: bool,
    pub policy_version: String,
    pub revocation_epoch: u64,
    pub challenge: String,
    pub peer_certificate_sha256: String,
    pub request_sha256: String,
}

impl Binding {
    fn valid(&self) -> bool {
        let fields = [
            &self.actor_uid,
            &self.namespace,
            &self.workspace_name,
            &self.workspace_uid,
            &self.provisioning_generation,
            &self.execution_id,
            &self.recording_id,
            &self.os_identity,
            &self.policy_version,
        ];
        if fields.iter().any(|v| {
            v.is_empty()
                || v.len() > 256
                || v.trim() != v.as_str()
                || v.chars().any(char::is_control)
        }) {
            return false;
        }
        if !matches!(self.operation.as_str(), "command" | "script" | "shell") {
            return false;
        }
        if !self.elevated
            && (self.os_identity.eq_ignore_ascii_case("root")
                || self.os_identity.eq_ignore_ascii_case("SYSTEM")
                || self.os_identity == "0")
        {
            return false;
        }
        valid_nonce(&self.challenge)
            && valid_digest(&self.peer_certificate_sha256)
            && valid_digest(&self.request_sha256)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub version: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub binding: Binding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

fn valid_nonce(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// SHA-256 of exact framed request bytes or the validated peer certificate DER.
pub fn digest(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    digest(public_key)[..32].to_owned()
}

/// Generate once per authenticated connection. Never restore an old challenge
/// with an empty replay cache after restart or disconnect.
pub fn new_challenge() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Non-cloneable connection-local replay state. `&mut self` makes consumption
/// exclusive; a concurrent transport must retain it behind one shared mutex.
pub struct Verifier {
    keys: HashMap<String, VerifyingKey>,
    used: HashMap<String, i64>,
    capacity: usize,
    last_time: i64,
}

impl Verifier {
    /// Only independently provisioned public keys belong here. Overlap old/new
    /// keys during rotation; never resolve keys from a token URL or guest input.
    pub fn new(public_keys: &[[u8; 32]], capacity: usize) -> Result<Self, Error> {
        if public_keys.is_empty() || public_keys.len() > 16 || !(1..=65536).contains(&capacity) {
            return Err(Error::Invalid);
        }
        let mut keys = HashMap::new();
        for key in public_keys {
            let verifying = VerifyingKey::from_bytes(key).map_err(|_| Error::Invalid)?;
            if keys.insert(key_id(key), verifying).is_some() {
                return Err(Error::Invalid);
            }
        }
        Ok(Self {
            keys,
            used: HashMap::new(),
            capacity,
            last_time: 0,
        })
    }

    pub fn consume(&mut self, token: &str, expected: &Binding, now: i64) -> Result<Claims, Error> {
        if token.len() > MAX_TOKEN_BYTES || !expected.valid() {
            return Err(Error::Invalid);
        }
        let mut parts = token.split('.');
        let h = parts.next().ok_or(Error::Invalid)?;
        let p = parts.next().ok_or(Error::Invalid)?;
        let s = parts.next().ok_or(Error::Invalid)?;
        if parts.next().is_some() {
            return Err(Error::Invalid);
        }
        let header: Header =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        if header.alg != "EdDSA" || header.typ != GRANT_TYPE {
            return Err(Error::Invalid);
        }
        let key = self.keys.get(&header.kid).ok_or(Error::Invalid)?;
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        key.verify_strict(format!("{h}.{p}").as_bytes(), &signature)
            .map_err(|_| Error::Invalid)?;
        let claims: Claims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        if claims.version != 1
            || claims.iss != ISSUER
            || claims.aud != AUDIENCE
            || !valid_nonce(&claims.jti)
            || !claims.binding.valid()
        {
            return Err(Error::Invalid);
        }
        if claims.iat <= 0
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > 60
            || now < claims.iat
            || now >= claims.exp
            || now < self.last_time
        {
            return Err(Error::Expired);
        }
        if &claims.binding != expected {
            return Err(Error::Binding);
        }
        self.last_time = now;
        self.used.retain(|_, expiry| *expiry > now);
        if self.used.contains_key(&claims.jti) {
            return Err(Error::Replay);
        }
        if self.used.len() >= self.capacity {
            return Err(Error::Capacity);
        }
        self.used.insert(claims.jti.clone(), claims.exp);
        Ok(claims)
    }
}

// --- QGA pilot transport (qga-pod-exec/v1) ---------------------------------
//
// Approved 2026-10-18 as an explicit opt-in backend for the Windows
// command-only MVP pilot: Kubernetes-authenticated pod exec into the current
// virt-launcher invokes this guest's installed runner through the QEMU guest
// agent. It is never a fallback from a failed mTLS management connection.
// Distinct audience/type values mean an mTLS endpoint can never accept these
// grants and the runner can never accept an mTLS-management grant.

pub const QGA_AUDIENCE: &str = "kube-workspaces/management-qga/v1";
pub const QGA_ISSUER: &str = "kube-workspaces-api/management-qga/v1";
const QGA_GRANT_TYPE: &str = "kw-management-grant+qga";
pub const TRANSPORT_QGA_POD_EXEC: &str = "qga-pod-exec/v1";

/// Confirmed pilot contract bounds. Keep in step with the API-side limits.
pub const QGA_MAX_DEADLINE_SECONDS: u32 = 20;
pub const QGA_MAX_OUTPUT_BYTES: usize = 16 * 1024;
pub const QGA_MAX_ARGS: usize = 64;
pub const QGA_MAX_ARG_BYTES: usize = 8 * 1024;
pub const QGA_MAX_EXECUTABLE_BYTES: usize = 1024;
pub const QGA_MAX_CWD_BYTES: usize = 1024;
pub const QGA_MAX_ENVELOPE_BYTES: usize = 96 * 1024;
pub const QGA_MAX_SCRIPT_BYTES: usize = 64 * 1024;

/// Version 2 Linux script payload. The exact request bytes, including this
/// policy, body and basename hint, are covered by the grant request digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QgaScript {
    pub body: String,
    pub name: Option<String>,
    pub interpreter_policy: String,
}

impl QgaScript {
    pub fn validate(&self) -> Result<(), String> {
        if self.interpreter_policy != "linux-shebang-v1"
            || self.body.is_empty()
            || self.body.len() > QGA_MAX_SCRIPT_BYTES
            || self.body.contains('\0')
        {
            return Err("script body or interpreter policy is unsupported".into());
        }
        // Fixed absolute interpreters only; no env/PATH lookup, interpreter
        // arguments, CRLF shebangs or shell-string construction.
        if !matches!(
            self.body.split('\n').next().unwrap_or_default(),
            "#!/bin/sh" | "#!/bin/bash" | "#!/usr/bin/bash" | "#!/usr/bin/python3"
        ) {
            return Err("unsupported Linux script shebang".into());
        }
        if let Some(name) = &self.name {
            if name.is_empty()
                || name.len() > 128
                || matches!(name.as_str(), "." | "..")
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            {
                return Err("script name must be a bounded basename hint".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum QgaError {
    Invalid,
    Expired,
    Binding,
    Replay,
    Capacity,
    Entropy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QgaBinding {
    pub actor_uid: String,
    pub namespace: String,
    pub workspace_name: String,
    pub workspace_uid: String,
    pub provisioning_generation: String,
    pub execution_id: String,
    pub recording_id: String,
    pub operation: String,
    pub os_identity: String,
    pub elevated: bool,
    pub policy_version: String,
    pub revocation_epoch: u64,
    pub challenge: String,
    pub transport: String,
    pub transport_target_sha256: String,
    pub request_sha256: String,
}

impl QgaBinding {
    fn valid(&self) -> bool {
        let fields = [
            &self.actor_uid,
            &self.namespace,
            &self.workspace_name,
            &self.workspace_uid,
            &self.provisioning_generation,
            &self.execution_id,
            &self.recording_id,
            &self.policy_version,
        ];
        if fields.iter().any(|v| {
            v.is_empty()
                || v.len() > 256
                || v.trim() != v.as_str()
                || v.chars().any(char::is_control)
        }) {
            return false;
        }
        // Bounded elevated commands only. The platform runner additionally
        // enforces that the signed identity matches its actual OS identity.
        if (self.operation != "command" && self.operation != "script")
            || self.transport != TRANSPORT_QGA_POD_EXEC
            || !(self.os_identity.eq_ignore_ascii_case("SYSTEM") || self.os_identity == "root")
            || !self.elevated
        {
            return false;
        }
        valid_nonce(&self.challenge)
            && valid_digest(&self.transport_target_sha256)
            && valid_digest(&self.request_sha256)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QgaClaims {
    pub version: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub binding: QgaBinding,
}

/// Bounded command request framed by the API and staged to the guest. The
/// grant's `request_sha256` is the digest of the exact serialized bytes of
/// this value as they appear in the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QgaCommandRequest {
    pub version: u32,
    pub challenge: String,
    pub transport_target_sha256: String,
    pub actor_uid: String,
    pub namespace: String,
    pub workspace_name: String,
    pub workspace_uid: String,
    pub provisioning_generation: String,
    pub execution_id: String,
    pub recording_id: String,
    pub operation: String,
    pub os_identity: String,
    pub elevated: bool,
    pub policy_version: String,
    pub revocation_epoch: u64,
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<QgaScript>,
    pub cwd: Option<String>,
    pub deadline_seconds: u32,
}

impl QgaCommandRequest {
    /// Structural and pilot-bound checks. `enrolled_uid` is the guest's own
    /// enrolled workspace UID — the one binding the runner can verify
    /// independently of the API-supplied envelope.
    pub fn validate(&self, enrolled_uid: &str) -> Result<(), String> {
        match (self.version, self.operation.as_str(), &self.script) {
            (1, "command", None) => (),
            (2, "script", Some(script))
                if self.os_identity == "root"
                    && self.executable.is_empty()
                    && self.args.is_empty() =>
            {
                script.validate()?
            }
            _ => return Err("unsupported request version, operation or script framing".into()),
        }
        if !(self.os_identity.eq_ignore_ascii_case("SYSTEM") || self.os_identity == "root")
            || !self.elevated
        {
            return Err("pilot transport requires explicit SYSTEM or root identity".into());
        }
        if !(1..=QGA_MAX_DEADLINE_SECONDS).contains(&self.deadline_seconds) {
            return Err(format!(
                "deadline_seconds must be within 1..={QGA_MAX_DEADLINE_SECONDS}"
            ));
        }
        if self.script.is_none()
            && (self.executable.is_empty()
                || self.executable.len() > QGA_MAX_EXECUTABLE_BYTES
                || self.executable.trim() != self.executable.as_str()
                || self.executable.chars().any(char::is_control))
        {
            return Err("executable is missing or out of bounds".into());
        }
        if self.args.len() > QGA_MAX_ARGS
            || self
                .args
                .iter()
                .any(|a| a.len() > QGA_MAX_ARG_BYTES || a.chars().any(char::is_control))
        {
            return Err("arguments are out of bounds".into());
        }
        if let Some(cwd) = &self.cwd {
            if cwd.is_empty()
                || cwd.len() > QGA_MAX_CWD_BYTES
                || cwd.trim() != cwd.as_str()
                || cwd.chars().any(char::is_control)
            {
                return Err("cwd is out of bounds".into());
            }
        }
        if self.workspace_uid != enrolled_uid {
            return Err("workspace UID does not match this guest's enrolled identity".into());
        }
        if !valid_nonce(&self.challenge)
            || !valid_digest(&self.transport_target_sha256)
            || self.actor_uid.is_empty()
            || self.namespace.is_empty()
            || self.workspace_name.is_empty()
            || self.provisioning_generation.is_empty()
            || self.execution_id.is_empty()
            || self.recording_id.is_empty()
            || self.policy_version.is_empty()
        {
            return Err("request binding fields are missing or malformed".into());
        }
        Ok(())
    }

    /// Expected binding assembled from the digest-authenticated request; the
    /// guest never takes expected values from the token itself.
    pub fn expected_binding(&self, request_sha256: String) -> QgaBinding {
        QgaBinding {
            actor_uid: self.actor_uid.clone(),
            namespace: self.namespace.clone(),
            workspace_name: self.workspace_name.clone(),
            workspace_uid: self.workspace_uid.clone(),
            provisioning_generation: self.provisioning_generation.clone(),
            execution_id: self.execution_id.clone(),
            recording_id: self.recording_id.clone(),
            operation: self.operation.clone(),
            os_identity: self.os_identity.clone(),
            elevated: self.elevated,
            policy_version: self.policy_version.clone(),
            revocation_epoch: self.revocation_epoch,
            challenge: self.challenge.clone(),
            transport: TRANSPORT_QGA_POD_EXEC.to_owned(),
            transport_target_sha256: self.transport_target_sha256.clone(),
            request_sha256,
        }
    }
}

/// Staged guest file: the signed grant plus the exact request bytes whose
/// digest the grant binds.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QgaEnvelope<'a> {
    pub grant: &'a str,
    pub request: &'a serde_json::value::RawValue,
}

/// Split a staged envelope, returning the grant and the verbatim request
/// bytes. Size-bounded before parsing.
pub fn split_qga_envelope(data: &[u8]) -> Result<(String, &serde_json::value::RawValue), QgaError> {
    if data.is_empty() || data.len() > QGA_MAX_ENVELOPE_BYTES {
        return Err(QgaError::Invalid);
    }
    let envelope: QgaEnvelope = serde_json::from_slice(data).map_err(|_| QgaError::Invalid)?;
    if envelope.grant.is_empty() || envelope.grant.len() > MAX_TOKEN_BYTES {
        return Err(QgaError::Invalid);
    }
    Ok((envelope.grant.to_owned(), envelope.request))
}

/// Bounded one-time-consumption verifier for QGA grants. The runner adds
/// persistent single-use state on top because it is a short-lived process.
pub struct QgaVerifier {
    keys: HashMap<String, VerifyingKey>,
    used: HashMap<String, i64>,
    capacity: usize,
    last_time: i64,
}

impl QgaVerifier {
    pub fn new(public_keys: &[[u8; 32]], capacity: usize) -> Result<Self, QgaError> {
        if public_keys.is_empty() || public_keys.len() > 16 || !(1..=65536).contains(&capacity) {
            return Err(QgaError::Invalid);
        }
        let mut keys = HashMap::new();
        for key in public_keys {
            let verifying = VerifyingKey::from_bytes(key).map_err(|_| QgaError::Invalid)?;
            if keys.insert(key_id(key), verifying).is_some() {
                return Err(QgaError::Invalid);
            }
        }
        Ok(Self {
            keys,
            used: HashMap::new(),
            capacity,
            last_time: 0,
        })
    }

    pub fn consume(
        &mut self,
        token: &str,
        expected: &QgaBinding,
        now: i64,
    ) -> Result<QgaClaims, QgaError> {
        if token.len() > MAX_TOKEN_BYTES || !expected.valid() {
            return Err(QgaError::Invalid);
        }
        let mut parts = token.split('.');
        let h = parts.next().ok_or(QgaError::Invalid)?;
        let p = parts.next().ok_or(QgaError::Invalid)?;
        let s = parts.next().ok_or(QgaError::Invalid)?;
        if parts.next().is_some() {
            return Err(QgaError::Invalid);
        }
        let header: Header =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|_| QgaError::Invalid)?)
                .map_err(|_| QgaError::Invalid)?;
        if header.alg != "EdDSA" || header.typ != QGA_GRANT_TYPE {
            return Err(QgaError::Invalid);
        }
        let key = self.keys.get(&header.kid).ok_or(QgaError::Invalid)?;
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(s).map_err(|_| QgaError::Invalid)?)
                .map_err(|_| QgaError::Invalid)?;
        key.verify_strict(format!("{h}.{p}").as_bytes(), &signature)
            .map_err(|_| QgaError::Invalid)?;
        let claims: QgaClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|_| QgaError::Invalid)?)
                .map_err(|_| QgaError::Invalid)?;
        if claims.version != 1
            || claims.iss != QGA_ISSUER
            || claims.aud != QGA_AUDIENCE
            || !valid_nonce(&claims.jti)
            || !claims.binding.valid()
        {
            return Err(QgaError::Invalid);
        }
        if claims.iat <= 0
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > 60
            || now < claims.iat
            || now >= claims.exp
            || now < self.last_time
        {
            return Err(QgaError::Expired);
        }
        if &claims.binding != expected {
            return Err(QgaError::Binding);
        }
        self.last_time = now;
        self.used.retain(|_, expiry| *expiry > now);
        if self.used.contains_key(&claims.jti) {
            return Err(QgaError::Replay);
        }
        if self.used.len() >= self.capacity {
            return Err(QgaError::Capacity);
        }
        self.used.insert(claims.jti.clone(), claims.exp);
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        public_key: String,
        now: i64,
        binding: Binding,
        token: String,
    }

    fn vector() -> Vector {
        serde_json::from_str(include_str!("../fixtures/management-v1.json")).unwrap()
    }

    fn verifier(v: &Vector) -> Verifier {
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&v.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        Verifier::new(&[key], 16).unwrap()
    }

    #[test]
    fn go_signature_interoperability_and_replay() {
        let v = vector();
        let mut verify = verifier(&v);
        assert_eq!(
            verify.consume(&v.token, &v.binding, v.now).unwrap().binding,
            v.binding
        );
        assert_eq!(
            verify.consume(&v.token, &v.binding, v.now).unwrap_err(),
            Error::Replay
        );
    }

    #[test]
    fn scope_expiry_signature_and_revocation_denials() {
        let v = vector();
        let mut verify = verifier(&v);
        let mut other = v.binding.clone();
        other.revocation_epoch += 1;
        assert_eq!(
            verify.consume(&v.token, &other, v.now).unwrap_err(),
            Error::Binding
        );
        other = v.binding.clone();
        other.request_sha256 = digest(b"other request");
        assert_eq!(
            verify.consume(&v.token, &other, v.now).unwrap_err(),
            Error::Binding
        );
        other = v.binding.clone();
        other.challenge = new_challenge().unwrap();
        assert_eq!(
            verify.consume(&v.token, &other, v.now).unwrap_err(),
            Error::Binding
        );
        other = v.binding.clone();
        other.provisioning_generation = "reset".to_string();
        assert_eq!(
            verify.consume(&v.token, &other, v.now).unwrap_err(),
            Error::Binding
        );
        assert_eq!(
            verify.consume(&v.token, &v.binding, v.now - 1).unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            verify
                .consume(&v.token, &v.binding, v.now + 30)
                .unwrap_err(),
            Error::Expired
        );
        assert!(verify
            .consume(&(v.token.clone() + "A"), &v.binding, v.now)
            .is_err());
        assert!(verify.consume("e30.e30.AA", &v.binding, v.now).is_err());
        assert!(verify.consume(&v.token, &v.binding, v.now).is_ok());
    }

    #[test]
    fn all_bindings_are_independent() {
        let v = vector();
        let mutations: &[fn(&mut Binding)] = &[
            |b| b.actor_uid.push('x'),
            |b| b.namespace.push('x'),
            |b| b.workspace_name.push('x'),
            |b| b.workspace_uid.push('x'),
            |b| b.provisioning_generation.push('x'),
            |b| b.execution_id.push('x'),
            |b| b.recording_id.push('x'),
            |b| b.operation = "script".into(),
            |b| b.os_identity.push('x'),
            |b| b.elevated = true,
            |b| b.policy_version.push('x'),
            |b| b.revocation_epoch += 1,
            |b| b.challenge = new_challenge().unwrap(),
            |b| b.peer_certificate_sha256 = digest(b"other peer"),
            |b| b.request_sha256 = digest(b"other request"),
        ];
        for change in mutations {
            let mut verify = verifier(&v);
            let mut other = v.binding.clone();
            change(&mut other);
            assert_eq!(
                verify.consume(&v.token, &other, v.now).unwrap_err(),
                Error::Binding
            );
            assert!(verify.consume(&v.token, &v.binding, v.now).is_ok());
        }
    }

    fn signed(claims: &Claims, seed: [u8; 32]) -> String {
        use ed25519_dalek::Signer;
        // Intentionally public fixture keys; never provision in an installation.
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let header = serde_json::json!({"alg": "EdDSA", "typ": GRANT_TYPE, "kid": key_id(key.verifying_key().as_bytes())});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
        )
    }

    #[test]
    fn qga_go_signature_interoperability_and_replay() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/management-qga-v1.json")).unwrap();
        let token = v["token"].as_str().unwrap().to_owned();
        let binding: QgaBinding = serde_json::from_value(v["binding"].clone()).unwrap();
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(v["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let now = v["now"].as_i64().unwrap();
        let mut verify = QgaVerifier::new(&[key], 16).unwrap();
        assert_eq!(
            verify.consume(&token, &binding, now).unwrap().binding,
            binding
        );
        assert_eq!(
            verify.consume(&token, &binding, now).unwrap_err(),
            QgaError::Replay
        );
    }

    #[test]
    fn qga_request_envelope_round_trip_and_expected_binding() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/management-qga-v1.json")).unwrap();
        let request_bytes = URL_SAFE_NO_PAD
            .decode(v["request_b64url"].as_str().unwrap())
            .unwrap();
        let token = v["token"].as_str().unwrap();
        let envelope = format!(
            "{{\"grant\":\"{token}\",\"request\":{}}}",
            std::str::from_utf8(&request_bytes).unwrap()
        );
        let (grant, request_raw) = split_qga_envelope(envelope.as_bytes()).unwrap();
        assert_eq!(grant, token);
        assert_eq!(digest(request_raw.get().as_bytes()), {
            let b: QgaBinding = serde_json::from_value(v["binding"].clone()).unwrap();
            b.request_sha256
        });
        let request: QgaCommandRequest = serde_json::from_str(request_raw.get()).unwrap();
        request
            .validate(&request.workspace_uid)
            .expect("fixture request must validate");
        let expected = request.expected_binding(digest(request_raw.get().as_bytes()));
        let binding: QgaBinding = serde_json::from_value(v["binding"].clone()).unwrap();
        assert_eq!(expected, binding);
        assert!(request.validate("other-uid").is_err());
        assert!(split_qga_envelope(b"{\"grant\":1}").is_err());
        assert!(split_qga_envelope(b"not json").is_err());
        assert!(split_qga_envelope(&[]).is_err());
    }

    #[test]
    fn qga_request_pilot_bounds_and_identity_denials() {
        let request = QgaCommandRequest {
            version: 1,
            challenge: new_challenge().unwrap(),
            transport_target_sha256: digest(b"target"),
            actor_uid: "user-1".into(),
            namespace: "team-a".into(),
            workspace_name: "vm-1".into(),
            workspace_uid: "uid".into(),
            provisioning_generation: "vm-uid".into(),
            execution_id: "exec-1".into(),
            recording_id: "rec-1".into(),
            operation: "command".into(),
            os_identity: "SYSTEM".into(),
            elevated: true,
            policy_version: "1".into(),
            revocation_epoch: 0,
            executable: "cmd.exe".into(),
            args: vec!["/c".into(), "echo hi".into()],
            script: None,
            cwd: None,
            deadline_seconds: 20,
        };
        assert!(request.validate("uid").is_ok());
        let mutations: &[fn(&mut QgaCommandRequest)] = &[
            |r| r.version = 2,
            |r| r.operation = "shell".into(),
            |r| r.os_identity = "workspace".into(),
            |r| r.elevated = false,
            |r| r.deadline_seconds = 0,
            |r| r.deadline_seconds = 21,
            |r| r.executable = String::new(),
            |r| r.executable = "x".repeat(QGA_MAX_EXECUTABLE_BYTES + 1),
            |r| r.args = vec!["x".repeat(QGA_MAX_ARG_BYTES + 1)],
            |r| r.cwd = Some("\n".into()),
            |r| r.challenge = "short".into(),
            |r| r.transport_target_sha256 = "bad".into(),
            |r| r.workspace_uid = "other".into(),
        ];
        for change in mutations {
            let mut mutated = request.clone();
            change(&mut mutated);
            assert!(
                mutated.validate("uid").is_err(),
                "mutation must deny: {mutated:?}"
            );
        }
        let mut script_req = request.clone();
        script_req.operation = "script".into();
        assert!(script_req.validate("uid").is_err());
        script_req.version = 2;
        script_req.os_identity = "root".into();
        script_req.executable.clear();
        script_req.args.clear();
        script_req.script = Some(QgaScript {
            body: "#!/bin/sh\nid\n".into(),
            name: Some("test.sh".into()),
            interpreter_policy: "linux-shebang-v1".into(),
        });
        assert!(script_req.validate("uid").is_ok());
        for change in [
            |r: &mut QgaCommandRequest| r.version = 1,
            |r: &mut QgaCommandRequest| r.operation = "command".into(),
            |r: &mut QgaCommandRequest| r.os_identity = "SYSTEM".into(),
            |r: &mut QgaCommandRequest| r.executable = "/bin/sh".into(),
            |r: &mut QgaCommandRequest| r.args.push("-c".into()),
            |r: &mut QgaCommandRequest| r.script = None,
        ] {
            let mut invalid = script_req.clone();
            change(&mut invalid);
            assert!(invalid.validate("uid").is_err());
        }
        // Expected binding is always SYSTEM/command over the fixed transport.
        let binding = request.expected_binding(digest(b"request"));
        assert!(binding.valid());
        let mut mtlspirit = binding.clone();
        mtlspirit.transport = "mtls/v1".into();
        assert!(!mtlspirit.valid());
        mtlspirit = binding.clone();
        mtlspirit.operation = "shell".into();
        assert!(!mtlspirit.valid());
        mtlspirit = binding.clone();
        mtlspirit.elevated = false;
        assert!(!mtlspirit.valid());
    }

    #[test]
    fn script_body_basename_and_interpreter_boundaries() {
        let mut script = QgaScript {
            body: "#!/bin/sh\n".into(),
            name: None,
            interpreter_policy: "linux-shebang-v1".into(),
        };
        for body in [
            "#!/bin/sh\n",
            "#!/bin/bash\n",
            "#!/usr/bin/bash\n",
            "#!/usr/bin/python3\n",
        ] {
            script.body = body.into();
            assert!(script.validate().is_ok());
        }
        for body in [
            "",
            "echo hi",
            "#!/usr/bin/env sh\n",
            "#!/bin/sh -e\n",
            "#!/bin/sh\r\n",
            "#!/bin/sh\nx\0",
        ] {
            script.body = body.into();
            assert!(script.validate().is_err());
        }
        script.body = format!("#!/bin/sh\n{}", "x".repeat(QGA_MAX_SCRIPT_BYTES - 10));
        assert_eq!(script.body.len(), QGA_MAX_SCRIPT_BYTES);
        assert!(script.validate().is_ok());
        script.body.push('x');
        assert!(script.validate().is_err());
        script.body = "#!/bin/sh\n".into();
        for name in [
            "",
            ".",
            "..",
            "../test",
            "/tmp/test",
            "a/b",
            "a\\b",
            "a\n",
            "a:b",
        ] {
            script.name = Some(name.into());
            assert!(script.validate().is_err());
        }
        script.name = Some("maintenance-1.sh".into());
        assert!(script.validate().is_ok());
        script.interpreter_policy = "unknown".into();
        assert!(script.validate().is_err());
    }

    #[test]
    fn go_script_v2_signature_interoperability_and_tamper_replay() {
        #[derive(Deserialize)]
        struct Fixture {
            now: i64,
            public_key: String,
            request: Box<serde_json::value::RawValue>,
            token: String,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../fixtures/linux-script-v2.json")).unwrap();
        let public: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&fixture.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let request: QgaCommandRequest = serde_json::from_str(fixture.request.get()).unwrap();
        request.validate("workspace-uid").unwrap();
        assert_eq!(request.version, 2);
        assert_eq!(
            request.script.as_ref().unwrap().body,
            "#!/bin/sh\nprintf 'hello\\n'\n"
        );
        let binding = request.expected_binding(digest(fixture.request.get().as_bytes()));
        let mut verifier = QgaVerifier::new(&[public], 4).unwrap();
        verifier
            .consume(&fixture.token, &binding, fixture.now)
            .unwrap();
        assert!(matches!(
            verifier.consume(&fixture.token, &binding, fixture.now),
            Err(QgaError::Replay)
        ));
        for change in [
            |r: &mut QgaCommandRequest| r.script.as_mut().unwrap().body.push_str("id\n"),
            |r: &mut QgaCommandRequest| r.script.as_mut().unwrap().name = Some("other.sh".into()),
            |r: &mut QgaCommandRequest| {
                r.script.as_mut().unwrap().interpreter_policy = "other".into()
            },
            |r: &mut QgaCommandRequest| r.cwd = Some("/tmp".into()),
        ] {
            let mut tampered = request.clone();
            change(&mut tampered);
            let expected =
                tampered.expected_binding(digest(&serde_json::to_vec(&tampered).unwrap()));
            let mut verifier = QgaVerifier::new(&[public], 4).unwrap();
            assert!(matches!(
                verifier.consume(&fixture.token, &expected, fixture.now),
                Err(QgaError::Binding)
            ));
        }
    }

    #[test]
    fn qga_verifier_cross_type_and_binding_denials() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/management-qga-v1.json")).unwrap();
        let token = v["token"].as_str().unwrap().to_owned();
        let binding: QgaBinding = serde_json::from_value(v["binding"].clone()).unwrap();
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(v["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let now = v["now"].as_i64().unwrap();
        let mut qga = QgaVerifier::new(&[key], 16).unwrap();
        // The mTLS verifier must reject the QGA grant type.
        let mut mtls = Verifier::new(&[key], 16).unwrap();
        let mtls_binding = Binding {
            actor_uid: binding.actor_uid.clone(),
            namespace: binding.namespace.clone(),
            workspace_name: binding.workspace_name.clone(),
            workspace_uid: binding.workspace_uid.clone(),
            provisioning_generation: binding.provisioning_generation.clone(),
            execution_id: binding.execution_id.clone(),
            recording_id: binding.recording_id.clone(),
            operation: "command".into(),
            os_identity: "workspace".into(),
            elevated: false,
            policy_version: binding.policy_version.clone(),
            revocation_epoch: 0,
            challenge: binding.challenge.clone(),
            peer_certificate_sha256: digest(b"peer"),
            request_sha256: binding.request_sha256.clone(),
        };
        assert!(mtls.consume(&token, &mtls_binding, now).is_err());
        let mutations: &[fn(&mut QgaBinding)] = &[
            |b| b.request_sha256 = digest(b"other"),
            |b| b.transport_target_sha256 = digest(b"other"),
            |b| b.workspace_uid.push('x'),
            |b| b.provisioning_generation = "reset".into(),
            |b| b.challenge = new_challenge().unwrap(),
            |b| b.revocation_epoch += 1,
        ];
        for change in mutations {
            let mut other = binding.clone();
            change(&mut other);
            assert_eq!(
                qga.consume(&token, &other, now).unwrap_err(),
                QgaError::Binding
            );
        }
        assert_eq!(
            qga.consume(&token, &binding, now + 30).unwrap_err(),
            QgaError::Expired
        );
        assert!(qga.consume(&token, &binding, now).is_ok());
    }

    #[test]
    fn cache_capacity_clock_rollback_and_key_rotation() {
        let v = vector();
        let mut verify = verifier(&v);
        verify.capacity = 1;
        let mut claims = verify.consume(&v.token, &v.binding, v.now).unwrap();
        claims.jti = new_challenge().unwrap();
        let token = signed(&claims, [0; 32]);
        assert_eq!(
            verify.consume(&token, &v.binding, v.now).unwrap_err(),
            Error::Capacity
        );
        claims.iat += 60;
        claims.exp += 60;
        let later = signed(&claims, [0; 32]);
        assert!(verify.consume(&later, &v.binding, v.now + 60).is_ok());
        assert_eq!(
            verify.consume(&v.token, &v.binding, v.now).unwrap_err(),
            Error::Expired
        );
        let old_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&v.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let new_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes();
        let mut rotating = Verifier::new(&[old_key, new_key], 16).unwrap();
        assert!(rotating.consume(&later, &v.binding, v.now + 60).is_ok());
        let new_token = signed(&claims, [1; 32]);
        assert!(rotating
            .consume(&new_token, &v.binding, v.now + 60)
            .is_err()); // same jti remains single-use across keys
        claims.jti = new_challenge().unwrap();
        assert!(rotating
            .consume(&signed(&claims, [1; 32]), &v.binding, v.now + 60)
            .is_ok());
        let mut retired = Verifier::new(&[new_key], 16).unwrap();
        assert_eq!(
            retired.consume(&later, &v.binding, v.now + 60).unwrap_err(),
            Error::Invalid
        );
    }
}
