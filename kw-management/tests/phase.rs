use ed25519_dalek::{Signer, SigningKey};
use kw_management::updates::{
    digest,
    installer::{Error as DispatchError, PhaseAuthority},
    journal::{Action, Plan, Snapshot},
    phase::{self, CurrentAuthority, Error, LiveContext, Permit, SignedPhaseAuthority},
};
use std::collections::HashMap;

const SIGNATURE: &str = "06854609cf8e43cbcd10053a53c34b166ec9601630f81b39e074ac2b85a6b8e41954105929b945d7a975e467ebed0bdb443eeeaba9514c39a4bc3b86e1be7d00";

fn fixture() -> (Permit, Vec<u8>, Snapshot) {
    let raw = include_str!("testdata/phase-v1.json")
        .trim_end()
        .as_bytes()
        .to_vec();
    let p: Permit = serde_json::from_slice(&raw).unwrap();
    let journal: Snapshot =
        serde_json::from_slice(include_bytes!("testdata/journal-v1.json")).unwrap();
    assert_eq!(p.encode(), raw);
    assert_eq!(p.plan_sha256, journal.plan.sha256());
    assert_eq!(&p.action, journal.active.as_ref().unwrap());
    (p, raw, journal)
}

fn keyring() -> (String, HashMap<String, [u8; 32]>) {
    let public = SigningKey::from_bytes(&[0x5a; 32])
        .verifying_key()
        .to_bytes();
    let id = digest(&public)[..32].to_owned();
    (id.clone(), HashMap::from([(id, public)]))
}

fn sign(raw: &[u8]) -> Vec<u8> {
    let mut message = phase::DOMAIN.to_vec();
    message.extend_from_slice(raw);
    SigningKey::from_bytes(&[0x5a; 32])
        .sign(&message)
        .to_bytes()
        .to_vec()
}

#[test]
fn shared_go_signature_and_exact_bindings() {
    let (p, raw, _) = fixture();
    let (id, keys) = keyring();
    let sig = sign(&raw);
    let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, SIGNATURE);
    for now in [p.issued_at, p.expires_at - 1] {
        assert_eq!(phase::verify(&raw, &sig, &id, &keys, &p, now), Ok(()));
    }
    for now in [-1, p.issued_at - 1, p.expires_at, i64::MAX] {
        assert_eq!(
            phase::verify(&raw, &sig, &id, &keys, &p, now),
            Err(Error::Expired)
        );
    }
    let mutations: Vec<Permit> = (0..9)
        .map(|n| {
            let mut v = p.clone();
            match n {
                0 => v.version += 1,
                1 => v.audience = "command".into(),
                2 => v.plan_sha256 = "5".repeat(64),
                3 => v.action.sequence += 1,
                4 => v.action.kind = "uninstall_target_msi".into(),
                5 => v.action.boot_id = "boot-2".into(),
                6 => v.owner_fence += 1,
                7 => v.challenge = "B".repeat(43),
                _ => v.peer_sha256 = "5".repeat(64),
            }
            v
        })
        .collect();
    for expected in mutations {
        assert_eq!(
            phase::verify(&raw, &sig, &id, &keys, &expected, p.issued_at),
            Err(Error::Binding)
        );
    }
}

#[test]
fn strict_encoding_trust_and_bounds() {
    let (p, raw, _) = fixture();
    let (id, keys) = keyring();
    let text = String::from_utf8(raw.clone()).unwrap();
    let bad = vec![
        format!(" {text}").into_bytes(),
        text.replace("\"version\":1", "\"version\":1,\"version\":1")
            .into_bytes(),
        text.replace("\"version\":1", "\"version\":1,\"extra\":true")
            .into_bytes(),
        text.replace("\"version\":1,", "").into_bytes(),
        vec![b'x'; phase::MAX_BYTES + 1],
        vec![0xff],
    ];
    for b in bad {
        assert_eq!(
            phase::verify(&b, &sign(&b), &id, &keys, &p, p.issued_at),
            Err(Error::Invalid)
        );
    }
    for n in 0..7 {
        let mut v = p.clone();
        match n {
            0 => v.expires_at += 1,
            1 => v.issued_at = 0,
            2 => v.owner_fence = 0,
            3 => v.action.sequence = 0,
            4 => v.action.kind = "shell".into(),
            5 => v.challenge = "bad".into(),
            _ => v.expires_at = i64::MAX,
        }
        let b = v.encode();
        assert_eq!(
            phase::verify(&b, &sign(&b), &id, &keys, &p, p.issued_at),
            Err(Error::Invalid)
        );
    }
    let sig = sign(&raw);
    assert_eq!(
        phase::verify(&raw, &sig, "unknown", &keys, &p, p.issued_at),
        Err(Error::Untrusted)
    );
    assert_eq!(
        phase::verify(&raw, &sig, &id, &HashMap::new(), &p, p.issued_at),
        Err(Error::Untrusted)
    );
    let foreign = SigningKey::from_bytes(&[0x5b; 32]).sign(&raw);
    assert_eq!(
        phase::verify(&raw, &foreign.to_bytes(), &id, &keys, &p, p.issued_at),
        Err(Error::Signature)
    );
}

// Test-only live authority. Production deliberately supplies no implementation.
struct Current {
    permit: Permit,
    deny: bool,
}
impl CurrentAuthority for Current {
    fn check(&mut self, _: &Plan, _: &Action, _: u64) -> Result<LiveContext, DispatchError> {
        if self.deny {
            return Err(DispatchError::Authority);
        }
        Ok(LiveContext {
            challenge: self.permit.challenge.clone(),
            peer_sha256: self.permit.peer_sha256.clone(),
            now: self.permit.issued_at,
        })
    }
}

#[test]
fn adapter_consumes_response_on_success_denial_and_outage() {
    let (p, raw, journal) = fixture();
    for deny in [false, true] {
        for wrong_fence in [false, true] {
            let (id, keys) = keyring();
            let mut authority = SignedPhaseAuthority::new(
                raw.clone(),
                sign(&raw),
                id,
                keys,
                Current {
                    permit: p.clone(),
                    deny,
                },
            );
            let fence = journal.owner_fence + u64::from(wrong_fence);
            let result = authority.authorize(&journal.plan, &p.action, fence);
            assert_eq!(result.is_ok(), !deny && !wrong_fence);
            assert_eq!(
                authority.authorize(&journal.plan, &p.action, journal.owner_fence),
                Err(DispatchError::Authority)
            );
        }
    }
}
