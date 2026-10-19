use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use kw_management::updates::{self, Error, Manifest, VerifiedManifest};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, Read};

const RAW: &[u8] = include_bytes!("testdata/manifest-v1.json");

fn signed(raw: &[u8]) -> Result<VerifiedManifest, Error> {
    let key = SigningKey::from_bytes(&[0x55; 32]);
    let public = key.verifying_key().to_bytes();
    let mut message = updates::DOMAIN.to_vec();
    message.extend_from_slice(raw);
    updates::verify(
        raw,
        &key.sign(&message).to_bytes(),
        &updates::key_id(&public),
        &updates::digest(raw),
        &HashMap::from([(updates::key_id(&public), public)]),
    )
}

#[test]
fn publisher_fixture_and_bounded_streams() {
    #[derive(Deserialize)]
    struct Vector {
        key_id: String,
        manifest_sha256: String,
        public_key: String,
        signature: String,
    }
    let vector: Vector =
        serde_json::from_slice(include_bytes!("testdata/manifest-v1-signature.json")).unwrap();
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(vector.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let signature = URL_SAFE_NO_PAD.decode(vector.signature).unwrap();
    let v = updates::verify(
        RAW,
        &signature,
        &vector.key_id,
        &vector.manifest_sha256,
        &HashMap::from([(vector.key_id.clone(), public)]),
    )
    .unwrap();
    assert_eq!(v.sha256(), vector.manifest_sha256);
    assert_eq!(v.metadata().target_id, "windows-agent-0.3.5");
    for (name, payload) in [
        ("agent.msi", "msi-v1"),
        ("updater.exe", "helper-v1"),
        ("idd.zip", "idd-v1"),
    ] {
        assert_eq!(v.verify_artifact(name, &mut payload.as_bytes()), Ok(()));
        for bad in [
            payload[..payload.len() - 1].to_owned(),
            format!("{payload}x"),
            "x".repeat(payload.len()),
        ] {
            assert_eq!(
                v.verify_artifact(name, &mut bad.as_bytes()),
                Err(Error::Payload)
            );
        }
    }
    assert_eq!(
        v.verify_artifact("other.msi", &mut "msi-v1".as_bytes()),
        Err(Error::Payload)
    );
    let mut endless = CountingReader(0);
    assert_eq!(
        v.verify_artifact("agent.msi", &mut endless),
        Err(Error::Payload)
    );
    assert_eq!(endless.0, 7);
    let mut failure = "msi-v1".as_bytes().chain(FailureReader);
    assert_eq!(
        v.verify_artifact("agent.msi", &mut failure),
        Err(Error::Payload)
    );
}

struct CountingReader(usize);
impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0 += buffer.len();
        buffer.fill(0);
        Ok(buffer.len())
    }
}
struct FailureReader;
impl Read for FailureReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic outage"))
    }
}

#[test]
fn publisher_and_raw_byte_substitution_fail() {
    let key = SigningKey::from_bytes(&[0x55; 32]);
    let public = key.verifying_key().to_bytes();
    let id = updates::key_id(&public);
    let keys = HashMap::from([(id.clone(), public)]);
    let mut message = updates::DOMAIN.to_vec();
    message.extend_from_slice(RAW);
    let signature = key.sign(&message).to_bytes();
    let digest = updates::digest(RAW);
    assert_eq!(
        updates::verify(RAW, &signature, "unknown", &digest, &keys).unwrap_err(),
        Error::Untrusted
    );
    assert_eq!(
        updates::verify(RAW, &signature, &id, &digest, &HashMap::new()).unwrap_err(),
        Error::Untrusted
    );
    assert_eq!(
        updates::verify(RAW, &signature, &id, &"1".repeat(64), &keys).unwrap_err(),
        Error::Digest
    );
    assert_eq!(
        updates::verify(RAW, &[0; 64], &id, &digest, &keys).unwrap_err(),
        Error::Signature
    );
    assert_eq!(
        updates::verify(RAW, &key.sign(RAW).to_bytes(), &id, &digest, &keys).unwrap_err(),
        Error::Signature
    );
    let mut changed = RAW.to_vec();
    changed.push(b' ');
    assert_eq!(
        updates::verify(&changed, &signature, &id, &updates::digest(&changed), &keys).unwrap_err(),
        Error::Signature
    );
    assert_eq!(
        updates::verify(&[0xff], &signature, &id, &digest, &keys).unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        updates::verify(
            &vec![b' '; updates::MAX_MANIFEST_BYTES + 1],
            &signature,
            &id,
            &digest,
            &keys
        )
        .unwrap_err(),
        Error::Invalid
    );
}

#[test]
fn publisher_rotation_requires_explicit_overlap() {
    let old = SigningKey::from_bytes(&[0x55; 32]);
    let next = SigningKey::from_bytes(&[0x56; 32]);
    let mut keys = HashMap::from([
        (
            updates::key_id(&old.verifying_key().to_bytes()),
            old.verifying_key().to_bytes(),
        ),
        (
            updates::key_id(&next.verifying_key().to_bytes()),
            next.verifying_key().to_bytes(),
        ),
    ]);
    let mut message = updates::DOMAIN.to_vec();
    message.extend_from_slice(RAW);
    for key in [&old, &next] {
        assert!(updates::verify(
            RAW,
            &key.sign(&message).to_bytes(),
            &updates::key_id(&key.verifying_key().to_bytes()),
            &updates::digest(RAW),
            &keys
        )
        .is_ok());
    }
    keys.remove(&updates::key_id(&old.verifying_key().to_bytes()));
    assert_eq!(
        updates::verify(
            RAW,
            &old.sign(&message).to_bytes(),
            &updates::key_id(&old.verifying_key().to_bytes()),
            &updates::digest(RAW),
            &keys
        )
        .unwrap_err(),
        Error::Untrusted
    );
}

#[test]
fn malformed_publisher_signed_schema_fails() {
    let raw = std::str::from_utf8(RAW).unwrap();
    for (from, to) in [
        (r#""version": 1"#, r#""version": 2"#),
        (r#""version": 1"#, r#""version": 1, "version": 1"#),
        (r#""version": 1"#, r#""version": 1, "ver\u0073ion": 1"#),
        (r#""version": 1"#, r#""version": 1, "unknown": true"#),
        (r#""version": 1"#, r#""version": 1, "Version": 1"#),
        (r#""file": "agent.msi""#, r#""File": "agent.msi""#),
        (
            r#""file": "agent.msi""#,
            r#""file": "agent.msi", "file": "other.msi""#,
        ),
        (
            r#""file": "agent.msi""#,
            r#""file": "agent.msi", "fi\u006ce": "other.msi""#,
        ),
        (r#""file": "agent.msi""#, r#""file": "../agent.msi""#),
        (r#""file": "agent.msi""#, r#""file": "c:agent.msi""#),
        (r#""file": "agent.msi""#, r#""file": "con.msi""#),
        (r#""file": "agent.msi""#, r#""file": "com1.msi""#),
        (r#""file": "agent.msi""#, r#""file": "agent.msi.""#),
        (r#""size": 6"#, r#""size": 0"#),
        (r#""size": 6"#, r#""size": 2147483649"#),
        (r#""size": 6"#, r#""size": 6.0"#),
        (r#""size": 6"#, r#""size": null"#),
        (r#""architecture": "amd64""#, r#""architecture": "arm64""#),
        (r#""os": "windows""#, r#""os": "linux""#),
        (
            r#""agent_version": "0.3.5""#,
            r#""agent_version": "0.03.5""#,
        ),
        (
            r#""agent_version": "0.3.5""#,
            r#""agent_version": "256.3.5""#,
        ),
        (r#""protocol_version": 1"#, r#""protocol_version": 2"#),
        (r#""management_max": 1"#, r#""management_max": 0"#),
        (
            r#""minimum_agent_version": "0.3.0""#,
            r#""minimum_agent_version": "0.4.0""#,
        ),
        (
            r#""upgrade_code": "f72bb43e-dba8-4dbb-a963-b201e6c0d885""#,
            r#""upgrade_code": "12345678-1234-1234-1234-123456789abc""#,
        ),
        (r#""ROOT\\ExampleIDD""#, r#""ROOT\\*""#),
        (
            r#""ROOT\\ExampleIDD""#,
            r#""ROOT\\ExampleIDD", "root\\exampleidd""#,
        ),
        (
            r#""target_id": "windows-agent-0.3.4""#,
            r#""target_id": "windows-agent-0.3.5""#,
        ),
        (
            r#""reboot_policy": "may-require""#,
            r#""reboot_policy": "always""#,
        ),
    ] {
        let changed = raw.replacen(from, to, 1);
        assert_ne!(changed, raw, "mutation did not apply: {from}");
        assert_eq!(
            signed(changed.as_bytes()).unwrap_err(),
            Error::Invalid,
            "accepted {to}"
        );
    }
    for suffix in ["{}", "null", "[]"] {
        assert_eq!(
            signed(format!("{raw}{suffix}").as_bytes()).unwrap_err(),
            Error::Invalid
        );
    }
    let duplicated_driver = raw.replacen(r#""driver": {"#, r#""driver": null, "driver": {"#, 1);
    assert_eq!(
        signed(duplicated_driver.as_bytes()).unwrap_err(),
        Error::Invalid
    );
}

#[test]
fn optional_driver_and_required_predecessor_array() {
    let mut m: Manifest = serde_json::from_slice(RAW).unwrap();
    m.driver = None;
    m.rollback_predecessors.clear();
    let raw = serde_json::to_vec(&m).unwrap();
    assert!(signed(&raw).is_ok());
    let raw = std::str::from_utf8(&raw).unwrap().replace(
        r#""rollback_predecessors":[]"#,
        r#""rollback_predecessors":null"#,
    );
    assert_eq!(signed(raw.as_bytes()).unwrap_err(), Error::Invalid);
}

#[test]
fn ambiguous_rollback_predecessors_fail() {
    let mut m: Manifest = serde_json::from_slice(RAW).unwrap();
    let p = m.rollback_predecessors[0].clone();
    m.rollback_predecessors.push(p.clone());
    m.rollback_predecessors[1].manifest_sha256 = "2".repeat(64);
    assert_eq!(
        signed(&serde_json::to_vec(&m).unwrap()).unwrap_err(),
        Error::Invalid
    );
    m.rollback_predecessors[1] = p;
    m.rollback_predecessors[1].target_id = "another-target".to_owned();
    assert_eq!(
        signed(&serde_json::to_vec(&m).unwrap()).unwrap_err(),
        Error::Invalid
    );
}
