use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use kw_management::updates::inventory::{
    self, Error, Inventory, INVENTORY_DOMAIN, INVENTORY_FRESH_SECONDS, MAX_INVENTORY_BYTES,
    MAX_INVENTORY_MSI,
};
use kw_management::updates::{digest, DOMAIN};
use serde::Deserialize;
use std::collections::HashMap;

const RAW: &[u8] = include_bytes!("testdata/inventory-v1.json");
const START: i64 = 1700000060;

type Case<'a> = (
    &'a str,
    &'a [u8],
    &'a [u8],
    &'a str,
    &'a HashMap<String, [u8; 32]>,
    Error,
);
type Mutation = (&'static str, Box<dyn Fn(&mut Inventory)>);

#[derive(Deserialize)]
struct Vector {
    key_id: String,
    inventory_sha256: String,
    public_key: String,
    signature: String,
}

fn vector() -> Vector {
    serde_json::from_slice(include_bytes!("testdata/inventory-v1-signature.json")).unwrap()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x5A; 32])
}

fn foreign_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

fn keys(vector: &Vector) -> HashMap<String, [u8; 32]> {
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&vector.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    HashMap::from([(vector.key_id.clone(), public)])
}

fn nonce() -> String {
    serde_json::from_slice::<Inventory>(RAW).unwrap().nonce
}

fn verify_with(
    raw: &[u8],
    signature: &[u8],
    now: i64,
) -> Result<inventory::VerifiedInventory, Error> {
    let vector = vector();
    inventory::verify(
        raw,
        signature,
        &vector.key_id,
        &nonce(),
        now,
        &keys(&vector),
    )
}

fn sign_bytes(raw: &[u8]) -> [u8; 64] {
    let mut message = INVENTORY_DOMAIN.to_vec();
    message.extend_from_slice(raw);
    key().sign(&message).to_bytes()
}

fn key_id_hex(public: &[u8; 32]) -> String {
    digest(public)[..32].to_owned()
}

fn inject(raw: &[u8], field: &str) -> Vec<u8> {
    let mut text = String::from_utf8(raw.to_vec()).unwrap();
    text.replace_range(0..1, &format!("{{{field}"));
    text.into_bytes()
}

fn replace_field(raw: &[u8], find: &[u8], with: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(raw.to_vec()).unwrap();
    let found = String::from_utf8(find.to_vec()).unwrap();
    assert!(text.contains(&found), "fixture drifted: {found}");
    text.replace(&found, core::str::from_utf8(with).unwrap())
        .into_bytes()
}

#[test]
fn signed_fixture_round_trip_and_freshness() {
    let vector = vector();
    let signature = URL_SAFE_NO_PAD.decode(&vector.signature).unwrap();
    let v = verify_with(RAW, &signature, START).unwrap();
    assert_eq!(v.sha256(), vector.inventory_sha256);
    assert_eq!(v.sha256(), digest(RAW));
    assert_eq!(v.metadata().namespace, "team-a");
    assert_eq!(v.metadata().attempt.as_ref().unwrap().phase, "active");
    assert_eq!(v.metadata().encode(), RAW);

    let parsed: Inventory = serde_json::from_slice(RAW).unwrap();
    let produced = inventory::sign(&parsed, &key());
    assert_eq!(produced.key_id, vector.key_id);
    assert_eq!(produced.inventory_sha256, vector.inventory_sha256);
    assert_eq!(URL_SAFE_NO_PAD.encode(produced.signature), vector.signature);

    for (now, fresh) in [
        (START + INVENTORY_FRESH_SECONDS, true),
        (START - 1, false),
        (START + INVENTORY_FRESH_SECONDS + 1, false),
        (START - INVENTORY_FRESH_SECONDS - 1, false),
    ] {
        assert_eq!(
            verify_with(RAW, &signature, now).is_ok(),
            fresh,
            "freshness misclassified at {now}"
        );
    }
    assert!(matches!(
        inventory::verify(RAW, &signature, &vector.key_id, "", START, &keys(&vector)),
        Err(Error::Fresh)
    ));
    let foreign = URL_SAFE_NO_PAD.encode([0x49 ^ 1; 32]);
    assert!(matches!(
        inventory::verify(
            RAW,
            &signature,
            &vector.key_id,
            &foreign,
            START,
            &keys(&vector)
        ),
        Err(Error::Fresh)
    ));

    let bare = {
        let mut inventory = parsed;
        inventory.driver = None;
        inventory.attempt = None;
        inventory
    };
    let encoded = String::from_utf8(bare.encode()).unwrap();
    assert!(encoded.contains(r#","driver":null"#));
    assert!(encoded.contains(r#","attempt":null"#));
}

#[test]
fn rejects_untrusted_tampered_and_non_canonical_bodies() {
    let vector = vector();
    let signature = URL_SAFE_NO_PAD.decode(&vector.signature).unwrap();
    let nonce = nonce();

    let mut flipped = signature.clone();
    flipped[0] ^= 1;
    let foreign_public = foreign_key().verifying_key().to_bytes();
    let mut mismatched = keys(&vector);
    mismatched.insert(key_id_hex(&foreign_public), [0x11; 32]);

    let other_signature = inventory::sign(
        &serde_json::from_slice::<Inventory>(RAW).unwrap(),
        &foreign_key(),
    );
    let mut manifest_message = DOMAIN.to_vec();
    manifest_message.extend_from_slice(RAW);
    let manifest_signature = key().sign(&manifest_message).to_bytes();

    let trailing = [RAW, b"{}"].concat();
    let trailing_signed = sign_bytes(&trailing);
    let spaced = [RAW, b" "].concat();
    let spaced_signed = sign_bytes(&spaced);
    let unknown = inject(RAW, r#""bogus":1,"#);
    let unknown_signed = sign_bytes(&unknown);
    let duplicate = inject(RAW, r#""version":1,"#);
    let duplicate_signed = sign_bytes(&duplicate);
    let missing = replace_field(RAW, b"\"timestamp\":1700000060,", b"");
    let missing_signed = sign_bytes(&missing);
    let null_scalar = replace_field(RAW, b"\"pending_reboot\":false", b"\"pending_reboot\":null");
    let null_scalar_signed = sign_bytes(&null_scalar);
    let case_variant = replace_field(RAW, b"\"version\":1", b"\"Version\":1");
    let case_variant_signed = sign_bytes(&case_variant);
    let oversize = vec![b' '; MAX_INVENTORY_BYTES + 1];
    let invalid_utf8 = [RAW[..RAW.len() - 1].as_ref(), &[0xff]].concat();

    let ring = keys(&vector);
    let empty = HashMap::new();
    let foreign_id = key_id_hex(&foreign_public);
    let cases: Vec<Case<'_>> = vec![
        (
            "flipped signature",
            RAW,
            &flipped,
            &vector.key_id,
            &ring,
            Error::Signature,
        ),
        (
            "signature from a different key",
            RAW,
            &other_signature.signature,
            &vector.key_id,
            &ring,
            Error::Signature,
        ),
        (
            "manifest domain framing",
            RAW,
            &manifest_signature,
            &vector.key_id,
            &ring,
            Error::Signature,
        ),
        (
            "unknown key id",
            RAW,
            &signature,
            &foreign_id,
            &ring,
            Error::Untrusted,
        ),
        (
            "empty keyring",
            RAW,
            &signature,
            &vector.key_id,
            &empty,
            Error::Untrusted,
        ),
        (
            "mismatched keyring entry",
            RAW,
            &signature,
            &vector.key_id,
            &mismatched,
            Error::Untrusted,
        ),
        (
            "oversized body",
            &oversize,
            &signature,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "invalid utf-8",
            &invalid_utf8,
            &signature,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "trailing json",
            &trailing,
            &trailing_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "trailing whitespace",
            &spaced,
            &spaced_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "unknown field",
            &unknown,
            &unknown_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "duplicate field",
            &duplicate,
            &duplicate_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "missing field",
            &missing,
            &missing_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "null scalar",
            &null_scalar,
            &null_scalar_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
        (
            "case-variant field",
            &case_variant,
            &case_variant_signed,
            &vector.key_id,
            &ring,
            Error::Invalid,
        ),
    ];
    for (name, raw, sig, id, ring, want) in cases {
        assert_eq!(
            inventory::verify(raw, sig, id, &nonce, START, ring).unwrap_err(),
            want,
            "{name}"
        );
    }
}

#[test]
fn rejects_schema_violations() {
    let base: Inventory = serde_json::from_slice(RAW).unwrap();
    let mutations: Vec<Mutation> = vec![
        ("unsupported schema", Box::new(|i| i.version = 2)),
        (
            "foreign architecture",
            Box::new(|i| i.architecture = "arm64".into()),
        ),
        (
            "short agent version",
            Box::new(|i| i.agent_version = "0.3".into()),
        ),
        (
            "leading-zero version",
            Box::new(|i| i.agent_version = "01.3.5".into()),
        ),
        (
            "uppercase build digest",
            Box::new(|i| i.build_sha256 = i.build_sha256.to_uppercase()),
        ),
        ("management range", Box::new(|i| i.management_max = 65)),
        ("inverted updater range", Box::new(|i| i.updater_min = 2)),
        (
            "epoch above int64",
            Box::new(|i| i.revocation_epoch = i64::MAX as u64 + 1),
        ),
        ("empty msi list", Box::new(|i| i.msi.clear())),
        (
            "unbounded msi list",
            Box::new(|i| {
                let first = i.msi[0].clone();
                while i.msi.len() <= MAX_INVENTORY_MSI {
                    i.msi.push(first.clone());
                }
            }),
        ),
        (
            "two agent registrations",
            Box::new(|i| i.msi[1].upgrade_code = kw_management::updates::AGENT_UPGRADE_CODE.into()),
        ),
        (
            "duplicate product code",
            Box::new(|i| i.msi[1].product_code = i.msi[0].product_code.clone()),
        ),
        (
            "nil product code",
            Box::new(|i| i.msi[0].product_code = "00000000-0000-0000-0000-000000000000".into()),
        ),
        (
            "product equals upgrade",
            Box::new(|i| i.msi[1].product_code = i.msi[1].upgrade_code.clone()),
        ),
        (
            "bad msi version",
            Box::new(|i| i.msi[1].version = "1.4".into()),
        ),
        (
            "empty install directory",
            Box::new(|i| i.msi[0].install_directory.clear()),
        ),
        (
            "control byte in path",
            Box::new(|i| i.msi[0].install_directory = "C:\\Apps\u{1}Bad".into()),
        ),
        (
            "non-ascii path",
            Box::new(|i| i.msi[0].install_directory = "C:\\Apps\\café".into()),
        ),
        (
            "bad package identity",
            Box::new(|i| i.driver.as_mut().unwrap().package_identity = "bad identity".into()),
        ),
        (
            "bad package digest",
            Box::new(|i| i.driver.as_mut().unwrap().package_sha256 = "xyz".into()),
        ),
        (
            "non-inf published name",
            Box::new(|i| i.driver.as_mut().unwrap().inf_name = "idd.dll".into()),
        ),
        (
            "device without separator",
            Box::new(|i| i.driver.as_mut().unwrap().device_instance = "ROOT-IDD-0000".into()),
        ),
        (
            "three-part driver version",
            Box::new(|i| i.driver.as_mut().unwrap().driver_version = "25.7.23".into()),
        ),
        (
            "unknown attempt phase",
            Box::new(|i| i.attempt.as_mut().unwrap().phase = "installing".into()),
        ),
        (
            "attempt sequence bound",
            Box::new(|i| {
                i.attempt.as_mut().unwrap().sequence =
                    kw_management::updates::journal::MAX_JOURNAL_SEQUENCE + 1
            }),
        ),
        (
            "uppercase attempt id",
            Box::new(|i| i.attempt.as_mut().unwrap().attempt_id = "UPD-1".into()),
        ),
        ("malformed nonce", Box::new(|i| i.nonce = "short".into())),
        ("zero timestamp", Box::new(|i| i.timestamp = 0)),
        (
            "uppercase namespace",
            Box::new(|i| i.namespace = "Team".into()),
        ),
    ];
    for (name, mutate) in mutations {
        let mut inventory = base.clone();
        mutate(&mut inventory);
        let raw = inventory.encode();
        let produced = inventory::sign(&inventory, &key());
        let ring = HashMap::from([(produced.key_id.clone(), key().verifying_key().to_bytes())]);
        let error = inventory::verify(
            &raw,
            &produced.signature,
            &produced.key_id,
            &inventory.nonce,
            inventory.timestamp,
            &ring,
        )
        .unwrap_err();
        assert_eq!(error, Error::Invalid, "{name}");
    }
}
