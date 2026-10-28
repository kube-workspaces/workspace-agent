//! Shared Go-issued public certificate profile fixtures. These are not live
//! credentials; there are no private keys and no trust/handshake implementation.

use base64::{engine::general_purpose::STANDARD, Engine};
use kw_management::certificate::{parse_leaf_profile, InvalidCertificate, MAX_LEAF_DER_BYTES};
use serde::Deserialize;
use x509_cert::der::{asn1::BitString, Decode, Encode};
use x509_cert::Certificate;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    now: u64,
    root_der: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    der: String,
    #[serde(default)]
    uri: String,
    valid: bool,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../fixtures/management-pki-certificates-v1.json"
    ))
    .unwrap()
}

#[test]
fn shared_go_rust_leaf_profile_vectors() {
    let vectors = vectors();
    assert_eq!(
        parse_leaf_profile(&STANDARD.decode(vectors.root_der).unwrap()),
        Err(InvalidCertificate)
    );
    for case in vectors.cases {
        let der = STANDARD.decode(&case.der).unwrap();
        let profile = parse_leaf_profile(&der);
        assert_eq!(profile.is_ok(), case.valid, "{}: {profile:?}", case.name);
        if case.valid {
            let profile = profile.unwrap();
            assert_eq!(profile.identity.to_uri().unwrap(), case.uri);
            assert_eq!(profile.check_time(vectors.now), Ok(()));
            assert_eq!(profile.check_time(profile.not_before), Ok(()));
            assert_eq!(
                profile.check_time(profile.not_before - 1),
                Err(InvalidCertificate)
            );
            assert_eq!(
                profile.check_time(profile.not_after),
                Err(InvalidCertificate)
            );
            assert_eq!(profile.check_time(u64::MAX), Err(InvalidCertificate));
        }
    }
}

#[test]
fn malformed_oversized_and_duplicate_extension_inputs_deny() {
    assert_eq!(parse_leaf_profile(&[]), Err(InvalidCertificate));
    assert_eq!(
        parse_leaf_profile(&vec![0; MAX_LEAF_DER_BYTES + 1]),
        Err(InvalidCertificate)
    );
    let vectors = vectors();
    let der = STANDARD.decode(&vectors.cases[0].der).unwrap();
    for length in 0..der.len() {
        assert_eq!(parse_leaf_profile(&der[..length]), Err(InvalidCertificate));
    }
    let mut trailing = der.clone();
    trailing.push(0);
    assert_eq!(parse_leaf_profile(&trailing), Err(InvalidCertificate));
    let mut cert = Certificate::from_der(&der).unwrap();
    let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
    extensions.push(extensions[0].clone());
    assert_eq!(
        parse_leaf_profile(&cert.to_der().unwrap()),
        Err(InvalidCertificate)
    );
    let err = parse_leaf_profile(b"private-certificate-marker").unwrap_err();
    assert!(!format!("{err:?} {err}").contains("private-certificate-marker"));
}

#[test]
fn profile_inspection_does_not_establish_signature_trust() {
    let vectors = vectors();
    let der = STANDARD.decode(&vectors.cases[0].der).unwrap();
    let original = parse_leaf_profile(&der).unwrap();
    let mut cert = Certificate::from_der(&der).unwrap();
    let mut signature = cert.signature.as_bytes().unwrap().to_vec();
    signature[0] ^= 1;
    cert.signature = BitString::from_bytes(&signature).unwrap();
    let corrupted = cert.to_der().unwrap();
    assert_ne!(corrupted, der);
    // A TLS/chain verifier MUST reject this signature. A profile parser cannot
    // grant authority simply because the untrusted fields still match.
    assert_eq!(parse_leaf_profile(&corrupted).unwrap(), original);
}

#[test]
fn single_byte_mutations_never_escape_profile_invariants() {
    let vectors = vectors();
    for case in vectors.cases.iter().filter(|case| case.valid) {
        let der = STANDARD.decode(&case.der).unwrap();
        for index in 0..der.len() {
            for mask in [1, 0xff] {
                let mut mutated = der.clone();
                mutated[index] ^= mask;
                if let Ok(profile) = parse_leaf_profile(&mutated) {
                    let uri = profile.identity.to_uri().unwrap();
                    assert_eq!(
                        kw_management::identity::Identity::from_uri(&uri).unwrap(),
                        profile.identity
                    );
                    assert!(profile.not_after > profile.not_before);
                    assert!(profile.not_after - profile.not_before <= 3630);
                }
            }
        }
    }
}
