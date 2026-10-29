use base64::{engine::general_purpose::STANDARD, Engine};
use kw_management::certificate::parse_leaf_profile;
use kw_management::identity::Identity;
use kw_management::trust::{InvalidChain, TrustStore};
use serde::Deserialize;
use std::time::{Duration, UNIX_EPOCH};
use x509_cert::der::{
    asn1::{BitString, ObjectIdentifier, OctetString},
    Decode, Encode,
};
use x509_cert::ext::{
    pkix::{BasicConstraints, ExtendedKeyUsage},
    Extension,
};
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
    #[serde(default)]
    intermediates: Vec<String>,
    #[serde(default)]
    chain_valid: Option<bool>,
}
fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../fixtures/management-pki-certificates-v1.json"
    ))
    .unwrap()
}
fn decode(data: &str) -> Vec<u8> {
    STANDARD.decode(data).unwrap()
}
fn chain(case: &Case) -> Vec<Vec<u8>> {
    case.intermediates.iter().map(|der| decode(der)).collect()
}
fn api() -> Identity {
    Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/apis/api-1").unwrap()
}
fn guest() -> Identity {
    Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid-1/gen-2/3")
        .unwrap()
}
fn corrupt_signature(der: &[u8]) -> Vec<u8> {
    let mut cert = Certificate::from_der(der).unwrap();
    let mut signature = cert.signature.as_bytes().unwrap().to_vec();
    signature[0] ^= 1;
    cert.signature = BitString::from_bytes(&signature).unwrap();
    cert.to_der().unwrap()
}

#[test]
fn shared_go_issued_direct_and_intermediate_chains() {
    let vectors = vectors();
    let store = TrustStore::new(&[decode(&vectors.root_der)]).unwrap();
    for case in &vectors.cases {
        let expected = if case.valid {
            Identity::from_uri(&case.uri).unwrap()
        } else if case.name.ends_with("-guest") {
            guest()
        } else {
            api()
        };
        let result =
            store.verify_certificate(&decode(&case.der), &chain(case), &expected, vectors.now);
        let valid_chain = case.chain_valid.unwrap_or(case.valid);
        assert_eq!(result.is_ok(), valid_chain, "{}: {result:?}", case.name);
        if valid_chain {
            let der = decode(&case.der);
            assert_eq!(
                store.verify_certificate(
                    &corrupt_signature(&der),
                    &chain(case),
                    &expected,
                    vectors.now
                ),
                Err(InvalidChain)
            );
            // A correctly signed but differently bound certificate is not the
            // expected peer. Roles cannot be substituted either.
            let wrong_role = if expected == api() { guest() } else { api() };
            assert_eq!(
                store.verify_certificate(&der, &chain(case), &wrong_role, vectors.now),
                Err(InvalidChain)
            );
            if !case.intermediates.is_empty() {
                assert_eq!(
                    store.verify_certificate(&der, &[], &expected, vectors.now),
                    Err(InvalidChain)
                );
                let mut bad_chain = chain(case);
                bad_chain[0] = corrupt_signature(&bad_chain[0]);
                assert_eq!(
                    store.verify_certificate(&der, &bad_chain, &expected, vectors.now),
                    Err(InvalidChain)
                );
            }
        }
    }
}

#[test]
fn exact_guest_generation_epoch_and_time_are_required() {
    let vectors = vectors();
    let store = TrustStore::new(&[decode(&vectors.root_der)]).unwrap();
    let case = vectors
        .cases
        .iter()
        .find(|c| c.name == "valid-guest")
        .unwrap();
    let der = decode(&case.der);
    for uri in [
        "spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid-1/gen-3/3",
        "spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid-1/gen-2/4",
        "spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid-2/gen-2/3",
    ] {
        assert_eq!(
            store.verify_certificate(&der, &[], &Identity::from_uri(uri).unwrap(), vectors.now),
            Err(InvalidChain)
        );
    }
    let profile = parse_leaf_profile(&der).unwrap();
    assert_eq!(
        store.verify_certificate(&der, &[], &guest(), profile.not_before - 1),
        Err(InvalidChain)
    );
    assert_eq!(
        store.verify_certificate(&der, &[], &guest(), profile.not_after),
        Err(InvalidChain)
    );
}

#[test]
fn trust_roots_are_explicit_bounded_and_time_filtered() {
    let vectors = vectors();
    let root = decode(&vectors.root_der);
    let case = vectors
        .cases
        .iter()
        .find(|c| c.name == "valid-api")
        .unwrap();
    let leaf = decode(&case.der);
    assert!(TrustStore::new(&[]).is_err());
    assert!(TrustStore::new(&vec![root.clone(); 17]).is_err());
    assert!(TrustStore::new(std::slice::from_ref(&leaf)).is_err());
    assert!(TrustStore::new(&[vec![0; 65537]]).is_err());
    let mut expired = Certificate::from_der(&root).unwrap();
    expired.tbs_certificate.validity.not_after = (UNIX_EPOCH + Duration::from_secs(vectors.now))
        .try_into()
        .unwrap();
    let expired = expired.to_der().unwrap();
    let store = TrustStore::new(std::slice::from_ref(&expired)).unwrap();
    assert_eq!(
        store.verify_certificate(&leaf, &[], &api(), vectors.now),
        Err(InvalidChain)
    );
    let overlap = TrustStore::new(&[expired, root.clone()]).unwrap();
    assert_eq!(
        overlap.verify_certificate(&leaf, &[], &api(), vectors.now),
        Ok(())
    );
    let mut future = Certificate::from_der(&root).unwrap();
    future.tbs_certificate.validity.not_before = (UNIX_EPOCH
        + Duration::from_secs(vectors.now + 1))
    .try_into()
    .unwrap();
    let store = TrustStore::new(&[future.to_der().unwrap()]).unwrap();
    assert_eq!(
        store.verify_certificate(&leaf, &[], &api(), vectors.now),
        Err(InvalidChain)
    );
    // Changing a configured anchor's public key cannot trust a foreign signer.
    let mut foreign = Certificate::from_der(&root).unwrap();
    foreign.tbs_certificate.subject_public_key_info = Certificate::from_der(&leaf)
        .unwrap()
        .tbs_certificate
        .subject_public_key_info;
    let store = TrustStore::new(&[foreign.to_der().unwrap()]).unwrap();
    assert_eq!(
        store.verify_certificate(&leaf, &[], &api(), vectors.now),
        Err(InvalidChain)
    );
    assert_eq!(format!("{store:?}"), "management certificate trust store");
}

#[test]
fn configured_root_purpose_and_path_limits_are_not_discarded() {
    let vectors = vectors();
    let root = decode(&vectors.root_der);
    let mut restricted = Certificate::from_der(&root).unwrap();
    let eku = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")]);
    restricted
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(Extension {
            extn_id: ObjectIdentifier::new_unwrap("2.5.29.37"),
            critical: false,
            extn_value: OctetString::new(eku.to_der().unwrap()).unwrap(),
        });
    let store = TrustStore::new(&[restricted.to_der().unwrap()]).unwrap();
    let api_case = vectors
        .cases
        .iter()
        .find(|c| c.name == "valid-api")
        .unwrap();
    let guest_case = vectors
        .cases
        .iter()
        .find(|c| c.name == "valid-guest")
        .unwrap();
    assert_eq!(
        store.verify_certificate(&decode(&api_case.der), &[], &api(), vectors.now),
        Err(InvalidChain)
    );
    assert_eq!(
        store.verify_certificate(&decode(&guest_case.der), &[], &guest(), vectors.now),
        Ok(())
    );
    let mut restricted = Certificate::from_der(&root).unwrap();
    let constraints = BasicConstraints {
        ca: true,
        path_len_constraint: Some(0),
    };
    restricted
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19"))
        .unwrap()
        .extn_value = OctetString::new(constraints.to_der().unwrap()).unwrap();
    let store = TrustStore::new(&[restricted.to_der().unwrap()]).unwrap();
    assert_eq!(
        store.verify_certificate(&decode(&api_case.der), &[], &api(), vectors.now),
        Ok(())
    );
    let indirect = vectors
        .cases
        .iter()
        .find(|c| c.name == "valid-intermediate-api")
        .unwrap();
    assert_eq!(
        store.verify_certificate(
            &decode(&indirect.der),
            &chain(indirect),
            &api(),
            vectors.now
        ),
        Err(InvalidChain)
    );
}

#[test]
fn malformed_chains_and_unknown_root_constraints_fail_closed() {
    let vectors = vectors();
    let root = decode(&vectors.root_der);
    let store = TrustStore::new(std::slice::from_ref(&root)).unwrap();
    let case = vectors
        .cases
        .iter()
        .find(|c| c.name == "valid-api")
        .unwrap();
    let leaf = decode(&case.der);
    for chain in [
        vec![root.clone(); 9],
        vec![vec![0; 65537]],
        vec![b"private-chain-marker".to_vec()],
    ] {
        assert_eq!(
            store.verify_certificate(&leaf, &chain, &api(), vectors.now),
            Err(InvalidChain)
        );
    }
    let mut duplicate = Certificate::from_der(&root).unwrap();
    let extensions = duplicate.tbs_certificate.extensions.as_mut().unwrap();
    extensions.push(extensions[0].clone());
    assert!(TrustStore::new(&[duplicate.to_der().unwrap()]).is_err());
    let mut unknown = Certificate::from_der(&root).unwrap();
    unknown
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.2.3.4"),
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0]).unwrap(),
        });
    assert!(TrustStore::new(&[unknown.to_der().unwrap()]).is_err());
    let err = store
        .verify_certificate(b"private-chain-marker", &[], &api(), vectors.now)
        .unwrap_err();
    assert!(!format!("{err:?} {err}").contains("private-chain-marker"));
}
