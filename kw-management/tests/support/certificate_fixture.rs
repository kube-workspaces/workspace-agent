use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{Duration, SystemTime};
use x509_cert::{
    der::{
        asn1::{BitString, Ia5String, ObjectIdentifier, OctetString},
        Decode, Encode,
    },
    ext::pkix::{name::GeneralName, SubjectAltName},
    request::CertReq,
    Certificate,
};

// Fresh synthetic CA signs only the public CSR. No guest key extraction and no
// deployed issuer/identity. Shared by integration and durability fault tests.
pub fn issue(csr: &[u8], guest_uri: &str, issued_at: SystemTime) -> (Vec<u8>, Vec<u8>) {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../fixtures/management-pki-certificates-v1.json"
    ))
    .unwrap();
    let mut issuer = Certificate::from_der(
        &STANDARD
            .decode(vectors["root_der"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let leaf_der = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid-guest")
        .unwrap()["der"]
        .as_str()
        .unwrap();
    let mut leaf = Certificate::from_der(&STANDARD.decode(leaf_der).unwrap()).unwrap();
    let mut seed = [0; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let signer = SigningKey::from_bytes(&seed);
    issuer.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.3.101.112");
    issuer.signature_algorithm.parameters = None;
    issuer.tbs_certificate.subject_public_key_info.algorithm = issuer.signature_algorithm.clone();
    issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key = BitString::from_bytes(signer.verifying_key().as_bytes()).unwrap();
    leaf.signature_algorithm = issuer.signature_algorithm.clone();
    leaf.tbs_certificate.subject_public_key_info = CertReq::from_der(csr).unwrap().info.public_key;
    let san = SubjectAltName(vec![
        GeneralName::UniformResourceIdentifier(Ia5String::new(guest_uri).unwrap()),
        GeneralName::DnsName(Ia5String::new("management.workspace.internal").unwrap()),
    ]);
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.17"))
        .unwrap()
        .extn_value = OctetString::new(san.to_der().unwrap()).unwrap();
    let sign = |cert: &mut Certificate, lifetime| {
        cert.tbs_certificate.signature = cert.signature_algorithm.clone();
        cert.tbs_certificate.validity.not_before =
            (issued_at - Duration::from_secs(30)).try_into().unwrap();
        cert.tbs_certificate.validity.not_after = (issued_at + Duration::from_secs(lifetime))
            .try_into()
            .unwrap();
        cert.signature = BitString::from_bytes(
            &signer
                .sign(&cert.tbs_certificate.to_der().unwrap())
                .to_bytes(),
        )
        .unwrap();
        cert.to_der().unwrap()
    };
    (sign(&mut issuer, 86400), sign(&mut leaf, 600))
}
