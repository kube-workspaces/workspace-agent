use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use kw_management::{
    identity::Identity,
    tls::{Authorize, Pending, Server, TlsDenied, ALPN},
    trust::TrustStore,
};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::io::{Cursor, Read};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};
use x509_cert::{
    der::{
        asn1::{BitString, ObjectIdentifier},
        Decode, Encode,
    },
    Certificate,
};

struct Material {
    root: Vec<u8>,
    guest: Vec<u8>,
    guest_key: Vec<u8>,
    api: Vec<u8>,
    api_key: Vec<u8>,
}
fn guest() -> Identity {
    Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid-1/gen-2/3")
        .unwrap()
}
fn api() -> Identity {
    Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/apis/api-1").unwrap()
}
fn key() -> SigningKey {
    let mut seed = [0; 32];
    getrandom::getrandom(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}
fn private_der(key: &SigningKey) -> Vec<u8> {
    // Test-only RFC 8410 PKCS#8 encoding. No fixture contains private keys.
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&key.to_bytes());
    der
}
fn signed(mut cert: Certificate, key: &SigningKey, issuer: &SigningKey, lifetime: u64) -> Vec<u8> {
    let oid = ObjectIdentifier::new_unwrap("1.3.101.112");
    cert.signature_algorithm.oid = oid;
    cert.signature_algorithm.parameters = None;
    cert.tbs_certificate.signature = cert.signature_algorithm.clone();
    cert.tbs_certificate.subject_public_key_info.algorithm = cert.signature_algorithm.clone();
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key = BitString::from_bytes(key.verifying_key().as_bytes()).unwrap();
    cert.tbs_certificate.validity.not_before = (SystemTime::now() - Duration::from_secs(30))
        .try_into()
        .unwrap();
    cert.tbs_certificate.validity.not_after = (SystemTime::now() + Duration::from_secs(lifetime))
        .try_into()
        .unwrap();
    cert.signature = BitString::from_bytes(
        &issuer
            .sign(&cert.tbs_certificate.to_der().unwrap())
            .to_bytes(),
    )
    .unwrap();
    cert.to_der().unwrap()
}
fn material() -> Material {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/management-pki-certificates-v1.json"
    ))
    .unwrap();
    let template = |name: &str| {
        let der = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()["der"]
            .as_str()
            .unwrap();
        Certificate::from_der(&STANDARD.decode(der).unwrap()).unwrap()
    };
    let root = Certificate::from_der(
        &STANDARD
            .decode(vectors["root_der"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let root_key = key();
    let guest_key = key();
    let api_key = key();
    Material {
        root: signed(root, &root_key, &root_key, 86400),
        guest: signed(template("valid-guest"), &guest_key, &root_key, 600),
        guest_key: private_der(&guest_key),
        api: signed(template("valid-api"), &api_key, &root_key, 600),
        api_key: private_der(&api_key),
    }
}
fn server(m: &Material, authorize: Arc<Authorize>) -> Server {
    Server::new(
        Arc::new(TrustStore::new(std::slice::from_ref(&m.root)).unwrap()),
        guest(),
        vec![m.guest.clone()],
        m.guest_key.clone(),
        authorize,
    )
    .unwrap()
}
fn client(m: &Material, identity: Option<(&[u8], &[u8])>, alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(m.root.clone())).unwrap();
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
    let mut config = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn;
    config.enable_early_data = true;
    Arc::new(config)
}
fn exchange(
    config: Arc<ClientConfig>,
    mut pending: Pending,
) -> Result<(ClientConnection, Pending), TlsDenied> {
    let mut client = ClientConnection::new(
        config,
        ServerName::try_from("management.workspace.internal").unwrap(),
    )
    .map_err(|_| TlsDenied)?;
    for _ in 0..64 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).map_err(|_| TlsDenied)?;
        if !wire.is_empty() {
            pending
                .read_tls(&mut Cursor::new(wire))
                .map_err(|_| TlsDenied)?;
            pending.process_new_packets()?;
        }
        let mut wire = Vec::new();
        if pending.wants_write() {
            pending.write_tls(&mut wire).map_err(|_| TlsDenied)?;
        }
        if !wire.is_empty() {
            client
                .read_tls(&mut Cursor::new(wire))
                .map_err(|_| TlsDenied)?;
            client.process_new_packets().map_err(|_| TlsDenied)?;
        }
        if !client.is_handshaking()
            && !pending.is_handshaking()
            && !client.wants_write()
            && !pending.wants_write()
        {
            return Ok((client, pending));
        }
    }
    Err(TlsDenied)
}

#[test]
fn full_handshake_binds_peer_fingerprint_and_never_resumes() {
    let m = material();
    let checks = Arc::new(AtomicUsize::new(0));
    let count = checks.clone();
    let s = server(
        &m,
        Arc::new(move |local, peer| {
            assert_eq!(local, &guest());
            assert_eq!(peer, &api());
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );
    let c = client(&m, Some((&m.api, &m.api_key)), vec![ALPN.to_vec()]);
    for _ in 0..2 {
        let (mut client, pending) = exchange(c.clone(), s.connection().unwrap()).unwrap();
        assert!(matches!(
            client.handshake_kind(),
            Some(rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest)
        ));
        assert!(client.early_data().is_none());
        let mut connection = pending.finish().unwrap();
        assert_eq!(connection.peer().identity(), &api());
        assert_eq!(
            connection.peer().certificate_sha256(),
            kw_management::digest(&m.api)
        );
        connection
            .write_plaintext(b"recorded transport fixture")
            .unwrap();
        let mut wire = Vec::new();
        connection.write_tls(&mut wire).unwrap();
        client.read_tls(&mut Cursor::new(wire)).unwrap();
        client.process_new_packets().unwrap();
        let mut data = [0; 26];
        client.reader().read_exact(&mut data).unwrap();
        assert_eq!(&data, b"recorded transport fixture");
    }
    assert!(checks.load(Ordering::SeqCst) >= 4);
}

#[test]
fn missing_foreign_wrong_purpose_and_wrong_alpn_clients_deny() {
    let m = material();
    let foreign = material();
    let s = server(&m, Arc::new(|_, _| Ok(())));
    for config in [
        client(&m, None, vec![ALPN.to_vec()]),
        client(
            &m,
            Some((&foreign.api, &foreign.api_key)),
            vec![ALPN.to_vec()],
        ),
        client(&m, Some((&m.guest, &m.guest_key)), vec![ALPN.to_vec()]),
        client(
            &m,
            Some((&m.api, &m.api_key)),
            vec![b"desktop-protocol".to_vec()],
        ),
    ] {
        assert!(exchange(config, s.connection().unwrap()).is_err());
    }
    // TLS itself permits a peer to omit ALPN: finish must still reject it.
    let (_, pending) = exchange(
        client(&m, Some((&m.api, &m.api_key)), vec![]),
        s.connection().unwrap(),
    )
    .unwrap();
    assert!(pending.finish().is_err());
}

#[test]
fn authorization_is_fresh_after_handshake_and_denial_poison_is_permanent() {
    let m = material();
    let allowed = Arc::new(AtomicBool::new(true));
    let current = allowed.clone();
    let s = server(
        &m,
        Arc::new(move |_, _| {
            if current.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(TlsDenied)
            }
        }),
    );
    let config = client(&m, Some((&m.api, &m.api_key)), vec![ALPN.to_vec()]);
    let (_, pending) = exchange(config.clone(), s.connection().unwrap()).unwrap();
    allowed.store(false, Ordering::SeqCst);
    assert!(pending.finish().is_err());
    allowed.store(true, Ordering::SeqCst);
    let (_, pending) = exchange(config, s.connection().unwrap()).unwrap();
    let mut active = pending.finish().unwrap();
    allowed.store(false, Ordering::SeqCst);
    assert_eq!(active.reauthorize(), Err(TlsDenied));
    allowed.store(true, Ordering::SeqCst);
    assert_eq!(active.reauthorize(), Err(TlsDenied));
    assert!(active.write_plaintext(b"must not send").is_err());
    assert!(active.read_plaintext(&mut [0; 1]).is_err());
    assert!(!active.wants_read() && !active.wants_write());
    let deny = server(&m, Arc::new(|_, _| Err(TlsDenied)));
    assert!(exchange(
        client(&m, Some((&m.api, &m.api_key)), vec![ALPN.to_vec()]),
        deny.connection().unwrap()
    )
    .is_err());
}

#[test]
fn invalid_local_credentials_and_incomplete_or_failed_sessions_have_no_peer() {
    let m = material();
    let trust = Arc::new(TrustStore::new(std::slice::from_ref(&m.root)).unwrap());
    for (enrolled, chain, key) in [
        (api(), vec![m.guest.clone()], m.guest_key.clone()),
        (guest(), vec![m.api.clone()], m.api_key.clone()),
        (guest(), vec![m.guest.clone()], m.api_key.clone()),
        (guest(), vec![], m.guest_key.clone()),
    ] {
        assert!(Server::new(trust.clone(), enrolled, chain, key, Arc::new(|_, _| Ok(()))).is_err());
    }
    let s = server(&m, Arc::new(|_, _| Ok(())));
    assert!(s.connection().unwrap().finish().is_err());
    let (_, mut pending) = exchange(
        client(&m, Some((&m.api, &m.api_key)), vec![ALPN.to_vec()]),
        s.connection().unwrap(),
    )
    .unwrap();
    // A fatal record after Finished must not permit minting connection evidence.
    pending
        .read_tls(&mut Cursor::new(vec![0x17, 0x03, 0x03, 0, 1, 0]))
        .unwrap();
    assert!(pending.process_new_packets().is_err());
    assert!(pending.finish().is_err());
    assert_eq!(
        format!("{s:?}"),
        "management TLS server (credentials redacted)"
    );
}

#[test]
fn transport_errors_are_redacted_and_terminal() {
    struct BadReader;
    impl Read for BadReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "private-transport-marker",
            ))
        }
    }
    let m = material();
    let s = server(&m, Arc::new(|_, _| Ok(())));
    let mut pending = s.connection().unwrap();
    let err = pending.read_tls(&mut BadReader).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!err.to_string().contains("private-transport-marker"));
    assert!(pending.finish().is_err());
}
