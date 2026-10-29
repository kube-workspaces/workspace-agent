use kw_management::{credentials::MachineKey, identity::Identity};
fn identity() -> Identity {
    Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid/gen/1")
        .unwrap()
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_storage_never_falls_back() {
    let path = std::env::temp_dir().join("unsupported-management-key-root");
    assert!(MachineKey::initialize(&path, &identity()).is_err());
    assert!(MachineKey::reopen(&path, &identity()).is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
        path::PathBuf,
        process::{Command, Stdio},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("kw-machine-key-{suffix}"));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn root(&self) -> PathBuf {
            self.0.join("key")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn durable_private_key_and_exact_csr_survive_reopen() {
        let temp = Temp::new();
        let root = temp.root();
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(
            fs::metadata(root.join("machine-key.json")).unwrap().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("machine-key.json")).unwrap().uid(),
            unsafe { libc::geteuid() }
        );
        assert!(MachineKey::initialize(&root, &identity()).is_err());
        assert!(MachineKey::reopen(&root, &identity()).is_err());
        assert_eq!(
            format!("{key:?}"),
            "management machine key (private material and location redacted)"
        );
        drop(key);
        let mut reopened = MachineKey::reopen(&root, &identity()).unwrap();
        assert_eq!(reopened.csr_der(&identity()).unwrap(), csr);
    }
    #[test]
    fn existing_empty_partial_and_corrupt_roots_are_never_adopted_or_repaired() {
        for content in [
            None,
            Some(Vec::new()),
            Some(b"private-key-marker".to_vec()),
            Some(vec![0; 16385]),
        ] {
            let temp = Temp::new();
            let root = temp.root();
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            if let Some(bytes) = &content {
                fs::write(root.join("machine-key.json"), bytes).unwrap();
                fs::set_permissions(
                    root.join("machine-key.json"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            assert!(MachineKey::initialize(&root, &identity()).is_err());
            assert!(MachineKey::reopen(&root, &identity()).is_err());
            if let Some(bytes) = content {
                assert_eq!(fs::read(root.join("machine-key.json")).unwrap(), bytes);
            }
        }
    }
    #[test]
    fn changed_binding_or_out_of_band_edits_permanently_poison_the_handle() {
        let temp = Temp::new();
        let root = temp.root();
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let original = fs::read(root.join("machine-key.json")).unwrap();
        let mut changed = identity();
        if let Identity::Guest {
            revocation_epoch, ..
        } = &mut changed
        {
            *revocation_epoch += 1;
        }
        assert!(key.csr_der(&changed).is_err());
        assert!(key.csr_der(&identity()).is_err());
        drop(key);
        assert!(MachineKey::reopen(&root, &changed).is_err());
        assert_eq!(fs::read(root.join("machine-key.json")).unwrap(), original);
        let mut key = MachineKey::reopen(&root, &identity()).unwrap();
        fs::write(root.join("machine-key.json"), b"corrupt").unwrap();
        assert!(key.csr_der(&identity()).is_err());
        fs::write(root.join("machine-key.json"), &original).unwrap();
        assert!(key.csr_der(&identity()).is_err());
    }
    #[test]
    fn links_permissions_untrusted_parents_and_replacements_deny() {
        for mutation in [
            "file-symlink",
            "root-symlink",
            "parent-symlink",
            "hardlink",
            "file-permissions",
            "root-permissions",
            "parent-permissions",
            "extra-file",
            "replacement",
        ] {
            let temp = Temp::new();
            let root = temp.root();
            let mut key = MachineKey::initialize(&root, &identity()).unwrap();
            match mutation {
                "file-symlink" => {
                    fs::rename(root.join("machine-key.json"), temp.0.join("old")).unwrap();
                    symlink(temp.0.join("old"), root.join("machine-key.json")).unwrap();
                }
                "root-symlink" => {
                    fs::rename(&root, temp.0.join("old")).unwrap();
                    symlink(temp.0.join("old"), &root).unwrap();
                }
                "parent-symlink" => {
                    symlink(&temp.0, temp.0.join("alias")).unwrap();
                    assert!(MachineKey::reopen(&temp.0.join("alias/key"), &identity()).is_err());
                    continue;
                }
                "hardlink" => {
                    fs::hard_link(root.join("machine-key.json"), temp.0.join("alias")).unwrap();
                }
                "file-permissions" => fs::set_permissions(
                    root.join("machine-key.json"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap(),
                "root-permissions" => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap()
                }
                "parent-permissions" => {
                    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o777)).unwrap()
                }
                "extra-file" => fs::write(root.join("unexpected"), b"not adopted").unwrap(),
                "replacement" => {
                    let bytes = fs::read(root.join("machine-key.json")).unwrap();
                    fs::rename(root.join("machine-key.json"), temp.0.join("old")).unwrap();
                    fs::write(root.join("machine-key.json"), bytes).unwrap();
                    fs::set_permissions(
                        root.join("machine-key.json"),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(key.csr_der(&identity()).is_err(), "{mutation}");
            drop(key);
            if mutation != "replacement" {
                assert!(
                    MachineKey::reopen(&root, &identity()).is_err(),
                    "{mutation}"
                );
            }
            // Replacing the complete immutable file while no owner is alive is
            // privileged tampering; this helper does not claim rollback resistance.
        }
    }
    #[test]
    fn process_loss_releases_ownership_without_rotating_key() {
        let temp = Temp::new();
        let root = temp.root();
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        drop(key);
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "linux::key_lock_child",
                    "--ignored",
                    "--nocapture",
                    "--format",
                    "terse",
                ])
                .env("KW_KEY_LOCK_TEST_ROOT", &root)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let reader = BufReader::new(child.0.stdout.take().unwrap());
        let mut locked = false;
        for line in reader.lines() {
            if line.unwrap().contains("key-is-locked") {
                locked = true;
                break;
            }
        }
        assert!(locked);
        assert!(MachineKey::reopen(&root, &identity()).is_err());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let mut key = MachineKey::reopen(&root, &identity()).unwrap();
        assert_eq!(key.csr_der(&identity()).unwrap(), csr);
    }
    #[test]
    fn lexical_aliases_and_nonregular_records_deny_without_repair() {
        use std::os::unix::ffi::OsStrExt;
        let temp = Temp::new();
        for path in [
            PathBuf::from("relative-key"),
            PathBuf::from(format!("{}/./key", temp.0.display())),
            temp.0.join("../alias-key"),
        ] {
            assert!(MachineKey::initialize(&path, &identity()).is_err());
        }
        let root = temp.root();
        let key = MachineKey::initialize(&root, &identity()).unwrap();
        drop(key);
        fs::remove_file(root.join("machine-key.json")).unwrap();
        let name =
            std::ffi::CString::new(root.join("machine-key.json").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(MachineKey::reopen(&root, &identity()).is_err());
    }
    fn certificates_for_csr(csr: &[u8], guest: &Identity) -> (Vec<u8>, Vec<u8>) {
        certificates_for_csr_at(csr, guest, std::time::SystemTime::now())
    }
    fn certificates_for_csr_at(
        csr: &[u8],
        guest: &Identity,
        issued_at: std::time::SystemTime,
    ) -> (Vec<u8>, Vec<u8>) {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::{Signer, SigningKey};
        use std::time::Duration;
        use x509_cert::{
            der::{
                asn1::{BitString, Ia5String, ObjectIdentifier, OctetString},
                Decode, Encode,
            },
            ext::pkix::{name::GeneralName, SubjectAltName},
            request::CertReq,
            Certificate,
        };
        // Fresh synthetic CA signs the stored key's public CSR. No private key
        // is extracted from the machine-key loader to construct this certificate.
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/management-pki-certificates-v1.json"
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
        issuer.tbs_certificate.subject_public_key_info.algorithm =
            issuer.signature_algorithm.clone();
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(signer.verifying_key().as_bytes()).unwrap();
        leaf.signature_algorithm = issuer.signature_algorithm.clone();
        leaf.tbs_certificate.subject_public_key_info =
            CertReq::from_der(csr).unwrap().info.public_key;
        let san = SubjectAltName(vec![
            GeneralName::UniformResourceIdentifier(
                Ia5String::new(&guest.to_uri().unwrap()).unwrap(),
            ),
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
        let issue = |cert: &mut Certificate, lifetime| {
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
        let root_der = issue(&mut issuer, 86400);
        let leaf_der = issue(&mut leaf, 600);
        (root_der, leaf_der)
    }
    #[test]
    fn tls_states_retain_custody_and_check_it_before_handshake_processing() {
        use kw_management::trust::TrustStore;
        use std::sync::Arc;
        let temp = Temp::new();
        let root = temp.root();
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        let (root_der, leaf_der) = certificates_for_csr(&csr, &identity());
        let server = key
            .tls_server(
                &identity(),
                Arc::new(TrustStore::new(&[root_der]).unwrap()),
                vec![leaf_der],
                Arc::new(|_, _| Ok(())),
            )
            .unwrap();
        drop(key);
        assert!(MachineKey::reopen(&root, &identity()).is_err());
        let mut pending = server.connection().unwrap();
        assert!(pending.process_new_packets().is_ok());
        fs::set_permissions(
            root.join("machine-key.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(pending.process_new_packets().is_err());
        fs::set_permissions(
            root.join("machine-key.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(server.connection().is_err());
        drop(server);
        assert!(MachineKey::reopen(&root, &identity()).is_err());
        drop(pending);
        let mut reopened = MachineKey::reopen(&root, &identity()).unwrap();
        assert_eq!(reopened.csr_der(&identity()).unwrap(), csr);
    }
    #[test]
    fn enrollment_certificate_is_bound_to_exact_csr_identity_trust_and_time() {
        use kw_management::trust::TrustStore;
        use std::{
            sync::Arc,
            time::{SystemTime, UNIX_EPOCH},
        };
        let temp = Temp::new();
        let root = temp.root();
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        let (root_der, leaf) = certificates_for_csr(&csr, &identity());
        let trust = Arc::new(TrustStore::new(&[root_der]).unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let chain = vec![leaf.clone()];
        let certificate = key
            .verify_enrollment_certificate(&identity(), &trust, chain.clone(), now)
            .unwrap();
        assert_eq!(certificate.chain_der(), &chain);
        assert_eq!(
            format!("{certificate:?}"),
            "management enrollment certificate (scope and contents redacted)"
        );
        assert!(key
            .verify_enrollment_certificate(&identity(), &trust, chain.clone(), now + 700)
            .is_err());
        assert!(key
            .verify_enrollment_certificate(&identity(), &trust, chain.clone(), now - 60)
            .is_err());
        for invalid in [
            vec![],
            vec![vec![]],
            vec![vec![0; 128 * 1024 + 1]],
            vec![leaf.clone(); 10],
            vec![leaf.clone(), b"invalid-intermediate".to_vec()],
        ] {
            assert!(key
                .verify_enrollment_certificate(&identity(), &trust, invalid, now)
                .is_err());
        }
        let mut damaged = leaf.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(key
            .verify_enrollment_certificate(&identity(), &trust, vec![damaged], now)
            .is_err());
        let mut other_identity = identity();
        if let Identity::Guest { generation, .. } = &mut other_identity {
            *generation = "other".into();
        }
        let (other_root, other_leaf) = certificates_for_csr(&csr, &other_identity);
        let other_trust = Arc::new(TrustStore::new(&[other_root]).unwrap());
        assert!(key
            .verify_enrollment_certificate(&identity(), &other_trust, vec![other_leaf], now)
            .is_err());
        assert!(key
            .verify_enrollment_certificate(&identity(), &other_trust, chain.clone(), now)
            .is_err());
        assert!(key
            .tls_server_from_enrollment(
                &identity(),
                other_trust,
                &certificate,
                Arc::new(|_, _| Ok(()))
            )
            .is_err());
        let second_temp = Temp::new();
        let mut other_key = MachineKey::initialize(&second_temp.root(), &identity()).unwrap();
        assert!(other_key
            .verify_enrollment_certificate(&identity(), &trust, chain, now)
            .is_err());
        assert!(other_key
            .tls_server_from_enrollment(
                &identity(),
                trust.clone(),
                &certificate,
                Arc::new(|_, _| Ok(()))
            )
            .is_err());
        // Invalid public responses do not poison good custody or change its CSR.
        assert_eq!(key.csr_der(&identity()).unwrap(), csr);
        drop(key);
        let mut reopened = MachineKey::reopen(&root, &identity()).unwrap();
        let server = reopened
            .tls_server_from_enrollment(&identity(), trust, &certificate, Arc::new(|_, _| Ok(())))
            .unwrap();
        assert!(server.connection().is_ok());
    }
    #[test]
    fn previously_verified_enrollment_does_not_bypass_tls_current_time() {
        use kw_management::trust::TrustStore;
        use std::{
            sync::Arc,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };
        let temp = Temp::new();
        let mut key = MachineKey::initialize(&temp.root(), &identity()).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        for issued_at in [
            SystemTime::now() - Duration::from_secs(3600),
            SystemTime::now() + Duration::from_secs(3600),
        ] {
            let (root, leaf) = certificates_for_csr_at(&csr, &identity(), issued_at);
            let trust = Arc::new(TrustStore::new(&[root]).unwrap());
            let at = issued_at.duration_since(UNIX_EPOCH).unwrap().as_secs();
            let certificate = key
                .verify_enrollment_certificate(&identity(), &trust, vec![leaf], at)
                .unwrap();
            assert!(key
                .tls_server_from_enrollment(
                    &identity(),
                    trust,
                    &certificate,
                    Arc::new(|_, _| Ok(()))
                )
                .is_err());
        }
        assert_eq!(key.csr_der(&identity()).unwrap(), csr);
    }
    #[test]
    #[ignore = "subprocess lock holder used by process_loss_releases_ownership_without_rotating_key"]
    fn key_lock_child() {
        let Some(root) = std::env::var_os("KW_KEY_LOCK_TEST_ROOT") else {
            return;
        };
        let _key = MachineKey::reopen(&PathBuf::from(root), &identity()).unwrap();
        println!("key-is-locked");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_exact(&mut [0; 1]);
    }
}
