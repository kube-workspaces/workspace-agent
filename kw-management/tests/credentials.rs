use kw_management::{credentials::MachineKey, identity::Identity};
#[cfg(target_os = "linux")]
#[path = "support/certificate_fixture.rs"]
mod certificate_fixture;
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
        certificate_fixture::issue(csr, &guest.to_uri().unwrap(), issued_at)
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
    fn durable_certificate_bundle_roundtrips_without_overwriting_key_or_existing_state() {
        use kw_management::trust::TrustStore;
        use std::{
            sync::Arc,
            time::{SystemTime, UNIX_EPOCH},
        };
        let temp = Temp::new();
        let root = temp.root();
        let bundle_root = temp.0.join("certificates");
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let key_bytes = fs::read(root.join("machine-key.json")).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        let (root_der, leaf) = certificates_for_csr(&csr, &identity());
        let trust = Arc::new(TrustStore::new(&[root_der]).unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = key
            .verify_enrollment_certificate(&identity(), &trust, vec![leaf], now)
            .unwrap();
        key.persist_enrollment_certificate(&bundle_root, &identity(), &trust, &certificate, now)
            .unwrap();
        assert_eq!(fs::metadata(&bundle_root).unwrap().mode() & 0o7777, 0o700);
        let record_path = bundle_root.join("certificate-bundle.json");
        assert_eq!(fs::metadata(&record_path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&record_path).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        let original = fs::read(&record_path).unwrap();
        assert!(!String::from_utf8(original.clone())
            .unwrap()
            .contains("private_key"));
        assert!(key
            .persist_enrollment_certificate(&bundle_root, &identity(), &trust, &certificate, now)
            .is_err());
        assert_eq!(fs::read(&record_path).unwrap(), original);
        assert_eq!(fs::read(root.join("machine-key.json")).unwrap(), key_bytes);
        // Bundle/key roots are not interchangeable or nested/adopted in place.
        assert!(key
            .persist_enrollment_certificate(&root, &identity(), &trust, &certificate, now)
            .is_err());
        let nested = root.join("certificates");
        assert!(key
            .persist_enrollment_certificate(&nested, &identity(), &trust, &certificate, now)
            .is_err());
        assert!(!nested.exists());
        let empty = temp.0.join("existing-empty");
        fs::DirBuilder::new().mode(0o700).create(&empty).unwrap();
        assert!(key
            .persist_enrollment_certificate(&empty, &identity(), &trust, &certificate, now)
            .is_err());
        assert!(key
            .reopen_enrollment_certificate(&empty, &identity(), &trust, now)
            .is_err());
        assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
        assert!(key
            .reopen_enrollment_certificate(&root, &identity(), &trust, now)
            .is_err());
        assert!(MachineKey::reopen(&bundle_root, &identity()).is_err());
        drop(key);
        let mut key = MachineKey::reopen(&root, &identity()).unwrap();
        let loaded = key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .unwrap();
        assert_eq!(loaded.chain_der(), certificate.chain_der());
        assert_eq!(key.csr_der(&identity()).unwrap(), csr);
        // Loaded public bytes form an immutable verified snapshot, NOT a live
        // bundle-file fence. New loads deny the corruption; old snapshots still
        // must pass TLS's current trust/time and held key-custody checks.
        fs::write(&record_path, b"corrupt").unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        let server = key
            .tls_server_from_enrollment(&identity(), trust, &loaded, Arc::new(|_, _| Ok(())))
            .unwrap();
        assert!(server.connection().is_ok());
    }
    #[test]
    fn certificate_bundle_reopen_revalidates_binding_chain_time_and_private_storage() {
        use kw_management::trust::TrustStore;
        use std::time::{SystemTime, UNIX_EPOCH};
        let temp = Temp::new();
        let root = temp.root();
        let bundle_root = temp.0.join("certificates");
        let mut key = MachineKey::initialize(&root, &identity()).unwrap();
        let csr = key.csr_der(&identity()).unwrap();
        let (root_der, leaf) = certificates_for_csr(&csr, &identity());
        let trust = TrustStore::new(&[root_der]).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = key
            .verify_enrollment_certificate(&identity(), &trust, vec![leaf], now)
            .unwrap();
        // Invalid/expired input does not create a destination or poison the key.
        assert!(key
            .persist_enrollment_certificate(
                &bundle_root,
                &identity(),
                &trust,
                &certificate,
                now + 700
            )
            .is_err());
        assert!(!bundle_root.exists());
        key.persist_enrollment_certificate(&bundle_root, &identity(), &trust, &certificate, now)
            .unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now + 700)
            .is_err());
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now - 60)
            .is_err());
        let (other_root, _) = certificates_for_csr(&csr, &identity());
        let other_trust = TrustStore::new(&[other_root]).unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &other_trust, now)
            .is_err());
        let other = Temp::new();
        let mut other_key = MachineKey::initialize(&other.root(), &identity()).unwrap();
        assert!(other_key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        let record_path = bundle_root.join("certificate-bundle.json");
        let original = fs::read(&record_path).unwrap();
        let source = String::from_utf8(original.clone()).unwrap();
        use base64::{engine::general_purpose::STANDARD, Engine};
        let fields: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let digest = fields["csr_sha256"].as_str().unwrap();
        let encoded_leaf = fields["chain_der"][0].as_str().unwrap();
        let mut broken_leaf = STANDARD.decode(encoded_leaf).unwrap();
        let last = broken_leaf.len() - 1;
        broken_leaf[last] ^= 1;
        for invalid in [
            Vec::new(),
            b"partial".to_vec(),
            vec![0; 288 * 1024 + 1],
            format!("{source}\n").into_bytes(),
            source
                .replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                .into_bytes(),
            source
                .replace(digest, &STANDARD.encode([0; 32]))
                .into_bytes(),
            source.replace("/uid/gen/1", "/uid/other/1").into_bytes(),
            source
                .replace(encoded_leaf, &STANDARD.encode(broken_leaf))
                .into_bytes(),
            source
                .replace(encoded_leaf, &format!("{encoded_leaf}="))
                .into_bytes(),
            source
                .replacen("\"version\":1", "\"version\":2", 1)
                .into_bytes(),
            source
                .replacen("\"version\":1", "\"version\":1,\"unknown\":true", 1)
                .into_bytes(),
        ] {
            fs::write(&record_path, &invalid).unwrap();
            assert!(key
                .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
                .is_err());
            assert_eq!(fs::read(&record_path).unwrap(), invalid);
        }
        fs::write(&record_path, &original).unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&record_path, temp.0.join("alias")).unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        fs::remove_file(temp.0.join("alias")).unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&record_path)
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&held).unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        drop(held);
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_ok());
        fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&record_path, temp.0.join("old-bundle")).unwrap();
        symlink(temp.0.join("old-bundle"), &record_path).unwrap();
        assert!(key
            .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
            .is_err());
        assert_eq!(fs::read(temp.0.join("old-bundle")).unwrap(), original);
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
