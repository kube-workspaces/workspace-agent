use super::super::{MachineKey, Request};
use super::*;
use crate::{identity::Identity, trust::TrustStore};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod certificate_fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/certificate_fixture.rs"
    ));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    RootCreated,
    RecordCreated,
    PartialWrite,
    RecordWritten,
    BeforeFileSync,
    FileSynced,
    BeforeDirectorySync,
    DirectorySynced,
    BeforeParentSync,
    ParentSynced,
}
const CRASH_STAGES: [Stage; 7] = [
    Stage::RootCreated,
    Stage::RecordCreated,
    Stage::PartialWrite,
    Stage::RecordWritten,
    Stage::FileSynced,
    Stage::DirectorySynced,
    Stage::ParentSynced,
];
const SYNC_STAGES: [Stage; 6] = [
    Stage::BeforeFileSync,
    Stage::FileSynced,
    Stage::BeforeDirectorySync,
    Stage::DirectorySynced,
    Stage::BeforeParentSync,
    Stage::ParentSynced,
];
struct Control {
    fault: Option<(Stage, bool)>,
    trace: Vec<Stage>,
}
thread_local! { static CONTROL: RefCell<Option<Control>> = const { RefCell::new(None) }; }
struct Probe;
impl Probe {
    fn start(fault: Option<(Stage, bool)>) -> Self {
        CONTROL.with(|c| {
            assert!(c.borrow().is_none());
            *c.borrow_mut() = Some(Control {
                fault,
                trace: Vec::new(),
            });
        });
        Self
    }
    fn trace(&self) -> Vec<Stage> {
        CONTROL.with(|c| c.borrow().as_ref().unwrap().trace.clone())
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        CONTROL.with(|c| *c.borrow_mut() = None);
    }
}
pub(super) fn partial_write_requested() -> bool {
    CONTROL.with(|c| {
        c.borrow()
            .as_ref()
            .is_some_and(|c| c.fault.is_some_and(|(s, _)| s == Stage::PartialWrite))
    })
}
pub(super) fn checkpoint(stage: Stage) -> Result<(), KeyUnavailable> {
    let fault = CONTROL.with(|c| {
        let mut c = c.borrow_mut();
        let c = c.as_mut()?;
        c.trace.push(stage);
        c.fault.filter(|(s, _)| *s == stage)
    });
    if let Some((_, pause)) = fault {
        if pause {
            // Test-only synchronization marker: never disclose bytes or paths.
            println!("credential-write-boundary");
            std::io::stdout().flush().unwrap();
            let _ = std::io::stdin().read_exact(&mut [0; 1]);
        }
        return Err(KeyUnavailable);
    }
    Ok(())
}
fn identity() -> Identity {
    Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid/gen/1")
        .unwrap()
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("kw-credential-fault-{suffix}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf {
        self.0.join("record")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn crash_at(root: &Path, stage: Stage, bundle_source: Option<&Path>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "credentials::linux::tests::write_boundary_child",
            "--ignored",
            "--nocapture",
            "--format",
            "terse",
        ])
        .env("KW_CREDENTIAL_FAULT_ROOT", root)
        .env("KW_CREDENTIAL_FAULT_STAGE", format!("{stage:?}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(source) = bundle_source {
        command.env("KW_CREDENTIAL_FAULT_BUNDLE_SOURCE", source);
    } else {
        command.env_remove("KW_CREDENTIAL_FAULT_BUNDLE_SOURCE");
    }
    let mut process = Process(command.spawn().unwrap());
    let output = process.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let found = BufReader::new(output)
            .lines()
            .any(|line| line.is_ok_and(|line| line.contains("credential-write-boundary")));
        let _ = tx.send(found);
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).ok(),
        Some(true),
        "{stage:?}"
    );
    process.0.kill().unwrap();
    process.0.wait().unwrap();
    reader.join().unwrap();
}
#[test]
#[ignore = "test-only crash writer; selected explicitly by hard_process_loss_at_every_write_boundary"]
fn write_boundary_child() {
    let Some(root) = std::env::var_os("KW_CREDENTIAL_FAULT_ROOT") else {
        return;
    };
    let name = std::env::var("KW_CREDENTIAL_FAULT_STAGE").unwrap();
    let stage = *CRASH_STAGES
        .iter()
        .find(|s| format!("{s:?}") == name)
        .unwrap();
    let _probe = Probe::start(Some((stage, true)));
    if let Some(source) = std::env::var_os("KW_CREDENTIAL_FAULT_BUNDLE_SOURCE") {
        let raw = fs::read(source).unwrap();
        let mut store = Store::initialize(Path::new(&root), Kind::CertificateBundle).unwrap();
        store.write_once(&raw).unwrap();
    } else {
        let _key = MachineKey::initialize(Path::new(&root), &identity()).unwrap();
    }
    panic!("configured boundary was not reached");
}
fn fixture() -> (Temp, MachineKey, TrustStore, u64) {
    let temp = Temp::new();
    let mut key = MachineKey::initialize(&temp.0.join("key"), &identity()).unwrap();
    let csr = key.csr_der(&identity()).unwrap();
    let at = SystemTime::now();
    let (root, leaf) = certificate_fixture::issue(&csr, &identity().to_uri().unwrap(), at);
    let trust = TrustStore::new(&[root]).unwrap();
    let now = at.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let certificate = key
        .verify_enrollment_certificate(&identity(), &trust, vec![leaf], now)
        .unwrap();
    key.persist_enrollment_certificate(
        &temp.0.join("source-bundle"),
        &identity(),
        &trust,
        &certificate,
        now,
    )
    .unwrap();
    (temp, key, trust, now)
}
#[test]
#[ignore = "dedicated Linux crash campaign; run separately from concurrent lock tests (also in CI)"]
fn hard_process_loss_at_every_write_boundary() {
    let (fixture, mut existing_key, trust, now) = fixture();
    let source = fixture.0.join("source-bundle/certificate-bundle.json");
    let bundle_bytes = fs::read(&source).unwrap();
    for bundle in [false, true] {
        for stage in CRASH_STAGES {
            let temp = Temp::new();
            let root = temp.root();
            crash_at(&root, stage, bundle.then_some(source.as_path()));
            let kind = if bundle {
                Kind::CertificateBundle
            } else {
                Kind::MachineKey
            };
            let path = root.join(kind.name());
            let before = fs::read(&path).ok();
            let complete = matches!(
                stage,
                Stage::RecordWritten
                    | Stage::FileSynced
                    | Stage::DirectorySynced
                    | Stage::ParentSynced
            );
            if bundle {
                let probe = Probe::start(None);
                let reopened =
                    existing_key.reopen_enrollment_certificate(&root, &identity(), &trust, now);
                assert_eq!(reopened.is_ok(), complete, "bundle {stage:?}");
                assert_eq!(
                    probe.trace(),
                    if complete {
                        SYNC_STAGES.to_vec()
                    } else {
                        vec![]
                    }
                );
                if complete {
                    assert_eq!(before.as_deref(), Some(bundle_bytes.as_slice()));
                }
                assert!(Store::initialize(&root, kind).is_err());
            } else {
                let probe = Probe::start(None);
                let reopened = MachineKey::reopen(&root, &identity());
                assert_eq!(reopened.is_ok(), complete, "key {stage:?}");
                assert_eq!(
                    probe.trace(),
                    if complete {
                        SYNC_STAGES.to_vec()
                    } else {
                        vec![]
                    }
                );
                if let Ok(mut key) = reopened {
                    let expected = Request::decode(before.as_ref().unwrap(), &identity())
                        .unwrap()
                        .csr;
                    assert_eq!(key.csr_der(&identity()).unwrap(), expected);
                }
                assert!(MachineKey::initialize(&root, &identity()).is_err());
            }
            assert!(fs::read(&path).ok() == before, "record changed: {stage:?}");
        }
    }
}
#[test]
fn sync_denial_on_reopen_returns_no_key_or_certificate_and_never_rewrites() {
    let (temp, mut key, trust, now) = fixture();
    let key_root = temp.0.join("key");
    let bundle_root = temp.0.join("source-bundle");
    let csr = key.csr_der(&identity()).unwrap();
    drop(key);
    for bundle in [false, true] {
        for stage in [
            Stage::BeforeFileSync,
            Stage::BeforeDirectorySync,
            Stage::BeforeParentSync,
        ] {
            let mut key = if bundle {
                Some(MachineKey::reopen(&key_root, &identity()).unwrap())
            } else {
                None
            };
            let path = if bundle {
                bundle_root.join(Kind::CertificateBundle.name())
            } else {
                key_root.join(Kind::MachineKey.name())
            };
            let before = fs::read(&path).unwrap();
            let probe = Probe::start(Some((stage, false)));
            if let Some(key) = &mut key {
                assert!(key
                    .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
                    .is_err());
            } else {
                assert!(MachineKey::reopen(&key_root, &identity()).is_err());
            }
            let end = SYNC_STAGES.iter().position(|s| *s == stage).unwrap();
            assert_eq!(probe.trace(), SYNC_STAGES[..=end]);
            drop(probe);
            assert!(
                fs::read(&path).unwrap() == before,
                "record contents changed"
            );
            drop(key);
            let mut key = MachineKey::reopen(&key_root, &identity()).unwrap();
            assert_eq!(key.csr_der(&identity()).unwrap(), csr);
            assert!(key
                .reopen_enrollment_certificate(&bundle_root, &identity(), &trust, now)
                .is_ok());
        }
    }
}

#[test]
fn sync_denial_or_lost_publication_ack_never_returns_material_or_overwrites() {
    let (fixture, mut existing_key, trust, now) = fixture();
    let certificate = existing_key
        .reopen_enrollment_certificate(&fixture.0.join("source-bundle"), &identity(), &trust, now)
        .unwrap();
    for bundle in [false, true] {
        for stage in [
            Stage::BeforeFileSync,
            Stage::BeforeDirectorySync,
            Stage::BeforeParentSync,
            Stage::ParentSynced,
        ] {
            let temp = Temp::new();
            let root = temp.root();
            let probe = Probe::start(Some((stage, false)));
            if bundle {
                assert!(existing_key
                    .persist_enrollment_certificate(&root, &identity(), &trust, &certificate, now)
                    .is_err());
            } else {
                assert!(MachineKey::initialize(&root, &identity()).is_err());
            }
            assert_eq!(probe.trace().last(), Some(&stage));
            drop(probe);
            let path = root.join(
                if bundle {
                    Kind::CertificateBundle
                } else {
                    Kind::MachineKey
                }
                .name(),
            );
            let before = fs::read(&path).unwrap();
            if bundle {
                assert!(existing_key
                    .persist_enrollment_certificate(&root, &identity(), &trust, &certificate, now)
                    .is_err());
                let loaded = existing_key
                    .reopen_enrollment_certificate(&root, &identity(), &trust, now)
                    .unwrap();
                assert_eq!(loaded.chain_der(), certificate.chain_der());
            } else {
                assert!(MachineKey::initialize(&root, &identity()).is_err());
                let mut key = MachineKey::reopen(&root, &identity()).unwrap();
                assert_eq!(
                    key.csr_der(&identity()).unwrap(),
                    Request::decode(&before, &identity()).unwrap().csr
                );
            }
            assert!(
                fs::read(&path).unwrap() == before,
                "record contents changed"
            );
        }
    }
}
