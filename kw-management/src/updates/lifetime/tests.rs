use super::*;
use crate::updates::journal::{Ack, ActionReceipt, Context, Event, Journal, Snapshot};

struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        let mut bytes = [0; 16];
        getrandom::getrandom(&mut bytes).unwrap();
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("kw-updater-lifetime-{name}"));
        persistence::create_root(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Authority {
    head: RecoveryHead,
}
impl RecoveryAuthority for Authority {
    fn current_head(&mut self, _: &LaunchBinding) -> Result<Option<RecoveryHead>, Error> {
        Ok(Some(RecoveryHead {
            plan_sha256: self.head.plan_sha256.clone(),
            checkpoint_sha256: self.head.checkpoint_sha256.clone(),
            minimum_sequence: self.head.minimum_sequence,
        }))
    }
}

fn rig(root: &Path) -> (LaunchBinding, Authority) {
    let plan =
        serde_json::from_str::<Snapshot>(include_str!("../../../tests/testdata/journal-v1.json"))
            .unwrap()
            .plan;
    let mut journal = Journal::new(plan.clone(), 1, 1700000000).unwrap();
    let mut store = FileStore::initialize(root, journal.clone()).unwrap();
    let mut context = Context {
        binding: plan.binding.clone(),
        owner_fence: 1,
        now: 1700000000,
        boot_id: "boot-1".into(),
        authorized: true,
        recording_available: true,
        installer_busy: false,
    };
    for kind in ["begin", "complete", "begin"] {
        context.now += 1;
        let receipt = journal
            .snapshot()
            .active
            .as_ref()
            .map(|action| ActionReceipt {
                sequence: action.sequence,
                kind: action.kind.clone(),
                outcome: "ok".into(),
                msi_code: None,
                service_state: "stopped".into(),
                product_code: String::new(),
                target_absent: false,
                driver_sha256: String::new(),
                identity_verified: false,
                health_verified: false,
            });
        let transition = journal
            .prepare(
                &Event {
                    kind: kind.into(),
                    receipt,
                },
                &context,
            )
            .unwrap();
        let ack = Ack {
            sequence: transition.sequence(),
            sha256: transition.sha256(),
            kind: "intent".into(),
        };
        (journal, _) = transition.commit(&mut store, &context, Some(&ack)).unwrap();
    }
    let launch = LaunchBinding {
        version: 1,
        binding: plan.binding.clone(),
        plan_sha256: plan.sha256(),
    };
    let authority = Authority {
        head: RecoveryHead {
            plan_sha256: launch.plan_sha256.clone(),
            checkpoint_sha256: journal.sha256(),
            minimum_sequence: journal.snapshot().sequence,
        },
    };
    (launch, authority)
}

#[test]
fn protected_binding_is_canonical_strict_and_not_overwritten() {
    let root = Root::new();
    let (launch, _) = rig(&root.0);
    launch.write_new(&root.0).unwrap();
    assert_eq!(LaunchBinding::read(&root.0).unwrap(), launch);
    assert!(launch.write_new(&root.0).is_err());
    let raw = launch.encode().unwrap();
    for invalid in [
        b"{}".to_vec(),
        [raw.as_slice(), b" "].concat(),
        vec![0; MAX_LAUNCH_BYTES + 1],
    ] {
        assert!(LaunchBinding::decode(&invalid).is_err());
    }
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    value["installer_flags"] = "arbitrary".into();
    assert!(LaunchBinding::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn unavailable_authority_does_not_adopt_local_head_or_touch_checkpoint() {
    let root = Root::new();
    let (launch, _) = rig(&root.0);
    fs::write(root.0.join("checkpoint.json"), b"corrupt").unwrap();
    assert!(launch
        .recover(&root.0, &mut UnavailableAuthority)
        .unwrap()
        .is_none());
    assert_eq!(
        fs::read(root.0.join("checkpoint.json")).unwrap(),
        b"corrupt"
    );
    let status = serde_json::to_value(RuntimeStatus::new(&launch, None)).unwrap();
    assert_eq!(status["state"], "waiting_for_authority");
    assert_eq!(status["effects_enabled"], false);
}

#[test]
fn recovery_retains_active_intent_and_exclusive_store_without_dispatch() {
    let root = Root::new();
    let (launch, mut authority) = rig(&root.0);
    let before = fs::read(root.0.join("checkpoint.json")).unwrap();
    let recovered = launch.recover(&root.0, &mut authority).unwrap().unwrap();
    assert_eq!(
        recovered.journal().snapshot().active.as_ref().unwrap().kind,
        "install_target_msi"
    );
    assert_eq!(recovered.journal().snapshot().sequence, 3);
    assert!(launch.recover(&root.0, &mut authority).is_err());
    RuntimeStatus::new(&launch, Some(&recovered))
        .write(&root.0)
        .unwrap();
    RuntimeStatus::new(&launch, Some(&recovered))
        .write(&root.0)
        .unwrap();
    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(root.0.join("updater-status.json")).unwrap()).unwrap();
    assert_eq!(status["journal_sequence"], 3);
    assert_eq!(status["effects_enabled"], false);
    drop(recovered);
    assert!(launch.recover(&root.0, &mut authority).unwrap().is_some());
    assert_eq!(fs::read(root.0.join("checkpoint.json")).unwrap(), before);
}

#[test]
fn forged_binding_head_plan_and_sequence_floor_deny() {
    let root = Root::new();
    let (launch, mut authority) = rig(&root.0);
    let trusted_digest = authority.head.checkpoint_sha256.clone();
    authority.head.minimum_sequence += 1;
    assert!(launch.recover(&root.0, &mut authority).is_err());
    authority.head.minimum_sequence -= 1;
    authority.head.checkpoint_sha256 = "0".repeat(64);
    assert!(launch.recover(&root.0, &mut authority).is_err());
    authority.head.checkpoint_sha256 = trusted_digest;
    let mut forged = launch.clone();
    forged.binding.vm_uid = "another-vm".into();
    assert!(forged.recover(&root.0, &mut authority).is_err());
    forged = launch;
    forged.plan_sha256 = "0".repeat(64);
    assert!(forged.recover(&root.0, &mut authority).is_err());
}
