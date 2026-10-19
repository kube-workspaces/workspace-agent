use super::*;
use crate::updates::{
    journal::{Ack, Context, Event, Journal, Snapshot, Store},
    Manifest, Predecessor,
};

const DIRECTORY: &str = r"C:\Program Files\Kube Workspaces Agent";

struct MemoryStore(String);
impl Store for MemoryStore {
    fn compare_and_swap(
        &mut self,
        expected: &str,
        next: &[u8],
    ) -> Result<(), super::super::journal::Error> {
        assert_eq!(expected, self.0);
        let mut bytes = b"kw-agent-upgrade-journal/v1\0".to_vec();
        bytes.extend_from_slice(next);
        self.0 = crate::updates::digest(&bytes);
        Ok(())
    }
}

struct Rig {
    journal: Journal,
    store: MemoryStore,
    context: Context,
    tx: Transaction,
}

fn manifests(plan: &Plan) -> (VerifiedManifest, VerifiedManifest) {
    // Trusted projections for dispatcher tests. Actual publisher signature and
    // raw artifact verification are exercised by the shared signed fixture tests.
    let mut t: Manifest =
        serde_json::from_str(include_str!("../../../tests/testdata/manifest-v1.json")).unwrap();
    t.driver = None;
    let mut p = t.clone();
    p.target_id = "windows-agent-0.3.4".into();
    p.agent_version = "0.3.4".into();
    p.msi.product_code = plan.previous_product_code.clone();
    p.rollback_predecessors.clear();
    t.rollback_predecessors = vec![Predecessor {
        target_id: p.target_id.clone(),
        manifest_sha256: plan.binding.previous_sha256.clone(),
    }];
    (
        VerifiedManifest {
            manifest: t,
            digest: plan.binding.target_sha256.clone(),
        },
        VerifiedManifest {
            manifest: p,
            digest: plan.binding.previous_sha256.clone(),
        },
    )
}

impl Rig {
    fn new() -> Self {
        let plan = serde_json::from_str::<Snapshot>(include_str!(
            "../../../tests/testdata/journal-v1.json"
        ))
        .unwrap()
        .plan;
        let (target, previous) = manifests(&plan);
        let tx = Transaction::new(plan.clone(), &target, &previous, DIRECTORY.into()).unwrap();
        let journal = Journal::new(plan.clone(), 1, 1700000000).unwrap();
        Self {
            store: MemoryStore(journal.sha256()),
            journal,
            tx,
            context: Context {
                binding: plan.binding,
                owner_fence: 1,
                now: 1700000000,
                boot_id: "boot-1".into(),
                authorized: true,
                recording_available: true,
                installer_busy: false,
            },
        }
    }

    fn advance(&mut self, kind: &str, receipt: Option<ActionReceipt>) -> Option<CommittedAction> {
        self.context.now += 1;
        let t = self
            .journal
            .prepare(
                &Event {
                    kind: kind.into(),
                    receipt,
                },
                &self.context,
            )
            .unwrap();
        let ack = Ack {
            sequence: t.sequence(),
            sha256: t.sha256(),
            kind: if kind == "begin" { "intent" } else { "result" }.into(),
        };
        let (j, permit) = t
            .commit_for_dispatch(&mut self.store, &self.context, Some(&ack))
            .unwrap();
        self.journal = j;
        permit
    }

    fn stop_agent(&mut self) {
        let permit = self.advance("begin", None).unwrap();
        let (action, _, _) = permit.into_parts();
        assert_eq!(action.kind, "stop_agent");
        self.advance(
            "complete",
            Some(ActionReceipt {
                sequence: action.sequence,
                kind: action.kind,
                outcome: "ok".into(),
                msi_code: None,
                service_state: "stopped".into(),
                product_code: String::new(),
                target_absent: false,
                driver_sha256: String::new(),
                identity_verified: false,
                health_verified: false,
            }),
        );
    }

    fn install_permit(&mut self) -> CommittedAction {
        self.stop_agent();
        self.advance("begin", None).unwrap()
    }
}

struct FakeInstaller {
    products: Vec<Product>,
    effects: Vec<String>,
    code: u32,
    busy: bool,
    reboot: bool,
    bad_package: bool,
    lost_result: bool,
    inconsistent_success: bool,
    observations: usize,
    fail_post_observation: bool,
}

fn product(package: &Package) -> Product {
    Product {
        product_code: package.product_code().into(),
        upgrade_code: package.upgrade_code().into(),
        version: package.version().into(),
        install_directory: DIRECTORY.into(),
    }
}

impl FakeInstaller {
    fn previous(tx: &Transaction) -> Self {
        Self {
            products: vec![product(&tx.previous)],
            effects: vec![],
            code: 0,
            busy: false,
            reboot: false,
            bad_package: false,
            lost_result: false,
            inconsistent_success: false,
            observations: 0,
            fail_post_observation: false,
        }
    }
}

impl MsiAdapter for FakeInstaller {
    fn observe(&mut self) -> Result<Observation, Error> {
        self.observations += 1;
        if self.fail_post_observation && self.observations > 1 {
            return Err(Error::Inventory);
        }
        Ok(Observation {
            products: self.products.clone(),
            installer_busy: self.busy,
            reboot_pending: self.reboot,
        })
    }
    fn verify_package(&mut self, _: &Package) -> Result<(), Error> {
        if self.bad_package {
            Err(Error::Package)
        } else {
            Ok(())
        }
    }
    fn install(&mut self, package: &Package, install_directory: &str) -> Result<u32, Error> {
        assert_eq!(install_directory, DIRECTORY);
        self.effects
            .push(format!("install:{}", package.product_code()));
        if !self.inconsistent_success {
            self.products = vec![product(package)];
        }
        if self.lost_result {
            Err(Error::Inventory)
        } else {
            Ok(self.code)
        }
    }
    fn uninstall(&mut self, p: &Product) -> Result<u32, Error> {
        assert_eq!(self.products, vec![p.clone()]);
        self.effects.push(format!("uninstall:{}", p.product_code));
        self.products.clear();
        Ok(self.code)
    }
}

struct Authority {
    deny: bool,
    calls: usize,
}
impl PhaseAuthority for Authority {
    fn authorize(&mut self, plan: &Plan, action: &Action, owner: u64) -> Result<(), Error> {
        assert_eq!(owner, 1);
        assert_eq!(plan.binding.vm_uid, "vm-uid");
        assert!(action.sequence > 0);
        self.calls += 1;
        if self.deny {
            Err(Error::Authority)
        } else {
            Ok(())
        }
    }
}
fn authority() -> Authority {
    Authority {
        deny: false,
        calls: 0,
    }
}

#[test]
fn dispatch_requires_exact_ack_and_durable_intent() {
    let mut rig = Rig::new();
    rig.stop_agent();
    rig.context.now += 1;
    let t = rig
        .journal
        .prepare(
            &Event {
                kind: "begin".into(),
                receipt: None,
            },
            &rig.context,
        )
        .unwrap();
    assert!(matches!(
        t.commit_for_dispatch(&mut rig.store, &rig.context, None),
        Err(super::super::journal::Error::Recording)
    ));
    assert_eq!(rig.store.0, rig.journal.sha256());
    let permit = rig.advance("begin", None).unwrap();
    let mut adapter = FakeInstaller::previous(&rig.tx);
    let mut gate = authority();
    let receipt = rig.tx.dispatch(permit, &mut adapter, &mut gate).unwrap();
    assert_eq!(gate.calls, 1);
    assert_eq!(receipt.outcome, "ok");
    assert!(!receipt.health_verified);
    rig.advance("complete", Some(receipt));
    assert_ne!(rig.journal.snapshot().result, "succeeded");
    assert_eq!(
        adapter.effects,
        vec![format!("install:{}", rig.tx.target.product_code())]
    );
}

#[test]
fn compensation_uninstalls_exact_target_before_installing_previous() {
    let mut rig = Rig::new();
    let permit = rig.install_permit();
    let mut adapter = FakeInstaller::previous(&rig.tx);
    let mut gate = authority();
    adapter.code = 1603;
    let failure = rig.tx.dispatch(permit, &mut adapter, &mut gate).unwrap();
    assert_eq!(failure.outcome, "failed");
    rig.advance("complete", Some(failure));
    assert_eq!(rig.journal.snapshot().phase, "rollback_pending");
    rig.advance("rollback", None);
    rig.stop_agent();
    adapter.code = 0;
    let permit = rig.advance("begin", None).unwrap();
    let removal = rig.tx.dispatch(permit, &mut adapter, &mut gate).unwrap();
    assert!(removal.target_absent);
    rig.advance("complete", Some(removal));
    let permit = rig.advance("begin", None).unwrap();
    let restored = rig.tx.dispatch(permit, &mut adapter, &mut gate).unwrap();
    rig.advance("complete", Some(restored));
    assert_eq!(
        adapter.effects,
        [
            format!("install:{}", rig.tx.target.product_code()),
            format!("uninstall:{}", rig.tx.target.product_code()),
            format!("install:{}", rig.tx.previous.product_code()),
        ]
    );
    assert!(rig.journal.snapshot().result.is_empty()); // SCM/health/result still required.
    assert_eq!(gate.calls, 3);
}

#[test]
fn msi_reboot_results_are_not_final_success() {
    for code in [3010, 1641] {
        let mut rig = Rig::new();
        let permit = rig.install_permit();
        let mut adapter = FakeInstaller::previous(&rig.tx);
        adapter.code = code;
        let receipt = rig
            .tx
            .dispatch(permit, &mut adapter, &mut authority())
            .unwrap();
        assert_eq!(receipt.outcome, "reboot_required");
        rig.advance("complete", Some(receipt));
        assert_eq!(rig.journal.snapshot().phase, "awaiting_reboot");
        assert!(rig.journal.snapshot().result.is_empty());
        assert_eq!(adapter.effects.len(), 1);
    }
}

#[test]
fn preparation_and_authority_failures_launch_nothing() {
    for case in [
        "busy",
        "reboot",
        "package",
        "authority",
        "foreign_product",
        "foreign_upgrade",
        "wrong_version",
        "wrong_directory",
        "multiple_products",
        "no_previous",
        "binding",
    ] {
        let mut rig = Rig::new();
        let permit = rig.install_permit();
        let mut adapter = FakeInstaller::previous(&rig.tx);
        let mut gate = authority();
        match case {
            "busy" => adapter.busy = true,
            "reboot" => adapter.reboot = true,
            "package" => adapter.bad_package = true,
            "authority" => gate.deny = true,
            "foreign_product" => adapter.products[0].product_code = "foreign".into(),
            "foreign_upgrade" => adapter.products[0].upgrade_code = "foreign".into(),
            "wrong_version" => adapter.products[0].version = "0.0.1".into(),
            "wrong_directory" => adapter.products[0].install_directory = r"C:\Other".into(),
            "multiple_products" => adapter.products.push(product(&rig.tx.target)),
            "no_previous" => adapter.products.clear(),
            "binding" => rig.tx.plan.binding.actor_uid = "other".into(),
            _ => unreachable!(),
        }
        assert!(
            rig.tx.dispatch(permit, &mut adapter, &mut gate).is_err(),
            "{case}"
        );
        assert!(adapter.effects.is_empty(), "{case}");
    }
}

#[test]
fn unknown_results_do_not_retry_or_fabricate_a_receipt() {
    for case in ["lost_result", "lost_observation", "wrong_product"] {
        let mut rig = Rig::new();
        let permit = rig.install_permit();
        let mut adapter = FakeInstaller::previous(&rig.tx);
        adapter.lost_result = case == "lost_result";
        adapter.fail_post_observation = case == "lost_observation";
        adapter.inconsistent_success = case == "wrong_product";
        assert_eq!(
            rig.tx.dispatch(permit, &mut adapter, &mut authority()),
            Err(Error::Uncertain)
        );
        assert_eq!(adapter.effects.len(), 1);
        assert_eq!(rig.journal.snapshot().phase, "active");
        assert_eq!(
            rig.journal.snapshot().active.as_ref().unwrap().kind,
            "install_target_msi"
        );
    }
}

#[test]
fn manifest_substitution_unqualified_drivers_and_unsafe_paths_deny() {
    let rig = Rig::new();
    for case in [
        "target_digest",
        "previous_digest",
        "product",
        "predecessor",
        "compatibility",
        "driver",
    ] {
        let (mut target, mut previous) = manifests(&rig.tx.plan);
        match case {
            "target_digest" => target.digest = "a".repeat(64),
            "previous_digest" => previous.digest = "a".repeat(64),
            "product" => {
                target.manifest.msi.product_code = previous.manifest.msi.product_code.clone()
            }
            "predecessor" => target.manifest.rollback_predecessors.clear(),
            "compatibility" => target.manifest.compatibility.minimum_agent_version = "0.3.5".into(),
            "driver" => {
                target.manifest.driver = serde_json::from_str::<Manifest>(include_str!(
                    "../../../tests/testdata/manifest-v1.json"
                ))
                .unwrap()
                .driver
            }
            _ => unreachable!(),
        }
        assert!(
            Transaction::new(rig.tx.plan.clone(), &target, &previous, DIRECTORY.into()).is_err(),
            "{case}"
        );
    }
    for path in [
        r"relative",
        r"\\host\share",
        r"C:\dir\..\other",
        r"C:\dir:stream",
        "C:\\quoted\" FLAGS=1",
        r"C:\%TEMP%\agent",
        "C:\\trailing ",
        "C:\\newline\n",
    ] {
        assert!(!valid_directory(path), "{path}");
    }
    assert!(valid_directory(DIRECTORY));
    assert!(valid_directory(&format!("{DIRECTORY}\\")));
}
