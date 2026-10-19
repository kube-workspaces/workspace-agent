use kw_management::updates::{
    digest,
    journal::{
        Ack, Action, ActionReceipt, Context, Error, Event, Journal, Plan, Snapshot, Store,
        Transition, ATTEMPT_SECONDS, MAX_JOURNAL_SEQUENCE,
    },
};

const START: i64 = 1700000000;
const FIXTURE: &str = include_str!("testdata/journal-v1.json");

fn plan() -> Plan {
    serde_json::from_str::<Snapshot>(FIXTURE).unwrap().plan
}
fn head(raw: &[u8]) -> String {
    let mut data = b"kw-agent-upgrade-journal/v1\0".to_vec();
    data.extend_from_slice(raw);
    digest(&data)
}

struct MemoryStore {
    raw: Vec<u8>,
    writes: usize,
    fail: bool,
    lose_reply: bool,
}
impl Store for MemoryStore {
    fn compare_and_swap(&mut self, expected: &str, next: &[u8]) -> Result<(), Error> {
        if head(&self.raw) != expected {
            return Err(Error::Conflict);
        }
        if self.fail {
            return Err(Error::Persistence);
        }
        self.raw = next.to_vec();
        self.writes += 1;
        if self.lose_reply {
            return Err(Error::Persistence);
        }
        Ok(())
    }
}

fn rig(plan: Plan) -> (Journal, MemoryStore, Context) {
    let j = Journal::new(plan.clone(), 1, START).unwrap();
    let store = MemoryStore {
        raw: j.encode(),
        writes: 0,
        fail: false,
        lose_reply: false,
    };
    let c = Context {
        binding: plan.binding,
        owner_fence: 1,
        now: START,
        boot_id: "boot-1".into(),
        authorized: true,
        recording_available: true,
        installer_busy: false,
    };
    (j, store, c)
}

fn event(kind: &str) -> Event {
    Event {
        kind: kind.into(),
        receipt: None,
    }
}
fn ack(t: &Transition, kind: &str) -> Ack {
    Ack {
        sequence: t.sequence(),
        sha256: t.sha256(),
        kind: kind.into(),
    }
}

fn apply(j: &Journal, s: &mut MemoryStore, c: &mut Context, e: Event) -> (Journal, Option<Action>) {
    c.now += 1;
    let transition = j.prepare(&e, c).unwrap();
    let receipt = ack(
        &transition,
        if e.kind == "begin" {
            "intent"
        } else if e.kind == "finalize" {
            "result"
        } else {
            ""
        },
    );
    transition.commit(s, c, Some(&receipt)).unwrap()
}

fn ok_receipt(j: &Journal) -> ActionReceipt {
    let a = j.snapshot().active.as_ref().unwrap();
    let p = &j.snapshot().plan;
    let mut r = ActionReceipt {
        sequence: a.sequence,
        kind: a.kind.clone(),
        outcome: "ok".into(),
        msi_code: None,
        service_state: String::new(),
        product_code: String::new(),
        target_absent: false,
        driver_sha256: String::new(),
        identity_verified: false,
        health_verified: false,
    };
    match a.kind.as_str() {
        "stop_agent" => r.service_state = "stopped".into(),
        "start_agent" => r.service_state = "running".into(),
        "install_target_msi" => {
            r.msi_code = Some(0);
            r.product_code = p.target_product_code.clone();
        }
        "uninstall_target_msi" => {
            r.msi_code = Some(0);
            r.target_absent = true;
        }
        "install_previous_msi" => {
            r.msi_code = Some(0);
            r.product_code = p.previous_product_code.clone();
        }
        "install_target_driver" => r.driver_sha256 = p.target_driver_sha256.clone(),
        "restore_previous_driver" => r.driver_sha256 = p.previous_driver_sha256.clone(),
        "verify_target" => {
            r.product_code = p.target_product_code.clone();
            r.driver_sha256 = p.target_driver_sha256.clone();
            r.identity_verified = true;
            r.health_verified = true;
        }
        "verify_previous" => {
            r.product_code = p.previous_product_code.clone();
            r.driver_sha256 = p.previous_driver_sha256.clone();
            r.identity_verified = true;
            r.health_verified = true;
        }
        _ => {}
    }
    r
}

fn complete(r: ActionReceipt) -> Event {
    Event {
        kind: "complete".into(),
        receipt: Some(r),
    }
}
fn round(j: Journal, s: &mut MemoryStore, c: &mut Context) -> Journal {
    let (j, _) = apply(&j, s, c, event("begin"));
    let r = ok_receipt(&j);
    apply(&j, s, c, complete(r)).0
}

#[test]
fn shared_write_ahead_fixture_and_restart() {
    let (j, mut s, mut c) = rig(plan());
    let j = round(j, &mut s, &mut c);
    let (j, a) = apply(&j, &mut s, &mut c, event("begin"));
    let a = a.unwrap();
    assert_eq!(a.kind, "install_target_msi");
    assert_eq!(a.sequence, 3);
    assert_eq!(j.encode(), FIXTURE.trim().as_bytes());
    let reloaded = Journal::decode(&s.raw, &j.snapshot().plan.sha256(), &head(&s.raw), 3).unwrap();
    assert_eq!(reloaded.recovery(&c), "reconcile_action");
    c.installer_busy = true;
    assert_eq!(reloaded.recovery(&c), "wait_transaction");
    c.installer_busy = false;
    assert_eq!(
        reloaded.prepare(&event("begin"), &c).unwrap_err(),
        Error::Transition
    );
    let r = ok_receipt(&reloaded);
    let (reloaded, _) = apply(&reloaded, &mut s, &mut c, complete(r));
    assert_eq!(reloaded.snapshot().step, 2);
}

#[test]
fn exact_ack_and_durable_cas_precede_effects() {
    for failure in [
        "no-ack",
        "wrong-digest",
        "wrong-sequence",
        "wrong-kind",
        "before-write",
        "lost-reply",
        "changed-boot",
        "changed-epoch",
    ] {
        let (j, mut s, mut c) = rig(plan());
        c.now += 1;
        let transition = j.prepare(&event("begin"), &c).unwrap();
        let retry = j.prepare(&event("begin"), &c).unwrap();
        let mut a = Some(ack(&transition, "intent"));
        let want = match failure {
            "no-ack" => {
                a = None;
                Error::Recording
            }
            "wrong-digest" => {
                a.as_mut().unwrap().sha256 = "0".repeat(64);
                Error::Recording
            }
            "wrong-sequence" => {
                a.as_mut().unwrap().sequence += 1;
                Error::Recording
            }
            "wrong-kind" => {
                a.as_mut().unwrap().kind = "result".into();
                Error::Recording
            }
            "before-write" => {
                s.fail = true;
                Error::Persistence
            }
            "lost-reply" => {
                s.lose_reply = true;
                Error::Persistence
            }
            "changed-boot" => {
                c.boot_id = "boot-2".into();
                Error::Fence
            }
            _ => {
                c.binding.revocation_epoch += 1;
                Error::Fence
            }
        };
        assert_eq!(
            transition.commit(&mut s, &c, a.as_ref()).unwrap_err(),
            want,
            "{failure}"
        );
        if failure == "lost-reply" {
            let reloaded =
                Journal::decode(&s.raw, &j.snapshot().plan.sha256(), &head(&s.raw), 1).unwrap();
            assert_eq!(reloaded.recovery(&c), "reconcile_action");
            assert_eq!(
                retry.commit(&mut s, &c, a.as_ref()).unwrap_err(),
                Error::Conflict
            );
        } else {
            assert_eq!(s.writes, 0, "denied transition wrote state: {failure}");
        }
    }
}

#[test]
fn takeover_and_concurrent_writers_are_fenced() {
    let (j, mut s, mut c) = rig(plan());
    c.now += 1;
    let first = j.prepare(&event("begin"), &c).unwrap();
    let second = j.prepare(&event("begin"), &c).unwrap();
    let a = ack(&first, "intent");
    let (j, action) = first.commit(&mut s, &c, Some(&a)).unwrap();
    assert!(action.is_some());
    assert_eq!(
        second.commit(&mut s, &c, Some(&a)).unwrap_err(),
        Error::Conflict
    );
    let old = c.clone();
    c.owner_fence = 2;
    let (j, _) = apply(&j, &mut s, &mut c, event("claim"));
    assert_eq!(j.recovery(&old), "fenced");
    assert_eq!(j.recovery(&c), "reconcile_action");
    assert_eq!(j.prepare(&event("claim"), &c).unwrap_err(), Error::Fence);
}

#[test]
fn health_and_off_guest_result_are_required_for_success() {
    let (mut j, mut s, mut c) = rig(plan());
    while j.snapshot().phase == "ready" {
        j = apply(&j, &mut s, &mut c, event("begin")).0;
        let mut r = ok_receipt(&j);
        if r.kind == "verify_target" {
            r.health_verified = false;
            assert_eq!(
                j.prepare(&complete(r.clone()), &c).unwrap_err(),
                Error::Transition
            );
            r.health_verified = true;
            r.identity_verified = false;
            assert_eq!(
                j.prepare(&complete(r.clone()), &c).unwrap_err(),
                Error::Transition
            );
            r.identity_verified = true;
        }
        j = apply(&j, &mut s, &mut c, complete(r)).0;
    }
    assert_eq!(j.snapshot().phase, "result_pending");
    assert_eq!(j.snapshot().result, "succeeded");
    assert_eq!(j.recovery(&c), "commit_result");
    c.now += 1;
    let missing = j.prepare(&event("finalize"), &c).unwrap();
    assert_eq!(
        missing.commit(&mut s, &c, None).unwrap_err(),
        Error::Recording
    );
    let t = j.prepare(&event("finalize"), &c).unwrap();
    let a = ack(&t, "result");
    let (j, action) = t.commit(&mut s, &c, Some(&a)).unwrap();
    assert!(action.is_none());
    assert_eq!(j.recovery(&c), "report_result");
    assert_eq!(
        j.prepare(&event("begin"), &c).unwrap_err(),
        Error::Transition
    );
}

#[test]
fn cancellation_restores_service_or_admits_rollback() {
    let (j, mut s, mut c) = rig(plan());
    let j = round(j, &mut s, &mut c);
    let (j, _) = apply(&j, &mut s, &mut c, event("cancel"));
    assert_eq!(j.snapshot().flow, "cleanup");
    assert!(j.snapshot().result.is_empty());
    let j = round(j, &mut s, &mut c);
    assert_eq!(j.snapshot().result, "cancelled");
    assert!(!j.snapshot().service_needs_restore && !j.snapshot().mutated);

    let (j, mut s, mut c) = rig(plan());
    let j = round(j, &mut s, &mut c);
    let (j, _) = apply(&j, &mut s, &mut c, event("begin"));
    let (j, _) = apply(&j, &mut s, &mut c, event("cancel"));
    assert!(j.snapshot().active.is_some());
    let r = ok_receipt(&j);
    let (j, _) = apply(&j, &mut s, &mut c, complete(r));
    assert_eq!(j.snapshot().phase, "rollback_pending");
    assert_eq!(j.recovery(&c), "admit_rollback");
    assert_eq!(
        j.prepare(&event("begin"), &c).unwrap_err(),
        Error::Transition
    );
    let (mut j, _) = apply(&j, &mut s, &mut c, event("rollback"));
    while j.snapshot().phase == "ready" {
        j = round(j, &mut s, &mut c);
    }
    assert_eq!(j.snapshot().result, "rolled_back");
    assert!(!j.snapshot().service_needs_restore);
}

#[test]
fn msi_reboot_codes_do_not_mean_success_or_reboot_retry() {
    for allow in [false, true] {
        let mut p = plan();
        p.allow_reboot = allow;
        let (j, mut s, mut c) = rig(p);
        let j = round(j, &mut s, &mut c);
        let (j, _) = apply(&j, &mut s, &mut c, event("begin"));
        let mut r = ok_receipt(&j);
        r.msi_code = Some(3010);
        assert_eq!(
            j.prepare(&complete(r.clone()), &c).unwrap_err(),
            Error::Transition
        );
        r.outcome = "reboot_required".into();
        let (j, _) = apply(&j, &mut s, &mut c, complete(r));
        assert_eq!(j.snapshot().phase, "awaiting_reboot");
        assert!(j.snapshot().result.is_empty());
        assert_eq!(
            j.prepare(&event("observe_boot"), &c).unwrap_err(),
            Error::Transition
        );
        if allow {
            let (j, a) = apply(&j, &mut s, &mut c, event("begin"));
            assert_eq!(a.unwrap().kind, "reboot");
            assert_eq!(j.recovery(&c), "wait_reboot");
            assert_eq!(
                j.prepare(&event("begin"), &c).unwrap_err(),
                Error::Transition
            );
            c.now += 3600;
            c.boot_id = "boot-2".into();
            let (j, _) = apply(&j, &mut s, &mut c, event("observe_boot"));
            assert_eq!(j.snapshot().phase, "ready");
            assert_eq!(j.snapshot().reboot_count, 1);
            assert!(j.snapshot().expires_at > START + ATTEMPT_SECONDS);
        } else {
            assert_eq!(j.recovery(&c), "wait_reboot");
        }
    }
}

#[test]
fn authority_outages_clock_and_uncertain_completion_do_not_dispatch() {
    let (j, mut s, mut c) = rig(plan());
    for mode in ["revoked", "recording", "foreign-vm", "clock", "deadline"] {
        let mut bad = c.clone();
        match mode {
            "revoked" => bad.authorized = false,
            "recording" => bad.recording_available = false,
            "foreign-vm" => bad.binding.vm_uid = "another-vm".into(),
            "clock" => bad.now -= 1,
            _ => bad.now += ATTEMPT_SECONDS + 1,
        }
        assert!(j.prepare(&event("begin"), &bad).is_err(), "accepted {mode}");
    }
    let (j, _) = apply(&j, &mut s, &mut c, event("begin"));
    let (j, _) = apply(&j, &mut s, &mut c, event("recording_lost"));
    assert!(j.snapshot().active.is_some());
    assert_eq!(j.snapshot().result, "recording_lost");
    let (j, _) = apply(&j, &mut s, &mut c, event("finalize"));
    assert_eq!(j.recovery(&c), "manual_recovery");
}

#[test]
fn codec_denies_rollback_corruption_and_ambiguous_json() {
    let (j, mut s, mut c) = rig(plan());
    let j = round(j, &mut s, &mut c);
    let pd = j.snapshot().plan.sha256();
    assert_eq!(
        Journal::decode(&j.encode(), &pd, &j.sha256(), j.snapshot().sequence + 1).unwrap_err(),
        Error::Journal
    );
    assert_eq!(
        Journal::decode(&j.encode(), &"4".repeat(64), &j.sha256(), 0).unwrap_err(),
        Error::Journal
    );
    let mutations: [fn(&mut Snapshot); 7] = [
        |s| {
            s.phase = "active".into();
            s.active = None;
        },
        |s| s.plan.binding.vm_uid = "other-vm".into(),
        |s| s.sequence = MAX_JOURNAL_SEQUENCE + 1,
        |s| {
            s.result = "succeeded".into();
            s.phase = "terminal".into();
        },
        |s| s.reboot_count = 2,
        |s| s.updated_at = s.started_at - 1,
        |s| s.last_receipt.as_mut().unwrap().service_state = "arbitrary-log-text".into(),
    ];
    for mutate in mutations {
        let mut state = j.snapshot().clone();
        mutate(&mut state);
        let raw = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            Journal::decode(&raw, &pd, &head(&raw), 0).unwrap_err(),
            Error::Journal
        );
    }
    let raw = String::from_utf8(j.encode()).unwrap();
    for changed in [
        format!("{raw} "),
        raw.replacen(r#""version":1"#, r#""version":1,"Version":1"#, 1),
        raw.replacen(r#""version":1"#, r#""version":1,"version":1"#, 1),
    ] {
        assert_eq!(
            Journal::decode(changed.as_bytes(), &pd, &head(changed.as_bytes()), 0).unwrap_err(),
            Error::Journal
        );
    }
}
