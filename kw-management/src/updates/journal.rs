//! Offline write-ahead checkpoint/recovery model. The Store contract requires
//! durable CAS; native ACL/locking/flush/installer adapters are not supplied here.

use super::{digest, identifier, valid_digest, valid_guid, AGENT_UPGRADE_CODE};
use serde::{Deserialize, Serialize};

pub const MAX_JOURNAL_BYTES: usize = 16 * 1024;
pub const MAX_JOURNAL_SEQUENCE: u64 = 1_000_000;
pub const ATTEMPT_SECONDS: i64 = 15 * 60;
pub const REBOOT_WAIT_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Journal,
    Fence,
    Transition,
    Clock,
    Recording,
    Persistence,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub attempt_id: String,
    pub namespace: String,
    pub workspace_name: String,
    pub workspace_uid: String,
    pub vm_uid: String,
    pub revocation_epoch: u64,
    pub actor_uid: String,
    pub recording_id: String,
    pub target_sha256: String,
    pub previous_sha256: String,
    pub inventory_sha256: String,
}

/// A structural projection of verified manifests and authenticated inventory;
/// this type is not itself artifact trust or an installation grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub binding: Binding,
    pub target_product_code: String,
    pub previous_product_code: String,
    pub target_driver_sha256: String,
    pub previous_driver_sha256: String,
    pub allow_reboot: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub sequence: u64,
    pub kind: String,
    pub boot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    pub sequence: u64,
    pub kind: String,
    pub outcome: String,
    pub msi_code: Option<i64>,
    pub service_state: String,
    pub product_code: String,
    pub target_absent: bool,
    pub driver_sha256: String,
    pub identity_verified: bool,
    pub health_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub plan: Plan,
    pub sequence: u64,
    pub owner_fence: u64,
    pub phase: String,
    pub flow: String,
    pub step: u32,
    pub active: Option<Action>,
    pub last_receipt: Option<ActionReceipt>,
    pub mutated: bool,
    pub service_needs_restore: bool,
    pub cancel_requested: bool,
    pub reboot_count: u32,
    pub wait_boot_id: String,
    pub waiting_since: i64,
    pub started_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub cleanup_result: String,
    pub result: String,
}

#[derive(Clone, Debug)]
pub struct Journal {
    snapshot: Snapshot,
}

#[derive(Clone, Debug)]
pub struct Context {
    pub binding: Binding,
    pub owner_fence: u64,
    pub now: i64,
    pub boot_id: String,
    pub authorized: bool,
    pub recording_available: bool,
    pub installer_busy: bool,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: String,
    pub receipt: Option<ActionReceipt>,
}

/// Must atomically flush the new checkpoint only when the trusted current head
/// matches expected. An uncertain/lost write reply is an error, not success.
pub trait Store {
    fn compare_and_swap(&mut self, expected: &str, next: &[u8]) -> Result<(), Error>;
}

pub struct Ack {
    pub sequence: u64,
    pub sha256: String,
    pub kind: String,
}

#[derive(Debug)]
pub struct Transition {
    previous: String,
    boot_id: String,
    next: Journal,
    effect: Option<Action>,
    ack_kind: String,
}

/// A single-use local dispatch capability. Only a successfully persisted and
/// off-guest-acknowledged transition can create it; recovery cannot reconstruct
/// one from a serialized Action. Current phase authority must still be checked
/// immediately before the native effect.
#[derive(Debug)]
pub struct CommittedAction {
    action: Action,
    plan: Plan,
    owner_fence: u64,
}

impl CommittedAction {
    pub(super) fn into_parts(self) -> (Action, Plan, u64) {
        (self.action, self.plan, self.owner_fence)
    }
}

fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
    // This schema contains no custom serializers, floating point or map keys.
    serde_json::to_vec(value).expect("journal schema serialization is infallible")
}

impl Plan {
    pub fn sha256(&self) -> String {
        let mut raw = b"kw-agent-upgrade-plan/v1\0".to_vec();
        raw.extend_from_slice(&encoded(self));
        digest(&raw)
    }

    fn valid(&self) -> bool {
        let b = &self.binding;
        if [
            &b.attempt_id,
            &b.namespace,
            &b.workspace_name,
            &b.workspace_uid,
            &b.vm_uid,
            &b.actor_uid,
            &b.recording_id,
        ]
        .iter()
        .any(|s| !identifier(s))
        {
            return false;
        }
        if b.revocation_epoch > i64::MAX as u64
            || !valid_digest(&b.target_sha256)
            || !valid_digest(&b.previous_sha256)
            || b.target_sha256 == b.previous_sha256
            || !valid_digest(&b.inventory_sha256)
        {
            return false;
        }
        if !valid_guid(&self.target_product_code)
            || !valid_guid(&self.previous_product_code)
            || self.target_product_code == self.previous_product_code
            || self.target_product_code == AGENT_UPGRADE_CODE
            || self.previous_product_code == AGENT_UPGRADE_CODE
            || self.target_product_code == "00000000-0000-0000-0000-000000000000"
            || self.previous_product_code == "00000000-0000-0000-0000-000000000000"
        {
            return false;
        }
        (self.target_driver_sha256.is_empty() && self.previous_driver_sha256.is_empty())
            || (valid_digest(&self.target_driver_sha256)
                && valid_digest(&self.previous_driver_sha256))
    }
}

fn valid_time(now: i64) -> bool {
    now > 0 && now <= i64::MAX - 2 * REBOOT_WAIT_SECONDS - ATTEMPT_SECONDS
}

impl Journal {
    pub fn new(plan: Plan, owner: u64, now: i64) -> Result<Self, Error> {
        if !plan.valid() || owner == 0 || owner > i64::MAX as u64 || !valid_time(now) {
            return Err(Error::Journal);
        }
        Ok(Self {
            snapshot: Snapshot {
                version: 1,
                plan,
                sequence: 0,
                owner_fence: owner,
                phase: "ready".into(),
                flow: "forward".into(),
                step: 0,
                active: None,
                last_receipt: None,
                mutated: false,
                service_needs_restore: false,
                cancel_requested: false,
                reboot_count: 0,
                wait_boot_id: String::new(),
                waiting_since: 0,
                started_at: now,
                updated_at: now,
                expires_at: now + ATTEMPT_SECONDS,
                cleanup_result: String::new(),
                result: String::new(),
            },
        })
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn encode(&self) -> Vec<u8> {
        encoded(&self.snapshot)
    }
    pub fn sha256(&self) -> String {
        let mut raw = b"kw-agent-upgrade-journal/v1\0".to_vec();
        raw.extend_from_slice(&self.encode());
        digest(&raw)
    }

    /// Digest/floor must come from the trusted durable head and admitted plan,
    /// not from the guest report being decoded. A hash alone is not authority.
    pub fn decode(
        raw: &[u8],
        plan_digest: &str,
        checkpoint_digest: &str,
        minimum_sequence: u64,
    ) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_JOURNAL_BYTES {
            return Err(Error::Journal);
        }
        let snapshot: Snapshot = serde_json::from_slice(raw).map_err(|_| Error::Journal)?;
        let j = Self { snapshot };
        if !j.valid()
            || j.snapshot.sequence < minimum_sequence
            || j.snapshot.plan.sha256() != plan_digest
            || j.sha256() != checkpoint_digest
            || j.encode() != raw
        {
            return Err(Error::Journal);
        }
        Ok(j)
    }

    fn actions(&self) -> Vec<&'static str> {
        let mut actions = match self.snapshot.flow.as_str() {
            "forward" => vec!["stop_agent", "install_target_msi"],
            "rollback" => vec!["stop_agent", "uninstall_target_msi", "install_previous_msi"],
            "cleanup" => return vec!["start_agent"],
            _ => return vec![],
        };
        if !self.snapshot.plan.target_driver_sha256.is_empty() {
            actions.push(if self.snapshot.flow == "forward" {
                "install_target_driver"
            } else {
                "restore_previous_driver"
            });
        }
        actions.push("start_agent");
        actions.push(if self.snapshot.flow == "forward" {
            "verify_target"
        } else {
            "verify_previous"
        });
        actions
    }

    fn valid(&self) -> bool {
        let s = &self.snapshot;
        if s.version != 1
            || !s.plan.valid()
            || s.sequence > MAX_JOURNAL_SEQUENCE
            || s.owner_fence == 0
            || s.owner_fence > i64::MAX as u64
            || !valid_time(s.started_at)
            || !valid_time(s.updated_at)
            || s.updated_at < s.started_at
            || s.expires_at < s.started_at + ATTEMPT_SECONDS
            || s.expires_at > s.started_at + ATTEMPT_SECONDS + REBOOT_WAIT_SECONDS
            || s.reboot_count > 1
        {
            return false;
        }
        let actions = self.actions();
        if actions.is_empty() || s.step as usize > actions.len() {
            return false;
        }
        if s.sequence < u64::from(s.step) * 2
            || (s.step > 0 && s.last_receipt.is_none())
            || (s.flow == "rollback" && !s.mutated)
            || (s.flow == "cleanup" && s.mutated)
            || (s.flow == "forward" && s.step > 1 && !s.mutated)
        {
            return false;
        }
        if s.flow == "cleanup" && !["cancelled", "failed"].contains(&s.cleanup_result.as_str()) {
            return false;
        }
        if s.flow != "cleanup" && !s.cleanup_result.is_empty() {
            return false;
        }
        match s.phase.as_str() {
            "ready" => {
                if s.active.is_some() || s.step as usize >= actions.len() || !s.result.is_empty() {
                    return false;
                }
            }
            "active" => {
                if s.active.is_none()
                    || s.step as usize >= actions.len()
                    || s.active.as_ref().map(|a| a.kind.as_str())
                        != actions.get(s.step as usize).copied()
                    || !s.result.is_empty()
                {
                    return false;
                }
            }
            "rollback_pending" => {
                if s.active.is_some() || !s.mutated || s.flow != "forward" || !s.result.is_empty() {
                    return false;
                }
            }
            "awaiting_reboot" => {
                if s.waiting_since == 0
                    || !identifier(&s.wait_boot_id)
                    || !s.result.is_empty()
                    || (s.reboot_count == 1 && s.active.is_none())
                {
                    return false;
                }
                if let Some(a) = &s.active {
                    if a.kind != "reboot" || s.reboot_count != 1 || a.boot_id != s.wait_boot_id {
                        return false;
                    }
                }
            }
            "result_pending" | "terminal" => {
                if !valid_result(&s.result)
                    || (s.active.is_some()
                        && !["manual_recovery_required", "recording_lost"]
                            .contains(&s.result.as_str()))
                {
                    return false;
                }
                if s.result == "succeeded"
                    && (s.service_needs_restore
                        || s.flow != "forward"
                        || s.step as usize != actions.len()
                        || !self.health_receipt(s.last_receipt.as_ref(), "verify_target"))
                {
                    return false;
                }
                if s.result == "rolled_back"
                    && (s.service_needs_restore
                        || s.flow != "rollback"
                        || s.step as usize != actions.len()
                        || !self.health_receipt(s.last_receipt.as_ref(), "verify_previous"))
                {
                    return false;
                }
                if s.result == "cancelled" && (s.mutated || s.service_needs_restore) {
                    return false;
                }
            }
            _ => return false,
        }
        if s.phase != "awaiting_reboot" && (s.waiting_since != 0 || !s.wait_boot_id.is_empty()) {
            return false;
        }
        if s.waiting_since < 0 || s.waiting_since > s.updated_at {
            return false;
        }
        if let Some(a) = &s.active {
            if a.sequence == 0
                || a.sequence > s.sequence
                || !identifier(&a.boot_id)
                || (a.kind == "reboot" && s.reboot_count != 1)
            {
                return false;
            }
            if a.kind != "reboot" && actions.get(s.step as usize).copied() != Some(a.kind.as_str())
            {
                return false;
            }
            if mutating_action(&a.kind) && !s.mutated {
                return false;
            }
            if ["stop_agent", "start_agent"].contains(&a.kind.as_str()) && !s.service_needs_restore
            {
                return false;
            }
        }
        if let Some(r) = &s.last_receipt {
            if r.sequence == 0 || r.sequence > s.sequence || !self.receipt_valid(r) {
                return false;
            }
        }
        true
    }

    fn check(&self, c: &Context, claim: bool) -> Result<(), Error> {
        if !self.valid() {
            return Err(Error::Journal);
        }
        if c.binding != self.snapshot.plan.binding
            || (!claim && c.owner_fence != self.snapshot.owner_fence)
            || (claim
                && (c.owner_fence <= self.snapshot.owner_fence || c.owner_fence > i64::MAX as u64))
        {
            return Err(Error::Fence);
        }
        if !valid_time(c.now) || c.now < self.snapshot.updated_at || !identifier(&c.boot_id) {
            return Err(Error::Clock);
        }
        Ok(())
    }

    pub fn prepare(&self, event: &Event, c: &Context) -> Result<Transition, Error> {
        self.check(c, event.kind == "claim")?;
        if self.snapshot.phase == "terminal" || self.snapshot.sequence >= MAX_JOURNAL_SEQUENCE {
            return Err(Error::Transition);
        }
        let mut n = self.clone();
        n.snapshot.sequence += 1;
        n.snapshot.updated_at = c.now;
        let mut effect = None;
        let mut ack_kind = String::new();
        match event.kind.as_str() {
            "begin" => {
                if !c.authorized || !c.recording_available || c.installer_busy {
                    return Err(Error::Transition);
                }
                let kind = match n.snapshot.phase.as_str() {
                    "ready" => {
                        if c.now > n.snapshot.expires_at {
                            return Err(Error::Clock);
                        }
                        let k = n.actions()[n.snapshot.step as usize];
                        n.snapshot.phase = "active".into();
                        k
                    }
                    "awaiting_reboot" => {
                        let s = &mut n.snapshot;
                        if s.active.is_some()
                            || c.boot_id != s.wait_boot_id
                            || c.now - s.waiting_since > REBOOT_WAIT_SECONDS
                            || !s.plan.allow_reboot
                            || s.reboot_count != 0
                        {
                            return Err(Error::Transition);
                        }
                        s.reboot_count = 1;
                        "reboot"
                    }
                    _ => return Err(Error::Transition),
                };
                n.snapshot.active = Some(Action {
                    sequence: n.snapshot.sequence,
                    kind: kind.into(),
                    boot_id: c.boot_id.clone(),
                });
                if ["stop_agent", "start_agent"].contains(&kind) {
                    n.snapshot.service_needs_restore = true;
                }
                if mutating_action(kind) {
                    n.snapshot.mutated = true;
                }
                effect = n.snapshot.active.clone();
                ack_kind = "intent".into();
            }
            "complete" => {
                let a = n.snapshot.active.as_ref().ok_or(Error::Transition)?;
                let r = event.receipt.as_ref().ok_or(Error::Transition)?;
                if n.snapshot.phase != "active"
                    || r.sequence != a.sequence
                    || r.kind != a.kind
                    || !n.receipt_valid(r)
                {
                    return Err(Error::Transition);
                }
                n.snapshot.last_receipt = Some(r.clone());
                n.snapshot.active = None;
                if r.outcome == "failed" {
                    n.failed_action();
                } else {
                    if r.kind == "start_agent" {
                        n.snapshot.service_needs_restore = false;
                    }
                    n.snapshot.step += 1;
                    if r.outcome == "reboot_required" {
                        if n.snapshot.reboot_count != 0 {
                            n.result("manual_recovery_required");
                        } else {
                            n.snapshot.phase = "awaiting_reboot".into();
                            n.snapshot.waiting_since = c.now;
                            n.snapshot.wait_boot_id = c.boot_id.clone();
                        }
                    } else {
                        n.after_action();
                    }
                }
            }
            "cancel" => {
                let s = &mut n.snapshot;
                if !c.authorized
                    || s.cancel_requested
                    || s.phase == "result_pending"
                    || s.flow != "forward"
                {
                    return Err(Error::Transition);
                }
                s.cancel_requested = true;
                if s.phase == "ready" {
                    n.after_action();
                }
            }
            "rollback" => {
                let s = &mut n.snapshot;
                if !c.authorized
                    || !c.recording_available
                    || s.phase != "rollback_pending"
                    || c.now > s.expires_at
                {
                    return Err(Error::Transition);
                }
                s.flow = "rollback".into();
                s.step = 0;
                s.phase = "ready".into();
            }
            "observe_boot" => {
                let s = &mut n.snapshot;
                if s.phase != "awaiting_reboot" || c.boot_id == s.wait_boot_id {
                    return Err(Error::Transition);
                }
                if c.now - s.waiting_since > REBOOT_WAIT_SECONDS {
                    n.result("manual_recovery_required");
                } else {
                    s.expires_at += c.now - s.waiting_since;
                    s.active = None;
                    s.reboot_count = 1;
                    s.waiting_since = 0;
                    s.wait_boot_id.clear();
                    n.after_action();
                }
            }
            "claim" => {
                if !c.authorized {
                    return Err(Error::Fence);
                }
                n.snapshot.owner_fence = c.owner_fence;
            }
            "manual" => n.result("manual_recovery_required"),
            "recording_lost" => n.result("recording_lost"),
            "finalize" => {
                if n.snapshot.phase != "result_pending" || !c.recording_available {
                    return Err(Error::Transition);
                }
                n.snapshot.phase = "terminal".into();
                ack_kind = "result".into();
            }
            _ => return Err(Error::Transition),
        }
        if !n.valid() {
            return Err(Error::Journal);
        }
        Ok(Transition {
            previous: self.sha256(),
            boot_id: c.boot_id.clone(),
            next: n,
            effect,
            ack_kind,
        })
    }

    fn result(&mut self, result: &str) {
        self.snapshot.phase = "result_pending".into();
        self.snapshot.result = result.into();
        self.snapshot.waiting_since = 0;
        self.snapshot.wait_boot_id.clear();
    }

    fn failed_action(&mut self) {
        let s = &mut self.snapshot;
        if s.flow != "forward" {
            self.result("manual_recovery_required");
        } else if s.mutated {
            s.phase = "rollback_pending".into();
        } else if s.service_needs_restore {
            s.flow = "cleanup".into();
            s.step = 0;
            s.phase = "ready".into();
            s.cleanup_result = "failed".into();
        } else {
            self.result("failed");
        }
    }

    fn after_action(&mut self) {
        let length = self.actions().len();
        let s = &mut self.snapshot;
        if s.flow == "forward" && s.cancel_requested {
            if s.mutated {
                s.phase = "rollback_pending".into();
            } else if s.service_needs_restore {
                s.flow = "cleanup".into();
                s.step = 0;
                s.phase = "ready".into();
                s.cleanup_result = "cancelled".into();
            } else {
                self.result("cancelled");
            }
        } else if s.step as usize == length {
            let result = match s.flow.as_str() {
                "forward" => "succeeded",
                "rollback" => "rolled_back",
                _ => &s.cleanup_result,
            }
            .to_owned();
            self.result(&result);
        } else {
            s.phase = "ready".into();
        }
    }

    fn health_receipt(&self, r: Option<&ActionReceipt>, kind: &str) -> bool {
        let Some(r) = r else {
            return false;
        };
        if r.kind != kind || r.outcome != "ok" || !r.identity_verified || !r.health_verified {
            return false;
        }
        let p = &self.snapshot.plan;
        let (product, driver) = if kind == "verify_previous" {
            (&p.previous_product_code, &p.previous_driver_sha256)
        } else {
            (&p.target_product_code, &p.target_driver_sha256)
        };
        r.product_code == *product && (driver.is_empty() || r.driver_sha256 == *driver)
    }

    fn receipt_valid(&self, r: &ActionReceipt) -> bool {
        if !["", "unknown", "stopped", "running"].contains(&r.service_state.as_str())
            || (!r.product_code.is_empty()
                && (!valid_guid(&r.product_code)
                    || r.product_code == "00000000-0000-0000-0000-000000000000"))
            || (!r.driver_sha256.is_empty() && !valid_digest(&r.driver_sha256))
        {
            return false;
        }
        if !["ok", "failed", "reboot_required"].contains(&r.outcome.as_str()) {
            return false;
        }
        let msi = [
            "install_target_msi",
            "uninstall_target_msi",
            "install_previous_msi",
        ]
        .contains(&r.kind.as_str());
        if msi {
            let Some(code) = r.msi_code else {
                return false;
            };
            if code < 0 || code > i64::from(u32::MAX) {
                return false;
            }
            let expected = match code {
                0 => "ok",
                3010 | 1641 => "reboot_required",
                _ => "failed",
            };
            if r.outcome != expected {
                return false;
            }
        } else if r.msi_code.is_some() {
            return false;
        }
        if r.outcome == "failed" {
            return [
                "stop_agent",
                "start_agent",
                "install_target_msi",
                "uninstall_target_msi",
                "install_previous_msi",
                "install_target_driver",
                "restore_previous_driver",
                "verify_target",
                "verify_previous",
            ]
            .contains(&r.kind.as_str());
        }
        if r.outcome == "reboot_required" {
            return msi
                || ["install_target_driver", "restore_previous_driver"].contains(&r.kind.as_str());
        }
        let p = &self.snapshot.plan;
        match r.kind.as_str() {
            "stop_agent" => r.service_state == "stopped",
            "start_agent" => r.service_state == "running",
            "install_target_msi" => r.product_code == p.target_product_code,
            "uninstall_target_msi" => r.target_absent,
            "install_previous_msi" => r.product_code == p.previous_product_code,
            "install_target_driver" => {
                !p.target_driver_sha256.is_empty() && r.driver_sha256 == p.target_driver_sha256
            }
            "restore_previous_driver" => {
                !p.previous_driver_sha256.is_empty() && r.driver_sha256 == p.previous_driver_sha256
            }
            "verify_target" | "verify_previous" => self.health_receipt(Some(r), &r.kind),
            _ => false,
        }
    }

    pub fn recovery(&self, c: &Context) -> &'static str {
        if self.check(c, false).is_err() {
            return "fenced";
        }
        let s = &self.snapshot;
        if s.phase == "result_pending" {
            return if s.active.is_some() && c.installer_busy {
                "wait_transaction"
            } else {
                "commit_result"
            };
        }
        if s.phase == "terminal" && s.active.is_some() {
            return if c.installer_busy {
                "wait_transaction"
            } else {
                "manual_recovery"
            };
        }
        if let Some(a) = &s.active {
            if a.kind != "reboot" {
                return if c.installer_busy {
                    "wait_transaction"
                } else {
                    "reconcile_action"
                };
            }
        }
        if s.phase == "awaiting_reboot" {
            if c.now - s.waiting_since > REBOOT_WAIT_SECONDS {
                return "manual_recovery";
            }
            if c.boot_id != s.wait_boot_id {
                return "observe_boot";
            }
            if s.active.is_some() || !s.plan.allow_reboot || s.reboot_count != 0 {
                return "wait_reboot";
            }
        }
        if s.phase == "terminal" {
            return "report_result";
        }
        if s.sequence >= MAX_JOURNAL_SEQUENCE {
            return "manual_recovery";
        }
        if !c.authorized {
            return "fenced";
        }
        if s.phase != "awaiting_reboot" && c.now > s.expires_at {
            return "manual_recovery";
        }
        if !c.recording_available {
            return "wait_recording";
        }
        if c.installer_busy {
            return "wait_transaction";
        }
        if s.phase == "rollback_pending" {
            return "admit_rollback";
        }
        "request_phase_permit"
    }
}

fn valid_result(s: &str) -> bool {
    [
        "succeeded",
        "rolled_back",
        "cancelled",
        "failed",
        "manual_recovery_required",
        "recording_lost",
    ]
    .contains(&s)
}
fn mutating_action(s: &str) -> bool {
    [
        "install_target_msi",
        "install_target_driver",
        "uninstall_target_msi",
        "install_previous_msi",
        "restore_previous_driver",
    ]
    .contains(&s)
}

impl Transition {
    /// Production adapter dispatch uses this consuming permit rather than the
    /// serializable Action descriptor returned by the offline model interface.
    pub fn commit_for_dispatch(
        self,
        store: &mut impl Store,
        c: &Context,
        ack: Option<&Ack>,
    ) -> Result<(Journal, Option<CommittedAction>), Error> {
        let (journal, action) = self.commit(store, c, ack)?;
        let permit = action.map(|action| CommittedAction {
            action,
            plan: journal.snapshot.plan.clone(),
            owner_fence: journal.snapshot.owner_fence,
        });
        Ok((journal, permit))
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.next.encode()
    }
    pub fn sha256(&self) -> String {
        self.next.sha256()
    }
    pub fn sequence(&self) -> u64 {
        self.next.snapshot.sequence
    }

    /// An action descriptor is returned only after durable CAS and exact
    /// off-guest intent acknowledgment. It is not a signed execution grant.
    pub fn commit(
        self,
        store: &mut impl Store,
        c: &Context,
        ack: Option<&Ack>,
    ) -> Result<(Journal, Option<Action>), Error> {
        self.next.check(c, false)?;
        if c.boot_id != self.boot_id {
            return Err(Error::Fence);
        }
        if let Some(a) = &self.effect {
            if !c.authorized
                || c.installer_busy
                || (a.kind != "reboot" && c.now > self.next.snapshot.expires_at)
            {
                return Err(Error::Fence);
            }
            if a.kind == "reboot" && c.now - self.next.snapshot.waiting_since > REBOOT_WAIT_SECONDS
            {
                return Err(Error::Clock);
            }
        }
        if !self.ack_kind.is_empty()
            && (!c.recording_available
                || ack.map_or(true, |a| {
                    a.sequence != self.sequence()
                        || a.sha256 != self.sha256()
                        || a.kind != self.ack_kind
                }))
        {
            return Err(Error::Recording);
        }
        if let Err(error) = store.compare_and_swap(&self.previous, &self.bytes()) {
            return Err(if error == Error::Conflict {
                error
            } else {
                Error::Persistence
            });
        }
        Ok((self.next, self.effect))
    }
}
