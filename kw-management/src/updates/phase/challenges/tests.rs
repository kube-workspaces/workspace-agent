use super::*;
use crate::updates::{
    digest,
    installer::PhaseAuthority,
    journal::Snapshot as JournalSnapshot,
    persistence::create_root,
    phase::{self, SignedPhaseAuthority},
};
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::HashMap, fs, io::BufRead};

const START: i64 = 1_700_000_000;

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("kw-phase-{}", digest(&random)));
        create_root(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (Plan, Action) {
    let j: JournalSnapshot =
        serde_json::from_str(include_str!("../../../../tests/testdata/journal-v1.json")).unwrap();
    (j.plan, j.active.unwrap())
}

struct Live {
    now: i64,
    peer: String,
    deny: bool,
}
impl Default for Live {
    fn default() -> Self {
        Self {
            now: START,
            peer: "a".repeat(64),
            deny: false,
        }
    }
}
impl LiveAuthority for Live {
    fn check(&mut self, _: &Plan, _: &Action, _: u64) -> Result<PeerContext, DispatchError> {
        if self.deny {
            Err(DispatchError::Authority)
        } else {
            Ok(PeerContext {
                peer_sha256: self.peer.clone(),
                now: self.now,
            })
        }
    }
}

fn issued(root: &Root) -> (DurableCurrentAuthority<Live>, Challenge) {
    let (plan, action) = fixture();
    let mut current = DurableCurrentAuthority::new(
        FileChallenges::initialize(&root.0).unwrap(),
        Live::default(),
    );
    let challenge = current.challenge(&plan, &action, 1).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(&challenge.nonce).unwrap().len(), 32);
    (current, challenge)
}

fn response(challenge: &Challenge) -> (Vec<u8>, Vec<u8>, String, HashMap<String, [u8; 32]>) {
    let permit = Permit {
        version: 1,
        audience: "agent-upgrade.phase.v1".into(),
        plan_sha256: challenge.plan_sha256.clone(),
        action: challenge.action.clone(),
        owner_fence: challenge.owner_fence,
        challenge: challenge.nonce.clone(),
        peer_sha256: challenge.peer_sha256.clone(),
        issued_at: START,
        expires_at: START + MAX_SECONDS,
    };
    let raw = permit.encode();
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let public = key.verifying_key().to_bytes();
    let id = digest(&public)[..32].to_owned();
    let mut message = phase::DOMAIN.to_vec();
    message.extend_from_slice(&raw);
    let signature = key.sign(&message).to_bytes().to_vec();
    (raw, signature, id.clone(), HashMap::from([(id, public)]))
}

#[test]
fn one_outstanding_challenge_exclusive_root_and_reopen() {
    let root = Root::new();
    let (mut current, c) = issued(&root);
    let (plan, action) = fixture();
    assert!(current.challenge(&plan, &action, 1).is_err());
    assert!(matches!(
        FileChallenges::reopen(&root.0),
        Err(Error::Conflict)
    ));
    assert!(FileChallenges::initialize(&root.0).is_err());
    drop(current);
    let store = FileChallenges::reopen(&root.0).unwrap();
    let mut current = DurableCurrentAuthority::new(store, Live::default());
    let (raw, sig, id, keys) = response(&c);
    let mut authority = SignedPhaseAuthority::new(raw, sig, id, keys, current);
    assert_eq!(authority.authorize(&plan, &action, 1), Ok(()));
    drop(authority);
    let store = FileChallenges::reopen(&root.0).unwrap();
    current = DurableCurrentAuthority::new(store, Live::default());
    assert!(current.check(&plan, &action, 1).is_err());
    let next = current.challenge(&plan, &action, 1).unwrap();
    assert_ne!(next.nonce, c.nonce);
    // Old signed bytes fail even with a newly outstanding challenge.
    let (raw, sig, id, keys) = response(&c);
    let mut authority = SignedPhaseAuthority::new(raw, sig, id, keys, current);
    assert!(authority.authorize(&plan, &action, 1).is_err());
    drop(authority);
    assert!(FileChallenges::reopen(&root.0)
        .unwrap()
        .head
        .pending
        .is_none());
}

#[test]
fn every_success_denial_binding_or_authority_outage_burns_durably() {
    for mutation in 0..14 {
        let root = Root::new();
        let (mut current, c) = issued(&root);
        let (mut plan, mut action) = fixture();
        let mut fence = 1;
        let (mut raw, mut sig, mut id, keys) = response(&c);
        match mutation {
            0 => {} // Success is also durably single-use.
            1 => current.current.deny = true,
            2 => plan.binding.actor_uid = "another-actor".into(),
            3 => action.kind = "uninstall_target_msi".into(),
            4 => action.sequence += 1,
            5 => action.boot_id = "another-boot".into(),
            6 => fence += 1,
            7 => current.current.peer = "b".repeat(64),
            8 => current.current.now = c.expires_at,
            9 => current.current.now = c.created_at - 1,
            10 => sig[0] ^= 1,
            11 => id = "unknown-key".into(),
            12 => raw.clear(),
            _ => plan.binding.actor_uid.clear(), // Structurally invalid plan.
        }
        let mut authority = SignedPhaseAuthority::new(raw, sig, id, keys, current);
        assert_eq!(
            authority.authorize(&plan, &action, fence).is_ok(),
            mutation == 0,
            "mutation {mutation}"
        );
        drop(authority);
        let store = FileChallenges::reopen(&root.0).unwrap();
        assert!(store.head.pending.is_none(), "mutation {mutation}");
        let mut current = DurableCurrentAuthority::new(store, Live::default());
        assert!(current.check(&plan, &action, fence).is_err());
    }
}

#[test]
fn abandoned_challenge_is_spent_without_authorizing_work() {
    let root = Root::new();
    let (mut current, c) = issued(&root);
    current.store.invalidate().unwrap();
    assert!(current.store.invalidate().is_err());
    drop(current);
    let mut current =
        DurableCurrentAuthority::new(FileChallenges::reopen(&root.0).unwrap(), Live::default());
    let (plan, action) = fixture();
    assert!(current.check(&plan, &action, 1).is_err());
    assert_ne!(current.challenge(&plan, &action, 1).unwrap().nonce, c.nonce);
}

#[test]
fn invalid_issue_or_live_outage_cannot_create_challenges() {
    let root = Root::new();
    let mut current = DurableCurrentAuthority::new(
        FileChallenges::initialize(&root.0).unwrap(),
        Live::default(),
    );
    let (mut plan, action) = fixture();
    current.current.deny = true;
    assert!(current.challenge(&plan, &action, 1).is_err());
    current.current.deny = false;
    assert!(current.challenge(&plan, &action, 0).is_err());
    current.current.now = i64::MAX;
    assert!(current.challenge(&plan, &action, 1).is_err());
    current.current.now = START;
    plan.binding.actor_uid.clear();
    assert!(current.challenge(&plan, &action, 1).is_err());
    assert!(current.store.head.pending.is_none());
}

#[test]
fn uncertain_consumption_never_returns_authority_or_retries() {
    let root = Root::new();
    let (mut current, _) = issued(&root);
    let (plan, action) = fixture();
    current.store.fail_after_replace = true;
    assert!(current.check(&plan, &action, 1).is_err());
    current.store.fail_after_replace = false;
    assert!(current.check(&plan, &action, 1).is_err());
    drop(current);
    let mut current =
        DurableCurrentAuthority::new(FileChallenges::reopen(&root.0).unwrap(), Live::default());
    assert!(current.check(&plan, &action, 1).is_err());
    // Lost completion after replacement preserved the spent state.
    assert!(current.store.head.pending.is_none());
}

#[test]
fn interrupted_temporary_write_and_disk_changes_fail_closed() {
    let root = Root::new();
    let (mut current, _) = issued(&root);
    let (plan, action) = fixture();
    private_new(&root.0.join("challenges.next"))
        .unwrap()
        .write_all(b"partial")
        .unwrap();
    assert!(current.check(&plan, &action, 1).is_err());
    assert!(current.store.uncertain);
    drop(current);
    assert!(FileChallenges::reopen(&root.0).is_err());

    let root = Root::new();
    let (mut current, _) = issued(&root);
    fs::write(root.0.join("challenges.json"), b"{}").unwrap();
    assert!(current.check(&plan, &action, 1).is_err());
    drop(current);
    assert!(FileChallenges::reopen(&root.0).is_err());
}

#[test]
fn corrupt_noncanonical_missing_oversized_or_linked_state_denies() {
    for bytes in [
        b"{}".to_vec(),
        b"{\"version\":1,\"pending\":null,\"extra\":true}".to_vec(),
        b"{\"version\":1,\"version\":1,\"pending\":null}".to_vec(),
        b"{\"version\":1}".to_vec(),
        b" {\"version\":1,\"pending\":null}".to_vec(),
        vec![0; MAX_BYTES + 1],
    ] {
        let root = Root::new();
        drop(FileChallenges::initialize(&root.0).unwrap());
        fs::write(root.0.join("challenges.json"), bytes).unwrap();
        assert!(FileChallenges::reopen(&root.0).is_err());
    }
    let root = Root::new();
    assert!(FileChallenges::reopen(&root.0).is_err());
    drop(FileChallenges::initialize(&root.0).unwrap());
    fs::hard_link(root.0.join("challenges.json"), root.0.join("alias")).unwrap();
    assert!(FileChallenges::reopen(&root.0).is_err());
}

#[test]
#[ignore = "subprocess consumption holder; invoked only by hard_process_loss_keeps_challenge_spent"]
fn consumption_child() {
    let path = PathBuf::from(std::env::var_os("KW_PHASE_CHALLENGE_TEST_ROOT").unwrap());
    let mut current =
        DurableCurrentAuthority::new(FileChallenges::reopen(&path).unwrap(), Live::default());
    let (plan, action) = fixture();
    current.check(&plan, &action, 1).unwrap();
    println!("phase-challenge-spent");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(60));
}

#[test]
fn hard_process_loss_keeps_challenge_spent() {
    let root = Root::new();
    let (current, _) = issued(&root);
    drop(current);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "updates::phase::challenges::tests::consumption_child",
            "--nocapture",
        ])
        .env("KW_PHASE_CHALLENGE_TEST_ROOT", &root.0)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = false;
    for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines() {
        if line.unwrap().contains("phase-challenge-spent") {
            ready = true;
            break;
        }
    }
    let locked = FileChallenges::reopen(&root.0).is_err();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready);
    assert!(locked);
    let mut current =
        DurableCurrentAuthority::new(FileChallenges::reopen(&root.0).unwrap(), Live::default());
    let (plan, action) = fixture();
    assert!(current.check(&plan, &action, 1).is_err());
    assert!(current.store.head.pending.is_none());
}
