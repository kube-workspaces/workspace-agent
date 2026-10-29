use super::*;
use crate::updates::journal::{Ack, Context, Event, Plan, Snapshot};
use std::io::BufRead;

const START: i64 = 1700000000;
const FIXTURE: &str = include_str!("../../../tests/testdata/journal-v1.json");

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("kw-updater-{name}"));
        create_root(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn plan() -> Plan {
    serde_json::from_str::<Snapshot>(FIXTURE).unwrap().plan
}
fn initial() -> Journal {
    Journal::new(plan(), 1, START).unwrap()
}
fn reopen(root: &Root, j: &Journal) -> Result<FileStore, Error> {
    FileStore::reopen(
        &root.0,
        &j.snapshot().plan.sha256(),
        &j.sha256(),
        j.snapshot().sequence,
    )
}
fn begin(store: &mut FileStore) -> Journal {
    let context = Context {
        binding: plan().binding,
        owner_fence: 1,
        now: START + 1,
        boot_id: "boot-1".into(),
        authorized: true,
        recording_available: true,
        installer_busy: false,
    };
    let transition = store
        .journal()
        .prepare(
            &Event {
                kind: "begin".into(),
                receipt: None,
            },
            &context,
        )
        .unwrap();
    let ack = Ack {
        sequence: transition.sequence(),
        sha256: transition.sha256(),
        kind: "intent".into(),
    };
    let (journal, effect) = transition.commit(store, &context, Some(&ack)).unwrap();
    assert_eq!(effect.unwrap().kind, "stop_agent");
    journal
}

#[test]
fn persists_write_ahead_and_reopens_without_replaying_effect() {
    let root = Root::new();
    let mut store = FileStore::initialize(&root.0, initial()).unwrap();
    let j = begin(&mut store);
    assert_eq!(store.journal().sha256(), j.sha256());
    drop(store);
    let recovered = reopen(&root, &j).unwrap();
    assert_eq!(recovered.journal().encode(), j.encode());
    assert_eq!(
        recovered.journal().snapshot().active.as_ref().unwrap().kind,
        "stop_agent"
    );
    // Recovery gets a checkpoint, not another effect descriptor.
    drop(recovered);
    assert!(FileStore::initialize(&root.0, initial()).is_err());
}

#[test]
fn ownership_is_exclusive_for_all_attempts() {
    let root = Root::new();
    let store = FileStore::initialize(&root.0, initial()).unwrap();
    assert!(matches!(reopen(&root, &initial()), Err(Error::Conflict)));
    assert!(matches!(
        FileStore::initialize(&root.0, initial()),
        Err(Error::Conflict)
    ));
    drop(store);
    assert!(reopen(&root, &initial()).is_ok());
}

#[test]
fn recovery_requires_independent_trusted_head_plan_and_floor() {
    let root = Root::new();
    let mut store = FileStore::initialize(&root.0, initial()).unwrap();
    let next = begin(&mut store);
    drop(store);
    assert!(reopen(&root, &initial()).is_err());
    assert!(FileStore::reopen(&root.0, &"a".repeat(64), &next.sha256(), 0).is_err());
    assert!(FileStore::reopen(&root.0, &plan().sha256(), &next.sha256(), 2).is_err());
    assert!(reopen(&root, &next).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn failed_validation_scope_releases_lock_despite_inherited_description() {
    let root = Root::new();
    let mut inherited = None;
    // A duplicated descriptor deterministically models the open-file description
    // retained between a concurrent fork and exec. No unsafe multithreaded fork.
    let rejected: Result<(), Error> = (|| {
        let lock = acquire(&root.0)?;
        inherited = Some(lock.file().try_clone().map_err(io_error)?);
        Err(Error::Journal)
    })();
    assert_eq!(rejected, Err(Error::Journal));
    let current = acquire(&root.0).expect("failed validation left an inherited lock behind");
    drop(inherited);
    assert!(matches!(acquire(&root.0), Err(Error::Conflict)));
    drop(current);
    assert!(acquire(&root.0).is_ok());
}

#[test]
fn stale_cas_invalid_bytes_and_out_of_band_changes_deny() {
    let root = Root::new();
    let mut store = FileStore::initialize(&root.0, initial()).unwrap();
    let j = begin(&mut store);
    assert_eq!(
        store.compare_and_swap(&initial().sha256(), &j.encode()),
        Err(Error::Conflict)
    );
    for bytes in [
        vec![],
        vec![b' '; MAX_JOURNAL_BYTES + 1],
        b"{}".to_vec(),
        j.encode(),
    ] {
        assert!(store.compare_and_swap(&j.sha256(), &bytes).is_err());
    }
    fs::write(root.0.join("checkpoint.json"), initial().encode()).unwrap();
    assert!(store.compare_and_swap(&j.sha256(), &j.encode()).is_err());
}

#[test]
fn uncertain_write_poisoned_until_trusted_reopen() {
    let root = Root::new();
    let mut store = FileStore::initialize(&root.0, initial()).unwrap();
    // Simulate a partial temporary file from a write interrupted before rename.
    let mut pending = private_new(&root.0.join("checkpoint.next")).unwrap();
    pending.write_all(b"partial").unwrap();
    pending.sync_all().unwrap();
    drop(pending);
    let t = store
        .journal()
        .prepare(
            &Event {
                kind: "cancel".into(),
                receipt: None,
            },
            &Context {
                binding: plan().binding,
                owner_fence: 1,
                now: START + 1,
                boot_id: "boot-1".into(),
                authorized: true,
                recording_available: true,
                installer_busy: false,
            },
        )
        .unwrap();
    assert_eq!(
        store.compare_and_swap(&initial().sha256(), &t.bytes()),
        Err(Error::Persistence)
    );
    fs::remove_file(root.0.join("checkpoint.next")).unwrap();
    assert_eq!(
        store.compare_and_swap(&initial().sha256(), &t.bytes()),
        Err(Error::Persistence)
    );
    drop(store);
    // Reopening requires the independent head, not the failed candidate.
    assert!(FileStore::reopen(&root.0, &plan().sha256(), &t.sha256(), 0).is_err());
    assert!(reopen(&root, &initial()).is_ok());
}

#[test]
fn abandoned_partial_file_is_removed_only_after_verified_recovery() {
    let root = Root::new();
    drop(FileStore::initialize(&root.0, initial()).unwrap());
    let pending = root.0.join("checkpoint.next");
    private_new(&pending)
        .unwrap()
        .write_all(b"partial")
        .unwrap();
    assert!(FileStore::reopen(&root.0, &plan().sha256(), &"0".repeat(64), 0).is_err());
    assert!(pending.exists());
    let mut store = reopen(&root, &initial()).unwrap();
    assert!(!pending.exists());
    begin(&mut store);
}

#[test]
fn lost_completion_after_replace_requires_new_head_reconciliation() {
    let root = Root::new();
    let mut store = FileStore::initialize(&root.0, initial()).unwrap();
    let context = Context {
        binding: plan().binding,
        owner_fence: 1,
        now: START + 1,
        boot_id: "boot-1".into(),
        authorized: true,
        recording_available: true,
        installer_busy: false,
    };
    let transition = store
        .journal()
        .prepare(
            &Event {
                kind: "begin".into(),
                receipt: None,
            },
            &context,
        )
        .unwrap();
    let next_head = transition.sha256();
    let ack = Ack {
        sequence: transition.sequence(),
        sha256: next_head.clone(),
        kind: "intent".into(),
    };
    store.fail_after_replace = true;
    // The write-ahead marker reached disk, but no effect is returned to the
    // helper when durable completion cannot be acknowledged to its caller.
    assert!(matches!(
        transition.commit(&mut store, &context, Some(&ack)),
        Err(Error::Persistence)
    ));
    assert_eq!(store.journal().sha256(), initial().sha256());
    assert_eq!(
        store.compare_and_swap(&initial().sha256(), &initial().encode()),
        Err(Error::Persistence)
    );
    drop(store);
    assert!(reopen(&root, &initial()).is_err());
    let recovered = FileStore::reopen(&root.0, &plan().sha256(), &next_head, 1).unwrap();
    assert_eq!(
        recovered.journal().snapshot().active.as_ref().unwrap().kind,
        "stop_agent"
    );
}

#[test]
fn corrupt_oversized_and_hardlinked_checkpoints_deny() {
    let root = Root::new();
    drop(FileStore::initialize(&root.0, initial()).unwrap());
    let path = root.0.join("checkpoint.json");
    fs::write(&path, vec![0; MAX_JOURNAL_BYTES + 1]).unwrap();
    assert!(reopen(&root, &initial()).is_err());
    fs::write(&path, b"corrupt").unwrap();
    assert!(reopen(&root, &initial()).is_err());
    fs::write(&path, initial().encode()).unwrap();
    fs::hard_link(&path, root.0.join("alias")).unwrap();
    assert!(reopen(&root, &initial()).is_err());
}

#[test]
fn roots_are_never_adopted_or_repaired() {
    let root = Root::new();
    assert!(create_root(&root.0).is_err());
    let weak = root.0.join("weak");
    fs::create_dir(&weak).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&weak, fs::Permissions::from_mode(0o755)).unwrap();
    }
    // On Windows the root's inheritable ACL gives this directory an inherited
    // descriptor; adoption requires an explicitly protected, expected owner ACL.
    assert!(FileStore::initialize(&weak, initial()).is_err());
}

#[test]
fn symlinked_roots_parents_and_checkpoints_deny() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir as symlink;
    let root = Root::new();
    let alias = root.0.join("alias");
    symlink(&root.0, &alias).unwrap();
    assert!(create_root(&alias.join("child")).is_err());
    assert!(FileStore::initialize(&alias, initial()).is_err());
    drop(FileStore::initialize(&root.0, initial()).unwrap());
    fs::rename(root.0.join("checkpoint.json"), root.0.join("saved")).unwrap();
    #[cfg(unix)]
    symlink(root.0.join("saved"), root.0.join("checkpoint.json")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(root.0.join("saved"), root.0.join("checkpoint.json"))
        .unwrap();
    assert!(reopen(&root, &initial()).is_err());
}

#[cfg(windows)]
#[test]
fn ambiguous_and_network_windows_paths_deny_before_creation() {
    let root = Root::new();
    for component in ["stream:secret", "nul\0suffix", "trailing.", "trailing "] {
        assert!(create_root(&root.0.join(component)).is_err());
    }
    assert!(create_root(Path::new(r"\\example.invalid\share\updates")).is_err());
}

#[test]
#[ignore = "subprocess lock holder; invoked only by process_death_releases_ownership"]
fn owner_child() {
    let root = PathBuf::from(std::env::var_os("KW_UPDATER_LOCK_TEST_ROOT").unwrap());
    let j = initial();
    let _store = FileStore::reopen(&root, &plan().sha256(), &j.sha256(), 0).unwrap();
    println!("updater-lock-held");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(60));
}

#[test]
fn process_death_releases_ownership() {
    let root = Root::new();
    drop(FileStore::initialize(&root.0, initial()).unwrap());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "updates::persistence::tests::owner_child",
            "--nocapture",
        ])
        .env("KW_UPDATER_LOCK_TEST_ROOT", &root.0)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = false;
    for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines() {
        if line.unwrap().contains("updater-lock-held") {
            ready = true;
            break;
        }
    }
    let locked = matches!(reopen(&root, &initial()), Err(Error::Conflict));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready, "child must acquire the lock before contention test");
    assert!(locked);
    assert!(reopen(&root, &initial()).is_ok());
}
