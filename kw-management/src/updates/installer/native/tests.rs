use super::*;
use std::io::Write;

#[derive(Default)]
struct Recording {
    count: usize,
    fail: bool,
    lost: bool,
}
impl Evidence for Recording {
    fn append(&mut self, _: u32, _: &str) -> Result<(), Error> {
        self.count += 1;
        if self.fail {
            Err(Error::Recording)
        } else {
            Ok(())
        }
    }
    fn recording_lost(&mut self) {
        self.lost = true;
    }
}

#[test]
fn callbacks_bound_text_and_never_cancel_an_installer() {
    let mut sink = Recording::default();
    let mut remaining = 100;
    {
        let callback = Mutex::new(Callback {
            evidence: &mut sink,
            remaining: &mut remaining,
            lost: false,
        });
        let text = wide("installer progress");
        unsafe {
            assert_eq!(
                message(
                    (&callback as *const Mutex<Callback<'_>>).cast_mut().cast(),
                    1,
                    PCWSTR(text.as_ptr())
                ),
                0
            );
        }
        assert!(!callback.lock().unwrap().lost);
        let oversized = wide("x".repeat(MAX_TEXT + 1));
        unsafe {
            assert_eq!(
                message(
                    (&callback as *const Mutex<Callback<'_>>).cast_mut().cast(),
                    1,
                    PCWSTR(oversized.as_ptr())
                ),
                0
            );
        }
        assert!(callback.lock().unwrap().lost);
    }
    assert_eq!(sink.count, 1);
}

#[test]
fn callback_sink_failure_and_budget_exhaustion_remain_recording_loss() {
    for fail in [false, true] {
        let mut sink = Recording {
            fail,
            ..Recording::default()
        };
        let mut remaining = if fail { 100 } else { 1 };
        let callback = Mutex::new(Callback {
            evidence: &mut sink,
            remaining: &mut remaining,
            lost: false,
        });
        let text = wide("evidence");
        unsafe {
            assert_eq!(
                message(
                    (&callback as *const Mutex<Callback<'_>>).cast_mut().cast(),
                    1,
                    PCWSTR(text.as_ptr())
                ),
                0
            );
        }
        assert!(callback.lock().unwrap().lost);
    }
}

fn package(path: &Path) -> Package {
    let db = database(path).unwrap();
    Package {
        file: "agent.msi".into(),
        sha256: crate::updates::digest(&std::fs::read(path).unwrap()),
        size: path.metadata().unwrap().len(),
        product_code: guid(&property(&db, "ProductCode").unwrap()).unwrap(),
        version: property(&db, "ProductVersion").unwrap(),
    }
}

fn edit_fixture(path: &Path, sql: &str) {
    let mut db = MSIHANDLE::default();
    let path = wide(path);
    unsafe {
        assert_eq!(
            MsiOpenDatabaseW(PCWSTR(path.as_ptr()), MSIDBOPEN_TRANSACT, &mut db),
            0
        );
        let db = MsiHandle(db);
        let mut view = MSIHANDLE::default();
        let sql = wide(sql);
        assert_eq!(
            MsiDatabaseOpenViewW(db.0, PCWSTR(sql.as_ptr()), &mut view),
            0
        );
        let view = MsiHandle(view);
        assert_eq!(MsiViewExecute(view.0, MSIHANDLE::default()), 0);
        drop(view);
        assert_eq!(MsiDatabaseCommit(db.0), 0);
    }
}

struct FixtureRoot(PathBuf);
impl Drop for FixtureRoot {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
#[ignore = "isolated MSI fixtures supplied by packaging/windows/test-updater-msi.ps1"]
fn isolated_native_msi_compensation() {
    let first = PathBuf::from(std::env::var_os("KW_UPDATER_TEST_FIRST").unwrap());
    let second = PathBuf::from(std::env::var_os("KW_UPDATER_TEST_SECOND").unwrap());
    let instance = std::env::var("KW_UPDATER_TEST_INSTANCE").unwrap();
    let upgrade = guid(&instance).unwrap();
    assert_ne!(
        upgrade,
        crate::updates::AGENT_UPGRADE_CODE,
        "never use the production product family in a lifecycle test"
    );
    let directory = std::env::var("KW_UPDATER_TEST_INSTALL_DIR").unwrap();
    let root = std::env::temp_dir().join(format!("kw-native-msi-{upgrade}"));
    security::create_root(&root).unwrap();
    let root = FixtureRoot(root);
    for (name, source) in [("target", &second), ("previous", &first)] {
        let dir = root.0.join(name);
        security::create_root(&dir).unwrap();
        let mut file = security::native::create_file(&dir.join("agent.msi")).unwrap();
        std::io::copy(&mut File::open(source).unwrap(), &mut file).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();
    }
    let previous = package(&first);
    let target = package(&second);
    let staged = root.0.join("target/agent.msi");
    let mut wrong = package(&second);
    wrong.version = "9.9.9".into();
    assert!(matches!(
        Pinned::open(&root.0.join("target"), &wrong, &upgrade),
        Err(Error::Package)
    ));
    wrong.version = target.version.clone();
    wrong.sha256 = "0".repeat(64);
    assert!(matches!(
        Pinned::open(&root.0.join("target"), &wrong, &upgrade),
        Err(Error::Package)
    ));
    for sql in [
        "UPDATE `Media` SET `Cabinet`='external.cab'",
        "UPDATE `File` SET `Attributes`=8192",
        "UPDATE `Property` SET `Value`='0' WHERE `Property`='ALLUSERS'",
    ] {
        edit_fixture(&staged, sql);
        // Rehash the edited test MSI: rejection must come from its content,
        // not merely the outer artifact hash. No production trust key is used.
        let candidate = package(&staged);
        assert!(
            matches!(
                Pinned::open(&root.0.join("target"), &candidate, &upgrade),
                Err(Error::Package)
            ),
            "{sql}"
        );
        let mut dest = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&staged)
            .unwrap();
        std::io::copy(&mut File::open(&second).unwrap(), &mut dest).unwrap();
        dest.sync_all().unwrap();
    }
    let mut sink = Recording::default();
    let mut adapter = WindowsMsi::open(&root.0, &target, &previous, &upgrade, &mut sink).unwrap();
    assert!(adapter.observe().unwrap().products.is_empty());
    // Pins deny alteration or replacement of either independently staged MSI.
    assert!(OpenOptions::new()
        .write(true)
        .open(root.0.join("target/agent.msi"))
        .is_err());
    assert!(std::fs::rename(
        root.0.join("previous/agent.msi"),
        root.0.join("previous/swapped.msi")
    )
    .is_err());
    assert!(std::fs::rename(root.0.join("target"), root.0.join("replaced")).is_err());
    assert_eq!(adapter.install(&previous, &directory).unwrap(), 0);
    let old = adapter.observe().unwrap();
    assert_eq!(old.products.len(), 1);
    assert_eq!(old.products[0].product_code, previous.product_code);
    assert_eq!(old.products[0].version, "0.0.1");
    assert_eq!(adapter.install(&target, &directory).unwrap(), 0);
    let new = adapter.observe().unwrap();
    assert_eq!(new.products.len(), 1);
    assert_eq!(new.products[0].product_code, target.product_code);
    assert_eq!(new.products[0].version, "0.0.2");
    // Real native downgrade guard, then the exact compensation sequence.
    assert_eq!(adapter.install(&previous, &directory).unwrap(), 1603);
    assert_eq!(adapter.uninstall(&new.products[0]).unwrap(), 0);
    assert!(adapter.observe().unwrap().products.is_empty());
    assert_eq!(adapter.install(&previous, &directory).unwrap(), 0);
    let restored = adapter.observe().unwrap();
    assert_eq!(restored.products[0].product_code, previous.product_code);
    assert_eq!(restored.products[0].version, "0.0.1");
    // Production adapter refuses to uninstall the predecessor, even by direct call.
    assert_eq!(
        adapter.uninstall(&restored.products[0]),
        Err(Error::Binding)
    );
    drop(adapter);
    assert!(sink.count > 6);
    assert!(!sink.lost);
    let mut failed_sink = Recording {
        fail: true,
        ..Recording::default()
    };
    let mut adapter =
        WindowsMsi::open(&root.0, &target, &previous, &upgrade, &mut failed_sink).unwrap();
    assert_eq!(adapter.install(&target, &directory), Err(Error::Recording));
    assert_eq!(adapter.install(&target, &directory), Err(Error::Recording));
    assert_eq!(
        adapter.observe().unwrap().products[0].product_code,
        previous.product_code
    );
    drop(adapter);
    assert_eq!(
        failed_sink.count, 1,
        "recording loss must prevent future MSI calls"
    );
    assert!(failed_sink.lost);
    // Fixture cleanup is performed independently by the enclosing PowerShell
    // script even if any assertion above fails. No production cleanup bypass.
}
