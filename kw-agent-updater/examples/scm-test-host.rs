//! Isolated CI harness only, never uploaded as the updater release artifact.
//! Supplies synthetic recovery authority; no installer dispatch is implemented.
#[cfg(windows)]
mod fixture {
    use kw_agent_updater::service::{self, Config};
    use kw_management::updates::{
        journal::{Ack, ActionReceipt, Context, Event, Journal, Snapshot},
        lifetime::{LaunchBinding, RecoveryAuthority, RecoveryHead, UnavailableAuthority},
        persistence::{create_root, FileStore},
    };
    use std::{
        io::Read,
        path::{Path, PathBuf},
    };

    pub fn main() -> Result<(), String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match args.as_slice() {
            [command, root, head] if command == "prepare" => {
                prepare(Path::new(root), Path::new(head))
            }
            [command, name] if command == "configure" => service::configure_recovery(name),
            [command, name, root, head] if command == "service" => service::dispatch(
                Config {
                    name: name.clone(),
                    root: root.into(),
                },
                Box::new(FixtureAuthority(PathBuf::from(head))),
            ),
            [command, name, root] if command == "service-unavailable" => service::dispatch(
                Config {
                    name: name.clone(),
                    root: root.into(),
                },
                Box::new(UnavailableAuthority),
            ),
            _ => Err("invalid CI fixture invocation".into()),
        }
    }

    struct FixtureAuthority(PathBuf);
    impl RecoveryAuthority for FixtureAuthority {
        fn current_head(
            &mut self,
            launch: &LaunchBinding,
        ) -> Result<Option<RecoveryHead>, kw_management::updates::lifetime::Error> {
            let mut raw = Vec::new();
            std::fs::File::open(&self.0)
                .and_then(|file| file.take(4097).read_to_end(&mut raw))
                .map_err(|_| kw_management::updates::lifetime::Error::Authority)?;
            if raw.len() > 4096 {
                return Err(kw_management::updates::lifetime::Error::Authority);
            }
            let value: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|_| kw_management::updates::lifetime::Error::Authority)?;
            if value["plan_sha256"].as_str() != Some(&launch.plan_sha256) {
                return Err(kw_management::updates::lifetime::Error::Authority);
            }
            Ok(Some(RecoveryHead {
                plan_sha256: launch.plan_sha256.clone(),
                checkpoint_sha256: value["checkpoint_sha256"]
                    .as_str()
                    .ok_or(kw_management::updates::lifetime::Error::Authority)?
                    .into(),
                minimum_sequence: value["minimum_sequence"]
                    .as_u64()
                    .ok_or(kw_management::updates::lifetime::Error::Authority)?,
            }))
        }
    }

    fn prepare(root: &Path, head: &Path) -> Result<(), String> {
        create_root(root).map_err(|_| "create isolated updater root failed")?;
        let mut plan = serde_json::from_str::<Snapshot>(include_str!(
            "../../kw-management/tests/testdata/journal-v1.json"
        ))
        .map_err(|_| "invalid fixture")?
        .plan;
        plan.binding.attempt_id = root
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid fixture directory")?
            .into();
        let mut journal =
            Journal::new(plan.clone(), 1, 1700000000).map_err(|_| "invalid fixture plan")?;
        let mut store = FileStore::initialize(root, journal.clone())
            .map_err(|_| "create fixture checkpoint failed")?;
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
            let t = journal
                .prepare(
                    &Event {
                        kind: kind.into(),
                        receipt,
                    },
                    &context,
                )
                .map_err(|_| "fixture transition failed")?;
            let ack = Ack {
                sequence: t.sequence(),
                sha256: t.sha256(),
                kind: "intent".into(),
            };
            (journal, _) = t
                .commit(&mut store, &context, Some(&ack))
                .map_err(|_| "fixture persistence failed")?;
        }
        let launch = LaunchBinding {
            version: 1,
            binding: plan.binding.clone(),
            plan_sha256: plan.sha256(),
        };
        launch
            .write_new(root)
            .map_err(|_| "fixture launch binding failed")?;
        let raw = serde_json::to_vec(&serde_json::json!({ "plan_sha256": launch.plan_sha256, "checkpoint_sha256": journal.sha256(), "minimum_sequence": journal.snapshot().sequence })).map_err(|_| "fixture head encoding failed")?;
        std::fs::write(head, raw).map_err(|_| "fixture authority write failed".into())
    }
}

fn main() {
    #[cfg(windows)]
    if let Err(error) = fixture::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("SCM fixture requires Windows");
        std::process::exit(1);
    }
}
