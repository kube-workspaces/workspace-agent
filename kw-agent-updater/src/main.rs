fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!(
            "kw-agent-updater {} (protocol {})",
            kw_agent_updater::VERSION,
            kw_agent_updater::PROTOCOL_VERSION
        );
        return;
    }
    #[cfg(windows)]
    let result = match args.as_slice() {
        [command] if command == "service" => kw_agent_updater::service::dispatch_default(),
        [command] if command == "configure-recovery" => {
            kw_agent_updater::service::configure_recovery(kw_agent_updater::service::NAME)
        }
        _ => Err("expected --version, service or configure-recovery".into()),
    };
    #[cfg(not(windows))]
    let result: Result<(), String> = Err("updater service requires Windows".into());
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
