//! Explicit test subprocess: persists only synthetic keys under a caller-created
//! private temporary parent. No listener, tokens or private-key output.
use base64::{engine::general_purpose::STANDARD, Engine};
use kw_management::{
    credentials::{KeyUnavailable, MachineKey},
    identity::Identity,
    trust::TrustStore,
};
use serde::Deserialize;
use std::{
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    identity: String,
    create: bool,
    #[serde(default)]
    roots: Vec<String>,
    #[serde(default)]
    certificates: Vec<String>,
}
fn run() -> Result<(String, bool), KeyUnavailable> {
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(512 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| KeyUnavailable)?;
    if raw.len() > 512 * 1024 {
        return Err(KeyUnavailable);
    }
    let config: Config = serde_json::from_slice(&raw).map_err(|_| KeyUnavailable)?;
    let identity = Identity::from_uri(&config.identity).map_err(|_| KeyUnavailable)?;
    let mut key = if config.create {
        MachineKey::initialize(&config.root, &identity)?
    } else {
        MachineKey::reopen(&config.root, &identity)?
    };
    let csr = key.csr_der(&identity)?;
    let mut tls_ready = false;
    if !config.certificates.is_empty() {
        let roots = config
            .roots
            .iter()
            .map(|s| STANDARD.decode(s).map_err(|_| KeyUnavailable))
            .collect::<Result<Vec<_>, _>>()?;
        let chain = config
            .certificates
            .iter()
            .map(|s| STANDARD.decode(s).map_err(|_| KeyUnavailable))
            .collect::<Result<Vec<_>, _>>()?;
        let server = key.tls_server(
            &identity,
            Arc::new(TrustStore::new(&roots).map_err(|_| KeyUnavailable)?),
            chain,
            Arc::new(|_, _| Ok(())),
        )?;
        #[cfg(target_os = "linux")]
        drop(key);
        if MachineKey::reopen(&config.root, &identity).is_ok() {
            return Err(KeyUnavailable);
        }
        let pending = server.connection().map_err(|_| KeyUnavailable)?;
        drop(server);
        if MachineKey::reopen(&config.root, &identity).is_ok() {
            return Err(KeyUnavailable);
        }
        drop(pending);
        let _reopened = MachineKey::reopen(&config.root, &identity)?;
        tls_ready = true;
    }
    Ok((STANDARD.encode(csr), tls_ready))
}
#[test]
#[ignore = "synthetic key/CSR interoperability subprocess, invoked explicitly by Go tests"]
fn rust_key_probe_child() {
    if std::env::var("KW_MANAGEMENT_KEY_PROBE").as_deref() != Ok("1") {
        return;
    }
    match run() {
        Ok((csr, tls_ready)) => println!(
            "{}",
            serde_json::json!({"event":"result","ok":true,"csr":csr,"tls_ready":tls_ready})
        ),
        Err(_) => println!("{}", serde_json::json!({"event":"result","ok":false})),
    }
}
