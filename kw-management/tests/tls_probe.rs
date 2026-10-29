//! Opt-in loopback subprocess used by the Go PKI interoperability campaign.
//! Not a shipped listener. Private test material arrives only on bounded stdin.
use base64::{engine::general_purpose::STANDARD, Engine};
use kw_management::{
    identity::Identity,
    tls::{Server, TlsDenied},
    trust::TrustStore,
};
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    roots: Vec<String>,
    certificates: Vec<String>,
    private_key: String,
    enrolled: String,
    deny: bool,
    deny_on_finish: bool,
}
struct DeadlineIo<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Read for DeadlineIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf)
    }
}
impl Write for DeadlineIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn run(stage: &mut &'static str) -> Result<(String, String), TlsDenied> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(512 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|_| TlsDenied)?;
    if input.len() > 512 * 1024 {
        return Err(TlsDenied);
    }
    let config: Config = serde_json::from_slice(&input).map_err(|_| TlsDenied)?;
    let roots = config
        .roots
        .iter()
        .map(|s| STANDARD.decode(s).map_err(|_| TlsDenied))
        .collect::<Result<Vec<_>, _>>()?;
    let chain = config
        .certificates
        .iter()
        .map(|s| STANDARD.decode(s).map_err(|_| TlsDenied))
        .collect::<Result<Vec<_>, _>>()?;
    let checks = Arc::new(AtomicUsize::new(0));
    let counter = checks.clone();
    let s = Server::new(
        Arc::new(TrustStore::new(&roots).map_err(|_| TlsDenied)?),
        Identity::from_uri(&config.enrolled).map_err(|_| TlsDenied)?,
        chain,
        STANDARD
            .decode(&config.private_key)
            .map_err(|_| TlsDenied)?,
        Arc::new(move |_, peer| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let expected =
                Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/apis/api-1")
                    .map_err(|_| TlsDenied)?;
            if config.deny || config.deny_on_finish && n > 0 || peer != &expected {
                Err(TlsDenied)
            } else {
                Ok(())
            }
        }),
    )?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| TlsDenied)?;
    listener.set_nonblocking(true).map_err(|_| TlsDenied)?;
    println!(
        "{}",
        serde_json::json!({"event":"ready","address":listener.local_addr().map_err(|_|TlsDenied)?.to_string()})
    );
    io::stdout().flush().map_err(|_| TlsDenied)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut socket = loop {
        match listener.accept() {
            Ok((s, peer)) if peer.ip().is_loopback() => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2))
            }
            _ => return Err(TlsDenied),
        }
    };
    drop(listener);
    let mut io = DeadlineIo {
        stream: &mut socket,
        deadline,
    };
    *stage = "handshake";
    let mut pending = s.connection()?;
    for _ in 0..128 {
        while pending.wants_write() {
            if pending.write_tls(&mut io).map_err(|_| TlsDenied)? == 0 {
                return Err(TlsDenied);
            }
        }
        if !pending.is_handshaking() {
            break;
        }
        if pending.read_tls(&mut io).map_err(|_| TlsDenied)? == 0 {
            return Err(TlsDenied);
        }
        pending.process_new_packets()?;
    }
    *stage = "finish";
    let mut active = pending.finish()?;
    *stage = "application";
    let identity = active.peer().identity().to_uri().map_err(|_| TlsDenied)?;
    let fingerprint = active.peer().certificate_sha256().to_owned();
    let mut byte = [0; 1];
    for _ in 0..128 {
        match active.read_plaintext(&mut byte) {
            Ok(1) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            _ => return Err(TlsDenied),
        }
        if active.read_tls(&mut io).map_err(|_| TlsDenied)? == 0 {
            return Err(TlsDenied);
        }
        active.process_new_packets()?;
    }
    if byte != [0x51] {
        return Err(TlsDenied);
    }
    if active.write_plaintext(&[0x52]).map_err(|_| TlsDenied)? != 1 {
        return Err(TlsDenied);
    }
    while active.wants_write() {
        if active.write_tls(&mut io).map_err(|_| TlsDenied)? == 0 {
            return Err(TlsDenied);
        }
    }
    Ok((identity, fingerprint))
}

#[test]
#[ignore = "loopback subprocess helper; invoked explicitly by Go PKI tests"]
fn rust_tls_probe_child() {
    if std::env::var("KW_MANAGEMENT_TLS_PROBE").as_deref() != Ok("1") {
        return;
    }
    let mut stage = "configuration";
    match run(&mut stage) {
        Ok((identity, fingerprint)) => println!(
            "{}",
            serde_json::json!({"event":"result","accepted":true,"identity":identity,"fingerprint":fingerprint,"stage":stage})
        ),
        Err(_) => println!(
            "{}",
            serde_json::json!({"event":"result","accepted":false,"stage":stage})
        ),
    }
}
