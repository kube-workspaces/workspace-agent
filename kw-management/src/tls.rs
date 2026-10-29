//! Management-only TLS 1.3 server state, with no listener or execution endpoint.
//! Pending sessions expose ciphertext I/O only. A completed full handshake,
//! exact ALPN and fresh local/peer authorization are required for plaintext.
//! Signed operation grants, independent recording and bounded ownership remain
//! caller-owned prerequisites, not permissions conferred by this transport.

use crate::{certificate::parse_leaf_profile, identity::Identity, trust::TrustStore};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{ring, verify_tls13_signature};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName, HandshakeKind, ProtocolVersion, ServerConfig,
    ServerConnection, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ALPN: &[u8] = b"kw-management/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsDenied;
impl std::fmt::Display for TlsDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management TLS unavailable or denied")
    }
}
impl std::error::Error for TlsDenied {}

/// Must independently consult current guest incarnation/epoch AND active API
/// replica authorization. Fail on outages and bound any lookup deadline. Neither
/// identity may be accepted merely because a certificate has a valid CA signature.
pub type Authorize = dyn Fn(&Identity, &Identity) -> Result<(), TlsDenied> + Send + Sync;
pub(crate) type LocalGuard = dyn Fn(&Identity) -> Result<(), TlsDenied> + Send + Sync;

struct Context {
    trust: Arc<TrustStore>,
    enrolled: Identity,
    local_chain: Vec<Vec<u8>>,
    authorize: Arc<Authorize>,
    local_guard: Option<Arc<LocalGuard>>,
}
impl Context {
    fn local(&self, now: u64) -> Result<(), TlsDenied> {
        if let Some(guard) = &self.local_guard {
            guard(&self.enrolled)?;
        }
        self.trust
            .verify_certificate(
                &self.local_chain[0],
                &self.local_chain[1..],
                &self.enrolled,
                now,
            )
            .map_err(|_| TlsDenied)
    }
    fn peer(&self, chain: &[CertificateDer<'_>], now: u64) -> Result<Identity, TlsDenied> {
        if chain.is_empty()
            || chain.len() > 9
            || chain.iter().any(|c| c.len() > 65536)
            || chain.iter().map(|c| c.len()).sum::<usize>() > 192 * 1024
        {
            return Err(TlsDenied);
        }
        let identity = parse_leaf_profile(chain[0].as_ref())
            .map_err(|_| TlsDenied)?
            .identity;
        if !matches!(identity, Identity::Api { .. }) {
            return Err(TlsDenied);
        }
        let intermediates: Vec<_> = chain[1..].iter().map(|c| c.as_ref().to_vec()).collect();
        self.trust
            .verify_certificate(chain[0].as_ref(), &intermediates, &identity, now)
            .map_err(|_| TlsDenied)?;
        self.local(now)?;
        (self.authorize)(&self.enrolled, &identity)?;
        Ok(identity)
    }
}
struct Verifier {
    context: Arc<Context>,
}
impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management TLS client verifier")
    }
}
fn certificate_error() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}
impl ClientCertVerifier for Verifier {
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if intermediates.len() > 8 {
            return Err(certificate_error());
        }
        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        chain.push(leaf.clone());
        chain.extend_from_slice(intermediates);
        self.context
            .peer(&chain, now.as_secs())
            .map_err(|_| certificate_error())?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(certificate_error())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &ring::default_provider().signature_verification_algorithms,
        )
        .map_err(|_| certificate_error())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn now() -> Result<u64, TlsDenied> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsDenied)?
        .as_secs())
}

/// Immutable server setup. Keys must come from protected guest provisioning;
/// this constructor neither generates keys nor opens a network listener.
pub struct Server {
    config: Arc<ServerConfig>,
    context: Arc<Context>,
}
impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management TLS server (credentials redacted)")
    }
}
impl Server {
    pub fn new(
        trust: Arc<TrustStore>,
        enrolled: Identity,
        local_chain: Vec<Vec<u8>>,
        pkcs8_key: Vec<u8>,
        authorize: Arc<Authorize>,
    ) -> Result<Self, TlsDenied> {
        Self::with_local_guard(trust, enrolled, local_chain, pkcs8_key, authorize, None)
    }
    pub(crate) fn with_local_guard(
        trust: Arc<TrustStore>,
        enrolled: Identity,
        local_chain: Vec<Vec<u8>>,
        pkcs8_key: Vec<u8>,
        authorize: Arc<Authorize>,
        local_guard: Option<Arc<LocalGuard>>,
    ) -> Result<Self, TlsDenied> {
        if !matches!(enrolled, Identity::Guest { .. })
            || local_chain.is_empty()
            || local_chain.len() > 9
            || pkcs8_key.is_empty()
            || pkcs8_key.len() > 16384
        {
            return Err(TlsDenied);
        }
        let context = Arc::new(Context {
            trust,
            enrolled,
            local_chain,
            authorize,
            local_guard,
        });
        context.local(now()?)?;
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsDenied)?
            .with_client_cert_verifier(Arc::new(Verifier {
                context: context.clone(),
            }))
            .with_single_cert(
                context
                    .local_chain
                    .iter()
                    .cloned()
                    .map(CertificateDer::from)
                    .collect(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_key)),
            )
            .map_err(|_| TlsDenied)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
            context,
        })
    }
    /// The driver must bound pending-session lifetime and transport I/O. No
    /// plaintext API exists until `finish` consumes a successful full handshake.
    pub fn connection(&self) -> Result<Pending, TlsDenied> {
        self.context.local(now()?)?;
        let mut connection = ServerConnection::new(self.config.clone()).map_err(|_| TlsDenied)?;
        connection.set_buffer_limit(Some(64 * 1024));
        Ok(Pending {
            wire: Wire {
                connection,
                failed: false,
            },
            context: self.context.clone(),
        })
    }
}

struct Wire {
    connection: ServerConnection,
    failed: bool,
}
fn io_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "management TLS unavailable or denied",
    )
}
impl Wire {
    fn read_tls(&mut self, input: &mut dyn Read) -> io::Result<usize> {
        if self.failed {
            return Err(io_denied());
        }
        match self.connection.read_tls(input) {
            Ok(0) => {
                self.failed = true;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(err) => {
                if !matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    self.failed = true;
                }
                Err(io::Error::new(err.kind(), "management TLS I/O failed"))
            }
        }
    }
    fn write_tls(&mut self, output: &mut dyn Write) -> io::Result<usize> {
        if self.failed {
            return Err(io_denied());
        }
        self.connection.write_tls(output).map_err(|err| {
            if !matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                self.failed = true;
            }
            io::Error::new(err.kind(), "management TLS I/O failed")
        })
    }
    fn process(&mut self) -> Result<(), TlsDenied> {
        if self.failed {
            return Err(TlsDenied);
        }
        self.connection
            .process_new_packets()
            .map(|_| ())
            .map_err(|_| {
                self.failed = true;
                TlsDenied
            })
    }
}

/// Ciphertext-only state. Plaintext cannot be read before `finish` succeeds.
///
/// ```compile_fail
/// fn premature_plaintext(mut pending: kw_management::tls::Pending) {
///     let _ = pending.read_plaintext(&mut [0; 1]);
/// }
/// ```
pub struct Pending {
    wire: Wire,
    context: Arc<Context>,
}
impl Pending {
    fn check_local(&mut self) -> Result<(), TlsDenied> {
        if self.wire.failed {
            return Err(TlsDenied);
        }
        let result = now().and_then(|now| self.context.local(now));
        if result.is_err() {
            self.wire.failed = true;
        }
        result
    }
    pub fn read_tls(&mut self, input: &mut dyn Read) -> io::Result<usize> {
        self.wire.read_tls(input)
    }
    pub fn write_tls(&mut self, output: &mut dyn Write) -> io::Result<usize> {
        self.check_local().map_err(|_| io_denied())?;
        self.wire.write_tls(output)
    }
    pub fn process_new_packets(&mut self) -> Result<(), TlsDenied> {
        self.check_local()?;
        self.wire.process()
    }
    pub fn wants_read(&self) -> bool {
        !self.wire.failed && self.wire.connection.wants_read()
    }
    pub fn wants_write(&self) -> bool {
        !self.wire.failed && self.wire.connection.wants_write()
    }
    pub fn is_handshaking(&self) -> bool {
        self.wire.connection.is_handshaking()
    }
    pub fn finish(self) -> Result<Authenticated, TlsDenied> {
        let conn = &self.wire.connection;
        if self.wire.failed
            || conn.is_handshaking()
            || conn.protocol_version() != Some(ProtocolVersion::TLSv1_3)
            || conn.alpn_protocol() != Some(ALPN)
            || !matches!(
                conn.handshake_kind(),
                Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
            )
        {
            return Err(TlsDenied);
        }
        let chain = conn.peer_certificates().ok_or(TlsDenied)?;
        let identity = self.context.peer(chain, now()?)?;
        let peer = TlsPeer {
            identity,
            certificate_sha256: crate::digest(chain[0].as_ref()),
        };
        Ok(Authenticated {
            wire: self.wire,
            context: self.context,
            peer,
        })
    }
}

/// Evidence of this completed TLS connection, NOT a reusable execution grant.
pub struct TlsPeer {
    identity: Identity,
    certificate_sha256: String,
}
impl TlsPeer {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
}
pub struct Authenticated {
    wire: Wire,
    context: Arc<Context>,
    peer: TlsPeer,
}
impl Authenticated {
    pub fn peer(&self) -> &TlsPeer {
        &self.peer
    }
    /// Call on renewal as well as before operations. A denial/outage permanently
    /// poisons the connection; restoring authority cannot revive the old session.
    pub fn reauthorize(&mut self) -> Result<(), TlsDenied> {
        if self.wire.failed {
            return Err(TlsDenied);
        }
        let result = (|| {
            let chain = self.wire.connection.peer_certificates().ok_or(TlsDenied)?;
            let identity = self.context.peer(chain, now()?)?;
            if identity != self.peer.identity {
                return Err(TlsDenied);
            }
            Ok(())
        })();
        if result.is_err() {
            self.wire.failed = true;
        }
        result
    }
    pub fn read_tls(&mut self, input: &mut dyn Read) -> io::Result<usize> {
        self.wire.read_tls(input)
    }
    pub fn write_tls(&mut self, output: &mut dyn Write) -> io::Result<usize> {
        self.reauthorize().map_err(|_| io_denied())?;
        self.wire.write_tls(output)
    }
    pub fn process_new_packets(&mut self) -> Result<(), TlsDenied> {
        self.wire.process()
    }
    pub fn wants_read(&self) -> bool {
        !self.wire.failed && self.wire.connection.wants_read()
    }
    pub fn wants_write(&self) -> bool {
        !self.wire.failed && self.wire.connection.wants_write()
    }
    pub fn read_plaintext(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.reauthorize().map_err(|_| io_denied())?;
        self.wire
            .connection
            .reader()
            .read(output)
            .map_err(|err| io::Error::new(err.kind(), "management TLS read failed"))
    }
    pub fn write_plaintext(&mut self, input: &[u8]) -> io::Result<usize> {
        self.reauthorize().map_err(|_| io_denied())?;
        self.wire
            .connection
            .writer()
            .write(input)
            .map_err(|err| io::Error::new(err.kind(), "management TLS write failed"))
    }
}
