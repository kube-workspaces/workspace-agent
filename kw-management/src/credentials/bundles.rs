//! Immutable public certificate snapshots in a separate dedicated root. This is
//! not service installation, rotation, enrollment networking or peer authority.

use super::{EnrollmentCertificate, KeyUnavailable, MachineKey};
use crate::{identity::Identity, trust::TrustStore};
use std::path::Path;

#[cfg(target_os = "linux")]
use super::{linux, STANDARD};
#[cfg(target_os = "linux")]
use base64::Engine;
#[cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    identity_uri: String,
    csr_sha256: String,
    chain_der: Vec<String>,
}

impl MachineKey {
    /// Persist one verified public certificate snapshot in a NEW dedicated root.
    /// Rechecks current trusted identity/time/roots and exact CSR before writing;
    /// never overwrites/adopts a root or edits the machine-key root. A failed
    /// write may leave a partial root: reopen may validate it, but never repairs
    /// or regenerates it. Publication is file/root/parent-fsynced before success.
    /// This does not install service credentials or implement renewal/rollback.
    pub fn persist_enrollment_certificate(
        &mut self,
        root: &Path,
        expected: &Identity,
        trust: &TrustStore,
        certificate: &EnrollmentCertificate,
        now: u64,
    ) -> Result<(), KeyUnavailable> {
        #[cfg(target_os = "linux")]
        {
            self.inner
                .lock()
                .map_err(|_| KeyUnavailable)?
                .storage
                .require_separate_root(root)?;
            let csr_sha256: [u8; 32] = Sha256::digest(self.csr_der(expected)?).into();
            if &certificate.identity != expected || certificate.csr_sha256 != csr_sha256 {
                return Err(KeyUnavailable);
            }
            self.verify_enrollment_certificate(expected, trust, certificate.chain.clone(), now)?;
            let record = Record {
                version: 1,
                identity_uri: expected.to_uri().map_err(|_| KeyUnavailable)?,
                csr_sha256: STANDARD.encode(csr_sha256),
                chain_der: certificate
                    .chain
                    .iter()
                    .map(|der| STANDARD.encode(der))
                    .collect(),
            };
            let raw = serde_json::to_vec(&record).map_err(|_| KeyUnavailable)?;
            let mut storage = linux::Store::initialize(root, linux::Kind::CertificateBundle)?;
            storage.write_once(&raw)?;
            storage.unchanged()?;
            self.csr_der(expected)?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, expected, trust, certificate, now);
            Err(KeyUnavailable)
        }
    }

    /// Load a public certificate snapshot, treating every persisted byte as
    /// untrusted. Revalidates canonical encoding, identity, exact CSR, configured
    /// roots and current validity. The returned artifact is a verified in-memory
    /// snapshot, not a live file guard; later edits cannot alter its bytes, and
    /// TLS setup still independently rechecks trust/time and machine-key custody.
    pub fn reopen_enrollment_certificate(
        &mut self,
        root: &Path,
        expected: &Identity,
        trust: &TrustStore,
        now: u64,
    ) -> Result<EnrollmentCertificate, KeyUnavailable> {
        #[cfg(target_os = "linux")]
        {
            let csr = self.csr_der(expected)?;
            let mut storage = linux::Store::reopen(root, linux::Kind::CertificateBundle)?;
            let raw = storage.read()?;
            storage.remember(&raw);
            let record: Record = serde_json::from_slice(&raw).map_err(|_| KeyUnavailable)?;
            if raw.as_slice() != serde_json::to_vec(&record).map_err(|_| KeyUnavailable)?
                || record.version != 1
                || record.identity_uri != expected.to_uri().map_err(|_| KeyUnavailable)?
                || record.csr_sha256 != STANDARD.encode(Sha256::digest(&csr))
                || record.chain_der.is_empty()
                || record.chain_der.len() > 9
            {
                return Err(KeyUnavailable);
            }
            let chain = record
                .chain_der
                .iter()
                .map(|encoded| {
                    let der = STANDARD.decode(encoded).map_err(|_| KeyUnavailable)?;
                    if STANDARD.encode(&der) != *encoded {
                        return Err(KeyUnavailable);
                    }
                    Ok(der)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let certificate = self.verify_enrollment_certificate(expected, trust, chain, now)?;
            storage.unchanged()?;
            Ok(certificate)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, expected, trust, now);
            Err(KeyUnavailable)
        }
    }
}
