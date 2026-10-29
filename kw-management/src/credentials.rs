//! Guest-held enrollment key and exact retry CSR. No bootstrap-token redemption,
//! issuance authority, certificate installation or listener is provided here.
//! Linux storage is private to the creating effective UID (use the privileged
//! machine service in production); other platforms fail closed pending native
//! storage protection. Desktop identity files are never read or adopted.

use crate::{
    identity::Identity,
    tls::{Authorize, Server},
    trust::TrustStore,
};
#[cfg(any(target_os = "linux", test))]
use base64::{engine::general_purpose::STANDARD, Engine};
#[cfg(any(target_os = "linux", test))]
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    Signature, Signer, SigningKey,
};
#[cfg(any(target_os = "linux", test))]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::{path::Path, sync::Arc};
#[cfg(any(target_os = "linux", test))]
use x509_cert::{
    der::{
        asn1::{BitString, ObjectIdentifier},
        Decode, Encode,
    },
    request::{CertReq, CertReqInfo, Version},
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};
#[cfg(any(target_os = "linux", test))]
use zeroize::{Zeroize, Zeroizing};

mod bundles;
#[cfg(target_os = "linux")]
mod linux;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUnavailable;
impl std::fmt::Display for KeyUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management machine key unavailable or denied")
    }
}
impl std::error::Error for KeyUnavailable {}

/// A certificate response verified for one exact persisted guest CSR. This is
/// only a point-in-time validation result, not current peer/execution authority.
/// No deserializer/unchecked constructor exists; installation is not implemented.
pub struct EnrollmentCertificate {
    #[cfg(target_os = "linux")]
    identity: Identity,
    #[cfg(target_os = "linux")]
    csr_sha256: [u8; 32],
    chain: Vec<Vec<u8>>,
}
impl std::fmt::Debug for EnrollmentCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management enrollment certificate (scope and contents redacted)")
    }
}
impl EnrollmentCertificate {
    /// Public DER, leaf first. Future installers must revalidate after loading;
    /// these bytes do not carry trusted roots or preserve this verified type.
    pub fn chain_der(&self) -> &[Vec<u8>] {
        &self.chain
    }
}

fn guest_identity(expected: &Identity) -> Result<(), KeyUnavailable> {
    if !matches!(expected, Identity::Guest { .. }) {
        return Err(KeyUnavailable);
    }
    expected.to_uri().map_err(|_| KeyUnavailable)?;
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
        parameters: None,
    }
}
#[cfg(any(target_os = "linux", test))]
fn public_key(key: &SigningKey) -> Result<SubjectPublicKeyInfoOwned, KeyUnavailable> {
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: algorithm(),
        subject_public_key: BitString::from_bytes(key.verifying_key().as_bytes())
            .map_err(|_| KeyUnavailable)?,
    })
}
#[cfg(any(target_os = "linux", test))]
struct Request {
    identity: Identity,
    key: SigningKey,
    csr: Vec<u8>,
}
#[cfg(any(target_os = "linux", test))]
impl Request {
    fn generate(expected: &Identity) -> Result<Self, KeyUnavailable> {
        guest_identity(expected)?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::getrandom(&mut *seed).map_err(|_| KeyUnavailable)?;
        let key = SigningKey::from_bytes(&seed);
        let info = CertReqInfo {
            version: Version::V1,
            subject: Default::default(),
            public_key: public_key(&key)?,
            attributes: Default::default(),
        };
        let signature = key.sign(&info.to_der().map_err(|_| KeyUnavailable)?);
        let csr = CertReq {
            info,
            algorithm: algorithm(),
            signature: BitString::from_bytes(&signature.to_bytes()).map_err(|_| KeyUnavailable)?,
        }
        .to_der()
        .map_err(|_| KeyUnavailable)?;
        Ok(Self {
            identity: expected.clone(),
            key,
            csr,
        })
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, KeyUnavailable> {
        let key = self.key.to_pkcs8_der().map_err(|_| KeyUnavailable)?;
        let record = Record {
            version: 1,
            identity_uri: self.identity.to_uri().map_err(|_| KeyUnavailable)?,
            private_key_pkcs8: STANDARD.encode(key.as_bytes()),
            csr_der: STANDARD.encode(&self.csr),
        };
        Ok(Zeroizing::new(
            serde_json::to_vec(&record).map_err(|_| KeyUnavailable)?,
        ))
    }
    fn decode(raw: &[u8], expected: &Identity) -> Result<Self, KeyUnavailable> {
        guest_identity(expected)?;
        let record: Record = serde_json::from_slice(raw).map_err(|_| KeyUnavailable)?;
        let canonical = Zeroizing::new(serde_json::to_vec(&record).map_err(|_| KeyUnavailable)?);
        if raw != canonical.as_slice()
            || record.version != 1
            || Identity::from_uri(&record.identity_uri).map_err(|_| KeyUnavailable)? != *expected
        {
            return Err(KeyUnavailable);
        }
        let der = Zeroizing::new(
            STANDARD
                .decode(&record.private_key_pkcs8)
                .map_err(|_| KeyUnavailable)?,
        );
        let csr = STANDARD
            .decode(&record.csr_der)
            .map_err(|_| KeyUnavailable)?;
        let encoded_key = Zeroizing::new(STANDARD.encode(&*der));
        if encoded_key.as_str() != record.private_key_pkcs8.as_str()
            || STANDARD.encode(&csr) != record.csr_der
        {
            return Err(KeyUnavailable);
        }
        let key = SigningKey::from_pkcs8_der(&der).map_err(|_| KeyUnavailable)?;
        let request = CertReq::from_der(&csr).map_err(|_| KeyUnavailable)?;
        if request.algorithm != algorithm()
            || request.info.version != Version::V1
            || !request.info.subject.is_empty()
            || !request.info.attributes.is_empty()
            || request.info.public_key != public_key(&key)?
        {
            return Err(KeyUnavailable);
        }
        let signature = Signature::from_slice(request.signature.as_bytes().ok_or(KeyUnavailable)?)
            .map_err(|_| KeyUnavailable)?;
        key.verifying_key()
            .verify_strict(
                &request.info.to_der().map_err(|_| KeyUnavailable)?,
                &signature,
            )
            .map_err(|_| KeyUnavailable)?;
        Ok(Self {
            identity: expected.clone(),
            key,
            csr,
        })
    }
}
#[cfg(any(target_os = "linux", test))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    identity_uri: String,
    private_key_pkcs8: String,
    csr_der: String,
}
#[cfg(any(target_os = "linux", test))]
impl Drop for Record {
    fn drop(&mut self) {
        self.private_key_pkcs8.zeroize();
    }
}

/// An exclusively held machine key. Creation never adopts an existing root;
/// reopening never regenerates missing/corrupt material or rebinds its identity.
/// Expected identity must come from fresh, trusted provisioning/current state.
pub struct MachineKey {
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
    #[cfg(target_os = "linux")]
    inner: Arc<Mutex<Inner>>,
}
#[cfg(target_os = "linux")]
struct Inner {
    request: Request,
    storage: linux::Store,
    poisoned: bool,
}
#[cfg(target_os = "linux")]
impl Inner {
    fn check(&mut self, expected: &Identity) -> Result<(), KeyUnavailable> {
        if self.poisoned {
            return Err(KeyUnavailable);
        }
        if &self.request.identity != expected || self.storage.unchanged().is_err() {
            self.poisoned = true;
            return Err(KeyUnavailable);
        }
        Ok(())
    }
}
impl std::fmt::Debug for MachineKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management machine key (private material and location redacted)")
    }
}
impl MachineKey {
    /// Verify untrusted enrollment response certificates against independently
    /// configured roots, current trusted guest identity/time and the exact stored
    /// CSR's public key. Never adopt trust roots from an enrollment response.
    /// Callers must bound network input before allocation; this bounds parsing.
    pub fn verify_enrollment_certificate(
        &mut self,
        expected: &Identity,
        trust: &TrustStore,
        chain: Vec<Vec<u8>>,
        now: u64,
    ) -> Result<EnrollmentCertificate, KeyUnavailable> {
        #[cfg(target_os = "linux")]
        {
            let mut inner = self.inner.lock().map_err(|_| KeyUnavailable)?;
            inner.check(expected)?;
            let (leaf, intermediates) = chain.split_first().ok_or(KeyUnavailable)?;
            // TrustStore applies bounded DER/profile/path parsing before we
            // inspect SPKI. Identity, time, EKU, DNS and issuer all must match.
            trust
                .verify_certificate(leaf, intermediates, expected, now)
                .map_err(|_| KeyUnavailable)?;
            let certificate = x509_cert::Certificate::from_der(leaf).map_err(|_| KeyUnavailable)?;
            if certificate.tbs_certificate.subject_public_key_info
                != public_key(&inner.request.key)?
            {
                return Err(KeyUnavailable);
            }
            inner.check(expected)?;
            Ok(EnrollmentCertificate {
                identity: expected.clone(),
                csr_sha256: Sha256::digest(&inner.request.csr).into(),
                chain,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected, trust, chain, now);
            Err(KeyUnavailable)
        }
    }

    /// Recheck custody and exact-CSR binding, then revalidate the chain at the
    /// current time under the supplied trust store. A prior verified response
    /// cannot bypass expiry, root removal or replacement by another machine key.
    pub fn tls_server_from_enrollment(
        &mut self,
        expected: &Identity,
        trust: Arc<TrustStore>,
        certificate: &EnrollmentCertificate,
        authorize: Arc<Authorize>,
    ) -> Result<Server, KeyUnavailable> {
        #[cfg(target_os = "linux")]
        {
            let csr = self.csr_der(expected)?;
            if &certificate.identity != expected
                || certificate.csr_sha256 != <[u8; 32]>::from(Sha256::digest(&csr))
            {
                return Err(KeyUnavailable);
            }
            self.tls_server(expected, trust, certificate.chain.clone(), authorize)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected, trust, certificate, authorize);
            Err(KeyUnavailable)
        }
    }

    pub fn initialize(root: &Path, expected: &Identity) -> Result<Self, KeyUnavailable> {
        guest_identity(expected)?;
        #[cfg(target_os = "linux")]
        {
            let mut storage = linux::Store::initialize(root, linux::Kind::MachineKey)?;
            let request = Request::generate(expected)?;
            storage.write_once(&request.encode()?)?;
            Ok(Self {
                inner: Arc::new(Mutex::new(Inner {
                    request,
                    storage,
                    poisoned: false,
                })),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            Err(KeyUnavailable)
        }
    }
    pub fn reopen(root: &Path, expected: &Identity) -> Result<Self, KeyUnavailable> {
        guest_identity(expected)?;
        #[cfg(target_os = "linux")]
        {
            let mut storage = linux::Store::reopen(root, linux::Kind::MachineKey)?;
            let raw = storage.read()?;
            let request = Request::decode(&raw, expected)?;
            storage.remember(&raw);
            Ok(Self {
                inner: Arc::new(Mutex::new(Inner {
                    request,
                    storage,
                    poisoned: false,
                })),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            Err(KeyUnavailable)
        }
    }
    /// Public CSR bytes only. Reopen/retry returns exactly the persisted CSR,
    /// not a new key or newly generated request that would rebind enrollment.
    pub fn csr_der(&mut self, expected: &Identity) -> Result<Vec<u8>, KeyUnavailable> {
        #[cfg(target_os = "linux")]
        {
            let mut inner = self.inner.lock().map_err(|_| KeyUnavailable)?;
            inner.check(expected)?;
            Ok(inner.request.csr.clone())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected;
            Err(KeyUnavailable)
        }
    }
    /// Load the private key directly into verified TLS server state. No raw key
    /// accessor is exposed. Roots and certificates must be independently trusted;
    /// this does not install/persist certificates or start any listener.
    pub fn tls_server(
        &mut self,
        expected: &Identity,
        trust: Arc<TrustStore>,
        chain: Vec<Vec<u8>>,
        authorize: Arc<Authorize>,
    ) -> Result<Server, KeyUnavailable> {
        #[cfg(target_os = "linux")]
        {
            let key = {
                let mut inner = self.inner.lock().map_err(|_| KeyUnavailable)?;
                inner.check(expected)?;
                inner
                    .request
                    .key
                    .to_pkcs8_der()
                    .map_err(|_| KeyUnavailable)?
            };
            // Every TLS state retains this guard, including pending handshakes
            // and established connections that outlive the loader/server handle.
            let guard = self.inner.clone();
            let local_guard: Arc<crate::tls::LocalGuard> = Arc::new(move |local| {
                let mut inner = guard.lock().map_err(|_| crate::tls::TlsDenied)?;
                inner.check(local).map_err(|_| crate::tls::TlsDenied)
            });
            Server::with_local_guard(
                trust,
                expected.clone(),
                chain,
                key.as_bytes().to_vec(),
                authorize,
                Some(local_guard),
            )
            .map_err(|_| KeyUnavailable)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected, trust, chain, authorize);
            Err(KeyUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity::from_uri("spiffe://kubeworkspaces.io/management/v1/workspaces/team/vm/uid/gen/1")
            .unwrap()
    }
    #[test]
    fn csr_has_only_proof_of_possession_and_roundtrips_exactly() {
        let request = Request::generate(&identity()).unwrap();
        let encoded = request.encode().unwrap();
        let reopened = Request::decode(&encoded, &identity()).unwrap();
        assert_eq!(request.csr, reopened.csr);
        assert_eq!(request.key.verifying_key(), reopened.key.verifying_key());
        let csr = CertReq::from_der(&request.csr).unwrap();
        assert!(csr.info.subject.is_empty());
        assert!(csr.info.attributes.is_empty());
        let other = Request::generate(&identity()).unwrap();
        assert_ne!(request.csr, other.csr);
        let mut record: Record = serde_json::from_slice(&encoded).unwrap();
        record.csr_der = STANDARD.encode(other.csr);
        assert!(Request::decode(&serde_json::to_vec(&record).unwrap(), &identity()).is_err());
        let mut record: Record = serde_json::from_slice(&encoded).unwrap();
        let mut csr = CertReq::from_der(&request.csr).unwrap();
        let mut signature = csr.signature.as_bytes().unwrap().to_vec();
        signature[0] ^= 1;
        csr.signature = BitString::from_bytes(&signature).unwrap();
        record.csr_der = STANDARD.encode(csr.to_der().unwrap());
        assert!(Request::decode(&serde_json::to_vec(&record).unwrap(), &identity()).is_err());
        let mut changed = identity();
        if let Identity::Guest { generation, .. } = &mut changed {
            *generation = "other".into();
        }
        assert!(Request::decode(&encoded, &changed).is_err());
        assert!(Request::decode(b"private-key-marker", &identity()).is_err());
    }
    #[test]
    fn aliases_duplicate_fields_and_noncanonical_records_deny() {
        let request = Request::generate(&identity()).unwrap();
        let encoded = request.encode().unwrap();
        let mut whitespace = encoded.to_vec();
        whitespace.push(b'\n');
        assert!(Request::decode(&whitespace, &identity()).is_err());
        let duplicate = String::from_utf8(encoded.to_vec()).unwrap().replacen(
            "\"version\":1",
            "\"version\":1,\"version\":1",
            1,
        );
        assert!(Request::decode(duplicate.as_bytes(), &identity()).is_err());
        assert!(Request::generate(&Identity::Api {
            replica_id: "api-1".into()
        })
        .is_err());
    }
}
