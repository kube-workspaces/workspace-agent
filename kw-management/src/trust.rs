//! Cryptographic management certificate-chain verification, not a TLS handshake.
//! Explicit roots only: no OS/web-PKI fallback. A verified certificate still does
//! not prove live private-key possession or current replica/workspace authority.

use crate::certificate::{parse_leaf_profile, MAX_LEAF_DER_BYTES};
use crate::identity::Identity;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::time::Duration;
use x509_cert::der::{asn1::ObjectIdentifier, Decode};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::Certificate;

const MAX_ROOTS: usize = 16;
const MAX_INTERMEDIATES: usize = 8;
const MAX_BUNDLE_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidChain;
impl std::fmt::Display for InvalidChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management certificate chain unavailable or denied")
    }
}
impl std::error::Error for InvalidChain {}

struct Root {
    der: CertificateDer<'static>,
    not_before: u64,
    not_after: u64,
    path_len: Option<u8>,
    usages: Option<Vec<ObjectIdentifier>>,
}

/// Immutable configured trust, with bounded root overlap for planned rotation.
/// Construction validates CA shape, not current time; expired/not-yet-valid
/// anchors are excluded on each verification. No production roots are generated.
pub struct TrustStore {
    roots: Vec<Root>,
}

impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("management certificate trust store")
    }
}

impl TrustStore {
    pub fn new(root_der: &[Vec<u8>]) -> Result<Self, InvalidChain> {
        if root_der.is_empty()
            || root_der.len() > MAX_ROOTS
            || root_der
                .iter()
                .any(|der| der.is_empty() || der.len() > MAX_LEAF_DER_BYTES)
            || root_der.iter().map(Vec::len).sum::<usize>() > MAX_BUNDLE_BYTES
        {
            return Err(InvalidChain);
        }
        let mut roots = Vec::with_capacity(root_der.len());
        for der in root_der {
            if der.is_empty() || der.len() > MAX_LEAF_DER_BYTES {
                return Err(InvalidChain);
            }
            let cert = Certificate::from_der(der).map_err(|_| InvalidChain)?;
            let extensions = cert.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
            if extensions.len() > 64 {
                return Err(InvalidChain);
            }
            for (i, extension) in extensions.iter().enumerate() {
                if extensions[..i]
                    .iter()
                    .any(|prior| prior.extn_id == extension.extn_id)
                    || extension.critical
                        && !matches!(
                            extension.extn_id.to_string().as_str(),
                            "2.5.29.19" | "2.5.29.15" | "2.5.29.37" | "2.5.29.30"
                        )
                {
                    return Err(InvalidChain);
                }
            }
            let (_, basic) = cert
                .tbs_certificate
                .get::<BasicConstraints>()
                .map_err(|_| InvalidChain)?
                .ok_or(InvalidChain)?;
            let (_, usage) = cert
                .tbs_certificate
                .get::<KeyUsage>()
                .map_err(|_| InvalidChain)?
                .ok_or(InvalidChain)?;
            if !basic.ca || !usage.key_cert_sign() {
                return Err(InvalidChain);
            }
            let usages = cert
                .tbs_certificate
                .get::<ExtendedKeyUsage>()
                .map_err(|_| InvalidChain)?
                .map(|(_, usage)| usage.0);
            let not_before = cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs();
            let not_after = cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();
            if not_after <= not_before {
                return Err(InvalidChain);
            }
            let der = CertificateDer::from(der.clone());
            webpki::anchor_from_trusted_cert(&der).map_err(|_| InvalidChain)?;
            roots.push(Root {
                der,
                not_before,
                not_after,
                path_len: basic.path_len_constraint,
                usages,
            });
        }
        Ok(Self { roots })
    }

    /// Verify a certificate against configured roots, exact expected identity,
    /// current validity, management profile and role-specific chain EKU/DNS.
    /// `expected` and `now` must come from independent provisioning/current state.
    /// This returns no execution grant or authenticated-connection capability.
    pub fn verify_certificate(
        &self,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
        expected: &Identity,
        now: u64,
    ) -> Result<(), InvalidChain> {
        expected.to_uri().map_err(|_| InvalidChain)?;
        if intermediates.len() > MAX_INTERMEDIATES
            || intermediates
                .iter()
                .any(|der| der.is_empty() || der.len() > MAX_LEAF_DER_BYTES)
            || intermediates.iter().map(Vec::len).sum::<usize>() > MAX_BUNDLE_BYTES
        {
            return Err(InvalidChain);
        }
        for intermediate in intermediates {
            Certificate::from_der(intermediate).map_err(|_| InvalidChain)?;
        }
        let profile = parse_leaf_profile(leaf).map_err(|_| InvalidChain)?;
        if &profile.identity != expected {
            return Err(InvalidChain);
        }
        profile.check_time(now).map_err(|_| InvalidChain)?;
        let mut anchors = Vec::with_capacity(self.roots.len());
        let mut active_roots = Vec::with_capacity(self.roots.len());
        let purpose = ObjectIdentifier::new_unwrap(match expected {
            Identity::Api { .. } => "1.3.6.1.5.5.7.3.2",
            Identity::Guest { .. } => "1.3.6.1.5.5.7.3.1",
        });
        for root in &self.roots {
            let purpose_allowed = root.usages.as_ref().map_or(true, |usages| {
                usages.iter().any(|oid| {
                    *oid == purpose || *oid == ObjectIdentifier::new_unwrap("2.5.29.37.0")
                })
            });
            if root.not_before <= now && now < root.not_after && purpose_allowed {
                anchors
                    .push(webpki::anchor_from_trusted_cert(&root.der).map_err(|_| InvalidChain)?);
                active_roots.push(root);
            }
        }
        if anchors.is_empty() {
            return Err(InvalidChain);
        }
        let leaf = CertificateDer::from(leaf);
        let end_entity = webpki::EndEntityCert::try_from(&leaf).map_err(|_| InvalidChain)?;
        let intermediates: Vec<_> = intermediates
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        let usage = match expected {
            Identity::Api { .. } => webpki::KeyUsage::client_auth(),
            Identity::Guest { .. } => webpki::KeyUsage::server_auth(),
        };
        // webpki trust anchors intentionally omit root validity/EKU/path-length
        // fields. Preserve the configured root's restrictions independently.
        let check_root_path = |path: &webpki::VerifiedPath<'_>| {
            let index = anchors
                .iter()
                .position(|anchor| std::ptr::eq(anchor, path.anchor()))
                .ok_or(webpki::Error::UnknownIssuer)?;
            if active_roots[index]
                .path_len
                .is_some_and(|limit| path.intermediate_certificates().count() > usize::from(limit))
            {
                return Err(webpki::Error::UnknownIssuer);
            }
            Ok(())
        };
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(now)),
                usage,
                None,
                Some(&check_root_path),
            )
            .map_err(|_| InvalidChain)?;
        if matches!(expected, Identity::Guest { .. }) {
            let name =
                ServerName::try_from("management.workspace.internal").map_err(|_| InvalidChain)?;
            end_entity
                .verify_is_valid_for_subject_name(&name)
                .map_err(|_| InvalidChain)?;
        }
        Ok(())
    }
}
