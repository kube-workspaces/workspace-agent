//! Management leaf profile inspection. This module does NOT verify signatures,
//! chains, trust roots, key possession, TLS or current peer authorization.
//! Never treat a successful parse as authenticated authority.

use crate::identity::Identity;
use x509_cert::der::{asn1::ObjectIdentifier, Decode};
use x509_cert::ext::pkix::{
    name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::Certificate;

pub const MAX_LEAF_DER_BYTES: usize = 64 * 1024;
const MAX_LEAF_WINDOW_SECONDS: u64 = 3600 + 30;
const SERVER_NAME: &str = "management.workspace.internal";
const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCertificate;

impl std::fmt::Display for InvalidCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid management certificate profile")
    }
}
impl std::error::Error for InvalidCertificate {}

/// Public, untrusted profile information. No instance of this struct proves
/// certificate authenticity, even when the time and identity match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafProfile {
    pub identity: Identity,
    pub not_before: u64,
    pub not_after: u64,
}

impl LeafProfile {
    /// Enforce the current validity window using an independently sourced clock.
    /// This is an additional check, not a replacement for TLS chain validation.
    pub fn check_time(&self, now_unix_seconds: u64) -> Result<(), InvalidCertificate> {
        if self.not_after <= self.not_before
            || self.not_after - self.not_before > MAX_LEAF_WINDOW_SECONDS
            || now_unix_seconds < self.not_before
            || now_unix_seconds >= self.not_after
        {
            return Err(InvalidCertificate);
        }
        Ok(())
    }
}

pub fn parse_leaf_profile(der: &[u8]) -> Result<LeafProfile, InvalidCertificate> {
    if der.is_empty() || der.len() > MAX_LEAF_DER_BYTES {
        return Err(InvalidCertificate);
    }
    let cert = Certificate::from_der(der).map_err(|_| InvalidCertificate)?;
    let tbs = &cert.tbs_certificate;
    if cert.signature_algorithm != tbs.signature {
        return Err(InvalidCertificate);
    }
    // Duplicate extensions are ambiguous even if only one is currently used.
    let extensions = tbs.extensions.as_deref().unwrap_or(&[]);
    if extensions.len() > 64 {
        return Err(InvalidCertificate);
    }
    for (i, extension) in extensions.iter().enumerate() {
        if extensions[..i]
            .iter()
            .any(|prior| prior.extn_id == extension.extn_id)
        {
            return Err(InvalidCertificate);
        }
    }
    if tbs
        .get::<BasicConstraints>()
        .map_err(|_| InvalidCertificate)?
        .is_some_and(|(_, bc)| bc.ca)
    {
        return Err(InvalidCertificate);
    }
    let (_, key_usage) = tbs
        .get::<KeyUsage>()
        .map_err(|_| InvalidCertificate)?
        .ok_or(InvalidCertificate)?;
    if key_usage != KeyUsage(KeyUsages::DigitalSignature.into()) {
        return Err(InvalidCertificate);
    }
    let (_, eku) = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| InvalidCertificate)?
        .ok_or(InvalidCertificate)?;
    if eku.0.len() != 1 {
        return Err(InvalidCertificate);
    }
    let (_, san) = tbs
        .get::<SubjectAltName>()
        .map_err(|_| InvalidCertificate)?
        .ok_or(InvalidCertificate)?;
    let mut identity = None;
    let mut dns_count = 0;
    for name in &san.0 {
        match name {
            GeneralName::UniformResourceIdentifier(uri) if identity.is_none() => {
                identity = Some(Identity::from_uri(uri.as_str()).map_err(|_| InvalidCertificate)?);
            }
            GeneralName::DnsName(name) if name.as_str() == SERVER_NAME => {
                dns_count += 1;
            }
            _ => return Err(InvalidCertificate),
        }
    }
    let identity = identity.ok_or(InvalidCertificate)?;
    match &identity {
        Identity::Api { .. } if dns_count == 0 && eku.0[0] == CLIENT_AUTH => {}
        Identity::Guest { .. } if dns_count == 1 && eku.0[0] == SERVER_AUTH => {}
        _ => return Err(InvalidCertificate),
    }
    let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs();
    if not_after <= not_before || not_after - not_before > MAX_LEAF_WINDOW_SECONDS {
        return Err(InvalidCertificate);
    }
    Ok(LeafProfile {
        identity,
        not_before,
        not_after,
    })
}
