//! Authenticated `management.inventory.v1` machine reports. The exact signed
//! bytes become the installed-inventory digest; the server-minted nonce and
//! freshness window are bound after signature verification. This module grants
//! no upgrade authority and implements no transport.

use super::{
    digest, identifier, journal::MAX_JOURNAL_SEQUENCE, key_id, valid_digest, valid_guid, version,
    AGENT_UPGRADE_CODE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const INVENTORY_DOMAIN: &[u8] = b"kw-management-inventory/v1\0";
pub const MAX_INVENTORY_BYTES: usize = 32 * 1024;
pub const INVENTORY_FRESH_SECONDS: i64 = 60;
pub const MAX_INVENTORY_MSI: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Untrusted,
    Signature,
    Fresh,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Msi {
    pub product_code: String,
    pub upgrade_code: String,
    pub version: String,
    pub install_directory: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Driver {
    pub package_identity: String,
    pub package_sha256: String,
    pub inf_name: String,
    pub device_instance: String,
    pub driver_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub attempt_id: String,
    pub phase: String,
    pub sequence: u64,
}

/// Agent-side machine report. Every string field is ASCII-bounded so the
/// canonical encoding stays byte-identical to the Go re-encode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub version: u32,
    pub nonce: String,
    pub timestamp: i64,
    pub namespace: String,
    pub name: String,
    pub workspace_uid: String,
    pub vm_uid: String,
    pub revocation_epoch: u64,
    pub os: String,
    pub architecture: String,
    pub agent_version: String,
    pub build_sha256: String,
    pub management_min: u16,
    pub management_max: u16,
    pub updater_min: u16,
    pub updater_max: u16,
    pub msi: Vec<Msi>,
    pub driver: Option<Driver>,
    pub pending_reboot: bool,
    pub attempt: Option<Attempt>,
}

#[derive(Debug)]
pub struct VerifiedInventory {
    inventory: Inventory,
    digest: String,
}

/// The exact report bytes plus the detached signature, produced by the agent
/// with its enrolled identity key. Signing is evidence production, not trust.
pub struct SignedInventory {
    pub key_id: String,
    pub inventory_sha256: String,
    pub signature: [u8; 64],
}

impl Inventory {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("inventory schema serialization is infallible")
    }

    fn valid(&self) -> bool {
        if self.version != 1
            || !valid_nonce(&self.nonce)
            || self.timestamp <= 0
            || self.revocation_epoch > i64::MAX as u64
            || !identifier(&self.namespace)
            || !identifier(&self.name)
            || !identifier(&self.workspace_uid)
            || !identifier(&self.vm_uid)
            || self.os != "windows"
            || self.architecture != "amd64"
            || version(&self.agent_version, 3).is_none()
            || !valid_digest(&self.build_sha256)
            || self.management_min == 0
            || self.management_max < self.management_min
            || self.management_max > 64
            || self.updater_min == 0
            || self.updater_max < self.updater_min
            || self.updater_max > 64
            || self.msi.is_empty()
            || self.msi.len() > MAX_INVENTORY_MSI
        {
            return false;
        }
        let mut agent = 0_usize;
        let mut products = HashSet::new();
        for registration in &self.msi {
            if !valid_guid(&registration.product_code)
                || registration.product_code == "00000000-0000-0000-0000-000000000000"
                || !valid_guid(&registration.upgrade_code)
                || registration.product_code == registration.upgrade_code
                || !products.insert(&registration.product_code)
                || version(&registration.version, 3).is_none()
                || !valid_install_directory(&registration.install_directory)
            {
                return false;
            }
            if registration.upgrade_code == AGENT_UPGRADE_CODE {
                agent += 1;
            }
        }
        if agent != 1 {
            return false;
        }
        if let Some(driver) = &self.driver {
            if !package_identity(&driver.package_identity)
                || !valid_digest(&driver.package_sha256)
                || !valid_inf_name(&driver.inf_name)
                || driver.device_instance.is_empty()
                || driver.device_instance.len() > 128
                || !driver.device_instance.contains('\\')
                || !driver
                    .device_instance
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.&\\-".contains(&b))
                || version(&driver.driver_version, 4).is_none()
            {
                return false;
            }
        }
        if let Some(attempt) = &self.attempt {
            if !identifier(&attempt.attempt_id)
                || !valid_journal_phase(&attempt.phase)
                || attempt.sequence > MAX_JOURNAL_SEQUENCE
            {
                return false;
            }
        }
        true
    }
}

impl VerifiedInventory {
    pub fn sha256(&self) -> &str {
        &self.digest
    }

    pub fn metadata(&self) -> &Inventory {
        &self.inventory
    }
}

/// Agent-side producer over the exact encoded bytes. The keyring and nonce are
/// supplied by the verifier; neither comes from this report.
pub fn sign(inventory: &Inventory, key: &SigningKey) -> SignedInventory {
    let raw = inventory.encode();
    let mut message = Vec::with_capacity(INVENTORY_DOMAIN.len() + raw.len());
    message.extend_from_slice(INVENTORY_DOMAIN);
    message.extend_from_slice(&raw);
    let public = key.verifying_key().to_bytes();
    SignedInventory {
        key_id: key_id(&public),
        inventory_sha256: digest(&raw),
        signature: key.sign(&message).to_bytes(),
    }
}

pub fn verify(
    raw: &[u8],
    signature: &[u8],
    id: &str,
    expected_nonce: &str,
    now: i64,
    keys: &HashMap<String, [u8; 32]>,
) -> Result<VerifiedInventory, Error> {
    if raw.is_empty() || raw.len() > MAX_INVENTORY_BYTES || std::str::from_utf8(raw).is_err() {
        return Err(Error::Invalid);
    }
    if keys.is_empty() || keys.len() > 16 || keys.iter().any(|(id, public)| id != &key_id(public)) {
        return Err(Error::Untrusted);
    }
    let public = keys.get(id).ok_or(Error::Untrusted)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::Untrusted)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
    let mut message = Vec::with_capacity(INVENTORY_DOMAIN.len() + raw.len());
    message.extend_from_slice(INVENTORY_DOMAIN);
    message.extend_from_slice(raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::Signature)?;
    // from_slice rejects unknown/duplicate fields and trailing JSON; the
    // canonical re-encode also requires every field, including null sections,
    // to appear exactly as serde would write it.
    let inventory: Inventory = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
    if !inventory.valid() || inventory.encode() != raw {
        return Err(Error::Invalid);
    }
    if !valid_nonce(&inventory.nonce) || inventory.nonce != expected_nonce {
        return Err(Error::Fresh);
    }
    if now < inventory.timestamp || now - inventory.timestamp > INVENTORY_FRESH_SECONDS {
        return Err(Error::Fresh);
    }
    Ok(VerifiedInventory {
        inventory,
        digest: digest(raw),
    })
}

fn valid_nonce(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == value)
}

fn valid_install_directory(value: &str) -> bool {
    !value.is_empty() && value.len() <= 260 && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn valid_inf_name(value: &str) -> bool {
    if !identifier(value) || value.ends_with('.') || !value.ends_with(".inf") {
        return false;
    }
    let stem = value.split('.').next().unwrap_or_default();
    if ["con", "prn", "aux", "nul"].contains(&stem) {
        return false;
    }
    !(stem.len() == 4
        && (stem.starts_with("com") || stem.starts_with("lpt"))
        && (b'1'..=b'9').contains(&stem.as_bytes()[3]))
}

fn package_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
}

fn valid_journal_phase(value: &str) -> bool {
    matches!(
        value,
        "ready" | "active" | "awaiting_reboot" | "rollback_pending" | "result_pending" | "terminal"
    )
}
