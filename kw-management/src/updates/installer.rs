//! Typed MSI transaction dispatch boundary for the independent updater.
//!
//! No service/listener is wired to this module. Native package verification,
//! Windows Installer inventory and current phase authority are required adapter
//! contracts. The dispatcher never accepts installer flags, scripts or arbitrary
//! ProductCodes. Driver-changing transactions require their own qualified adapter.

use super::{
    journal::{Action, ActionReceipt, CommittedAction, Plan},
    version, VerifiedManifest, AGENT_UPGRADE_CODE,
};

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Binding,
    Unsupported,
    Authority,
    Inventory,
    Busy,
    RebootPending,
    Package,
    /// An effect may have started or an observed result contradicts its return
    /// code. Reconcile the active journal action; never automatically retry it.
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Product {
    pub product_code: String,
    pub upgrade_code: String,
    pub version: String,
    pub install_directory: String,
}

/// A fresh per-machine Windows Installer observation, not Win32_Product or
/// monitoring metadata. Unknown/pending registration must return Inventory error.
#[derive(Debug)]
pub struct Observation {
    pub products: Vec<Product>,
    pub installer_busy: bool,
    pub reboot_pending: bool,
}

/// Immutable projection of a publisher-verified manifest. Native adapters must
/// locate it in protected staging, pin the file against replacement, rehash the
/// signed size/digest, and verify MSI ProductCode/UpgradeCode/ProductVersion
/// before returning from verify_package. The pin must survive the installer call.
#[derive(Debug)]
pub struct Package {
    file: String,
    sha256: String,
    size: u64,
    product_code: String,
    version: String,
}

impl Package {
    fn from_manifest(manifest: &VerifiedManifest) -> Self {
        let m = manifest.metadata();
        Self {
            file: m.msi.artifact.file.clone(),
            sha256: m.msi.artifact.sha256.clone(),
            size: m.msi.artifact.size,
            product_code: m.msi.product_code.clone(),
            version: m.agent_version.clone(),
        }
    }
    pub fn file(&self) -> &str {
        &self.file
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn product_code(&self) -> &str {
        &self.product_code
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn upgrade_code(&self) -> &str {
        AGENT_UPGRADE_CODE
    }
}

/// Native implementations use fixed Windows Installer APIs, machine-wide quiet
/// installation and reboot suppression. They may not force-kill an active MSI,
/// globally bypass downgrade protection, or delete ProgramData/identity data.
/// Installation/compensation never takes a caller-selected property string.
pub trait MsiAdapter {
    fn observe(&mut self) -> Result<Observation, Error>;
    fn verify_package(&mut self, package: &Package) -> Result<(), Error>;
    fn install(&mut self, package: &Package, install_directory: &str) -> Result<u32, Error>;
    fn uninstall(&mut self, product: &Product) -> Result<u32, Error>;
}

/// Revalidate the current identity, epoch, boot ID, lease/fence, cancellation/deadline,
/// policy and recorded phase authority after all preparation and immediately
/// before each side effect. No permissive production implementation is supplied.
pub trait PhaseAuthority {
    fn authorize(&mut self, plan: &Plan, action: &Action, owner_fence: u64) -> Result<(), Error>;
}

pub struct Transaction {
    plan: Plan,
    target: Package,
    previous: Package,
    install_directory: String,
}

impl Transaction {
    /// The recorded install directory must come from authenticated initial MSI
    /// inventory, not an API request. Each fresh observation must match it.
    pub fn new(
        plan: Plan,
        target: &VerifiedManifest,
        previous: &VerifiedManifest,
        install_directory: String,
    ) -> Result<Self, Error> {
        let t = target.metadata();
        let p = previous.metadata();
        if target.sha256() != plan.binding.target_sha256
            || previous.sha256() != plan.binding.previous_sha256
            || t.msi.product_code != plan.target_product_code
            || p.msi.product_code != plan.previous_product_code
            || t.msi.product_code == p.msi.product_code
            || !t.rollback_predecessors.iter().any(|entry| {
                entry.target_id == p.target_id && entry.manifest_sha256 == previous.sha256()
            })
            || !valid_directory(&install_directory)
        {
            return Err(Error::Binding);
        }
        if t.driver.is_some()
            || p.driver.is_some()
            || !plan.target_driver_sha256.is_empty()
            || !plan.previous_driver_sha256.is_empty()
        {
            return Err(Error::Unsupported);
        }
        let current = version(&p.agent_version, 3).ok_or(Error::Binding)?;
        let minimum = version(&t.compatibility.minimum_agent_version, 3).ok_or(Error::Binding)?;
        let maximum = version(&t.compatibility.maximum_agent_version, 3).ok_or(Error::Binding)?;
        if current < minimum || current > maximum {
            return Err(Error::Binding);
        }
        Ok(Self {
            plan,
            target: Package::from_manifest(target),
            previous: Package::from_manifest(previous),
            install_directory,
        })
    }

    /// Consume exactly one newly committed phase permit. A decoded journal or
    /// serialized action cannot call this path; interrupted actions reconcile.
    pub fn dispatch(
        &self,
        permit: CommittedAction,
        adapter: &mut impl MsiAdapter,
        authority: &mut impl PhaseAuthority,
    ) -> Result<ActionReceipt, Error> {
        let (action, plan, owner_fence) = permit.into_parts();
        if plan != self.plan {
            return Err(Error::Binding);
        }
        if ![
            "install_target_msi",
            "uninstall_target_msi",
            "install_previous_msi",
        ]
        .contains(&action.kind.as_str())
        {
            return Err(Error::Unsupported);
        }
        // Verify both recovery payloads before every new mutation, including
        // compensation. Native adapters retain their protected-file pins.
        adapter.verify_package(&self.target)?;
        adapter.verify_package(&self.previous)?;
        let before = adapter.observe()?;
        if before.installer_busy {
            return Err(Error::Busy);
        }
        if before.reboot_pending {
            return Err(Error::RebootPending);
        }
        self.validate_products(&before)?;
        let expected_before = match action.kind.as_str() {
            "install_target_msi" => Some(&self.previous),
            "uninstall_target_msi" => Some(&self.target),
            _ => None,
        };
        if let Some(package) = expected_before {
            if before.products.len() != 1 || !self.matches(&before.products[0], package) {
                return Err(Error::Inventory);
            }
        } else if !before.products.is_empty() {
            // Do not reinstall/repair a predecessor or remove an unrelated
            // target merely because compensation was requested.
            return Err(Error::Inventory);
        }
        authority.authorize(&self.plan, &action, owner_fence)?;
        let code = match action.kind.as_str() {
            "install_target_msi" => adapter.install(&self.target, &self.install_directory),
            "uninstall_target_msi" => adapter.uninstall(&before.products[0]),
            _ => adapter.install(&self.previous, &self.install_directory),
        }
        .map_err(|_| Error::Uncertain)?;
        // No retry after dispatch, even when native result/observation is lost.
        let after = adapter.observe().map_err(|_| Error::Uncertain)?;
        self.validate_products(&after)
            .map_err(|_| Error::Uncertain)?;
        if after.installer_busy {
            return Err(Error::Uncertain);
        }
        if code == 0 {
            let expected = match action.kind.as_str() {
                "install_target_msi" => Some(&self.target),
                "install_previous_msi" => Some(&self.previous),
                _ => None,
            };
            if let Some(package) = expected {
                if after.products.len() != 1 || !self.matches(&after.products[0], package) {
                    return Err(Error::Uncertain);
                }
            } else if !after.products.is_empty() {
                return Err(Error::Uncertain);
            }
        }
        let outcome = match code {
            0 => "ok",
            3010 | 1641 => "reboot_required",
            _ => "failed",
        };
        // A pending-reboot observation inconsistent with exit 0 also requires
        // reconciliation; it is never silently reported as a completed phase.
        if code == 0 && after.reboot_pending {
            return Err(Error::Uncertain);
        }
        Ok(ActionReceipt {
            sequence: action.sequence,
            kind: action.kind,
            outcome: outcome.into(),
            msi_code: Some(i64::from(code)),
            service_state: String::new(),
            product_code: after
                .products
                .first()
                .map(|p| p.product_code.clone())
                .unwrap_or_default(),
            target_absent: !after
                .products
                .iter()
                .any(|p| p.product_code == self.target.product_code),
            driver_sha256: String::new(),
            identity_verified: false,
            health_verified: false,
        })
    }

    fn validate_products(&self, observation: &Observation) -> Result<(), Error> {
        if observation.products.len() > 1
            || observation
                .products
                .iter()
                .any(|p| !self.matches(p, &self.target) && !self.matches(p, &self.previous))
        {
            return Err(Error::Inventory);
        }
        Ok(())
    }

    fn matches(&self, product: &Product, package: &Package) -> bool {
        product.product_code == package.product_code
            && product.upgrade_code == AGENT_UPGRADE_CODE
            && product.version == package.version
            && product.install_directory == self.install_directory
    }
}

fn valid_directory(path: &str) -> bool {
    // Conservative machine-local Windows path, suitable for a fixed MSI property
    // encoder. No UNC/device paths, alternate streams, traversal or interpolation.
    let bytes = path.as_bytes();
    path.len() <= 240
        && bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..3] == *b":\\"
        && path[3..]
            .strip_suffix('\\')
            .unwrap_or(&path[3..])
            .split('\\')
            .all(valid_component)
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '%' | '/' | '*' | '?' | '<' | '>' | '|'))
        && !path[2..].contains(':')
}

fn valid_component(part: &str) -> bool {
    if part.is_empty() || part == "." || part == ".." || part.ends_with(['.', ' ']) {
        return false;
    }
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    !["con", "prn", "aux", "nul"].contains(&stem.as_str())
        && !(stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && (b'1'..=b'9').contains(&stem.as_bytes()[3]))
}
