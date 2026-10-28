//! Canonical management certificate URI identities, shared with the API PKI.
//!
//! Parsing is NOT authentication: use only after certificate-chain, purpose,
//! lifetime and TLS protocol verification. A trusted leaf still requires fresh
//! replica/workspace authorization. No listener or enrollment authority lives here.

const API_PREFIX: &str = "spiffe://kubeworkspaces.io/management/v1/apis/";
const GUEST_PREFIX: &str = "spiffe://kubeworkspaces.io/management/v1/workspaces/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Identity {
    Api {
        replica_id: String,
    },
    Guest {
        namespace: String,
        workspace_name: String,
        workspace_uid: String,
        generation: String,
        revocation_epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidIdentity;

impl std::fmt::Display for InvalidIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid management certificate identity")
    }
}

impl std::error::Error for InvalidIdentity {}

fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

impl Identity {
    /// Decode only the exact canonical URI. Do not URL-normalize, percent-decode
    /// or accept alternate trust domains, ports, paths, queries or fragments.
    pub fn from_uri(uri: &str) -> Result<Self, InvalidIdentity> {
        // Four 256-byte components, the epoch and fixed framing fit this bound.
        if uri.len() > GUEST_PREFIX.len() + 4 * 257 + 20 {
            return Err(InvalidIdentity);
        }
        let identity = if let Some(replica_id) = uri.strip_prefix(API_PREFIX) {
            if !component(replica_id) {
                return Err(InvalidIdentity);
            }
            Self::Api {
                replica_id: replica_id.to_owned(),
            }
        } else if let Some(path) = uri.strip_prefix(GUEST_PREFIX) {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() != 5 || !parts[..4].iter().all(|part| component(part)) {
                return Err(InvalidIdentity);
            }
            let revocation_epoch = parts[4].parse::<u64>().map_err(|_| InvalidIdentity)?;
            if revocation_epoch.to_string() != parts[4] {
                return Err(InvalidIdentity);
            }
            Self::Guest {
                namespace: parts[0].to_owned(),
                workspace_name: parts[1].to_owned(),
                workspace_uid: parts[2].to_owned(),
                generation: parts[3].to_owned(),
                revocation_epoch,
            }
        } else {
            return Err(InvalidIdentity);
        };
        if identity.to_uri()? != uri {
            return Err(InvalidIdentity);
        }
        Ok(identity)
    }

    /// Encode a provisioned identity, rejecting invalid caller-constructed enums.
    /// Identity values must originate in authenticated provisioning/current state,
    /// never from an untrusted operation request or a CSR's requested SANs.
    pub fn to_uri(&self) -> Result<String, InvalidIdentity> {
        match self {
            Self::Api { replica_id } if component(replica_id) => {
                Ok(format!("{API_PREFIX}{replica_id}"))
            }
            Self::Guest {
                namespace,
                workspace_name,
                workspace_uid,
                generation,
                revocation_epoch,
            } if [namespace, workspace_name, workspace_uid, generation]
                .iter()
                .all(|part| component(part)) =>
            {
                Ok(format!(
                    "{GUEST_PREFIX}{namespace}/{workspace_name}/{workspace_uid}/{generation}/{revocation_epoch}"
                ))
            }
            _ => Err(InvalidIdentity),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Vectors {
        api: Vec<String>,
        guest: Vec<String>,
        invalid: Vec<String>,
    }

    #[test]
    fn shared_go_rust_identity_vectors() {
        let vectors: Vectors = serde_json::from_str(include_str!(
            "../fixtures/management-pki-identities-v1.json"
        ))
        .unwrap();
        for uri in vectors.api {
            let identity = Identity::from_uri(&uri).unwrap();
            assert!(matches!(identity, Identity::Api { .. }));
            assert_eq!(identity.to_uri().unwrap(), uri);
        }
        for uri in vectors.guest {
            let identity = Identity::from_uri(&uri).unwrap();
            assert!(matches!(identity, Identity::Guest { .. }));
            assert_eq!(identity.to_uri().unwrap(), uri);
        }
        for uri in vectors.invalid {
            assert_eq!(Identity::from_uri(&uri), Err(InvalidIdentity), "{uri}");
        }
    }

    #[test]
    fn exact_guest_binding_and_role_are_not_interchangeable() {
        let uri = format!("{GUEST_PREFIX}team/vm/uid-1/gen-2/3");
        let identity = Identity::from_uri(&uri).unwrap();
        assert_eq!(
            identity,
            Identity::Guest {
                namespace: "team".into(),
                workspace_name: "vm".into(),
                workspace_uid: "uid-1".into(),
                generation: "gen-2".into(),
                revocation_epoch: 3,
            }
        );
        for path in [
            "other/vm/uid-1/gen-2/3",
            "team/other/uid-1/gen-2/3",
            "team/vm/uid-2/gen-2/3",
            "team/vm/uid-1/gen-3/3",
            "team/vm/uid-1/gen-2/4",
        ] {
            assert_ne!(
                identity,
                Identity::from_uri(&format!("{GUEST_PREFIX}{path}")).unwrap()
            );
        }
        assert_ne!(
            identity,
            Identity::from_uri(&format!("{API_PREFIX}uid-1")).unwrap()
        );
    }

    #[test]
    fn component_bounds_and_constructed_values() {
        for n in [1, 256] {
            let component = "a".repeat(n);
            for uri in [format!("{API_PREFIX}{component}"), format!("{GUEST_PREFIX}{component}/{component}/{component}/{component}/18446744073709551615")] {
                assert_eq!(Identity::from_uri(&uri).unwrap().to_uri().unwrap(), uri);
            }
        }
        for component in [
            "a".repeat(257),
            String::new(),
            "../sensitive-path".into(),
            "é".into(),
        ] {
            assert_eq!(
                Identity::Api {
                    replica_id: component.clone()
                }
                .to_uri(),
                Err(InvalidIdentity)
            );
            assert_eq!(
                Identity::from_uri(&format!("{GUEST_PREFIX}team/vm/{component}/gen/0")),
                Err(InvalidIdentity)
            );
        }
        let err =
            Identity::from_uri(&format!("{API_PREFIX}private-identity-marker/path")).unwrap_err();
        assert!(!format!("{err:?} {err}").contains("private-identity-marker"));
    }
}
