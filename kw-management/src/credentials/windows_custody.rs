//! Read-only Windows custody preflight, NOT a machine-key storage backend.
//! Lexical paths alone convey no trust. The native probe pins existing directory
//! handles and checks the leaf descriptor; it neither establishes a complete
//! trusted-ancestor policy nor reads/creates keys, certificates or desktop files.
//! MachineKey storage on Windows remains unconditionally unavailable.

use super::KeyUnavailable;

#[cfg(windows)]
mod native;

/// Conservative local DOS path subset, without UNC/device/extended namespaces,
/// ADS, short-name syntax, dot components, trailing aliases or reserved devices.
/// This is lexical validation only: native handle checks are still mandatory.
#[derive(Clone)]
pub struct MachinePath(String);
impl std::fmt::Debug for MachinePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Windows machine path (redacted)")
    }
}
impl MachinePath {
    pub fn parse(path: &str) -> Result<Self, KeyUnavailable> {
        let bytes = path.as_bytes();
        if !(4..=240).contains(&bytes.len())
            || !bytes[0].is_ascii_uppercase()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return Err(KeyUnavailable);
        }
        for component in path[3..].split('\\') {
            if component.is_empty()
                || component.len() > 128
                || !(component.as_bytes()[0].is_ascii_alphanumeric()
                    || b"_-".contains(&component.as_bytes()[0]))
                || !component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" _.-".contains(&b))
                || component.ends_with(['.', ' '])
            {
                return Err(KeyUnavailable);
            }
            let base = component
                .split('.')
                .next()
                .ok_or(KeyUnavailable)?
                .trim_end_matches(' ')
                .to_ascii_uppercase();
            if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || ["COM", "LPT"].iter().any(|prefix| {
                    base.strip_prefix(prefix)
                        .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
                })
            {
                return Err(KeyUnavailable);
            }
        }
        Ok(Self(path.to_owned()))
    }
    /// Case-insensitive conservative overlap check. Does NOT resolve filesystem
    /// aliases; pinned native handles remain necessary before any storage use.
    pub fn overlaps(&self, other: &Self) -> bool {
        let a = self.0.to_ascii_lowercase();
        let b = other.0.to_ascii_lowercase();
        a == b || a.starts_with(&format!("{b}\\")) || b.starts_with(&format!("{a}\\"))
    }
}

/// Opaque pinned read-only probe. No raw handle, file I/O or authority accessor.
/// A successful probe is not a credential or complete Windows custody proof.
pub struct DirectoryProbe {
    #[cfg(windows)]
    inner: native::Directory,
    poisoned: bool,
}
impl std::fmt::Debug for DirectoryProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Windows directory probe (path and handles redacted)")
    }
}
impl DirectoryProbe {
    /// Inspect an EXISTING directory without creating/repairing ACLs or files.
    /// Non-Windows platforms explicitly deny instead of emulating protection.
    pub fn open(path: &MachinePath) -> Result<Self, KeyUnavailable> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: native::Directory::open(path)?,
                poisoned: false,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(KeyUnavailable)
        }
    }
    /// Any detected handle/path/descriptor change permanently poisons this probe.
    /// Reopening is explicit; successful recheck still grants no storage/exec use.
    pub fn recheck(&mut self) -> Result<(), KeyUnavailable> {
        if self.poisoned {
            return Err(KeyUnavailable);
        }
        #[cfg(windows)]
        let result = self.inner.check();
        #[cfg(not(windows))]
        let result = Err(KeyUnavailable);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

#[cfg(any(windows, test))]
fn restricted_directory_sddl(text: &str) -> bool {
    // Exact handle-derived descriptor only. No inherited, NULL, extra/unknown
    // ACEs or unprivileged owners. Reject even broader read grants conservatively.
    ["BA", "SY"].iter().any(|owner| {
        ["P", "PAI"]
            .iter()
            .any(|flags| text == format!("O:{owner}D:{flags}(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lexical_aliases_namespaces_and_device_names_deny() {
        for path in [
            r"C:\Program Files\Kube Workspaces\management",
            r"D:\private\keys",
            r"C:\one\item-v1.2",
            r"C:\_temp\_private\management",
        ] {
            let parsed = MachinePath::parse(path).unwrap();
            assert_eq!(format!("{parsed:?}"), "Windows machine path (redacted)");
        }
        for path in [
            "",
            r"C:\",
            r"c:\private\key",
            r"C:private\key",
            r"\private\key",
            r"\\host\share\key",
            r"\\?\C:\private\key",
            r"\\.\C:\private\key",
            r"C:/private/key",
            r"C:\\private\key",
            "C:\\private\\key\\",
            r"C:\private\.\key",
            r"C:\private\..\key",
            r"C:\private\key.",
            "C:\\private\\key ",
            r"C:\private\key:stream",
            r"C:\PROGRA~1\key",
            r"C:\private\CON",
            r"C:\private\con.txt",
            r"C:\private\CON .txt",
            r"C:\private\NUL.log",
            r"C:\private\AUX",
            r"C:\private\PRN",
            r"C:\private\COM0",
            r"C:\private\com9.dat",
            r"C:\private\LPT1",
            r"C:\private\LPT9.txt",
            "C:\\private\\hidden\u{7f}",
            "C:\\private\\nul\0",
            "C:\\private\\café",
        ] {
            assert!(
                MachinePath::parse(path).is_err(),
                "accepted an unsupported lexical path"
            );
        }
        assert!(MachinePath::parse(&format!("C:\\{}", "a".repeat(129))).is_err());
        assert!(
            MachinePath::parse(&format!("C:\\{}\\{}", "a".repeat(120), "b".repeat(120))).is_err()
        );
    }
    #[test]
    fn overlap_is_case_insensitive_and_component_bounded() {
        let key = MachinePath::parse(r"C:\Private\Keys").unwrap();
        for other in [r"C:\private\KEYS", r"C:\private", r"C:\private\keys\certs"] {
            let other = MachinePath::parse(other).unwrap();
            assert!(key.overlaps(&other));
            assert!(other.overlaps(&key));
        }
        for other in [
            r"C:\private\KeysOther",
            r"C:\private\certs",
            r"D:\Private\Keys",
        ] {
            assert!(!key.overlaps(&MachinePath::parse(other).unwrap()));
        }
    }
    #[test]
    fn descriptor_policy_accepts_only_exact_protected_machine_principals() {
        for owner in ["BA", "SY"] {
            for flags in ["P", "PAI"] {
                assert!(restricted_directory_sddl(&format!(
                    "O:{owner}D:{flags}(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                )));
            }
        }
        for text in [
            "",
            "O:BAD:NO_ACCESS_CONTROL",
            "O:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)",
        ] {
            assert!(!restricted_directory_sddl(text));
        }
    }
    #[cfg(not(windows))]
    #[test]
    fn non_windows_probe_never_emulates_native_custody() {
        assert!(
            DirectoryProbe::open(&MachinePath::parse(r"C:\private\management").unwrap()).is_err()
        );
    }
}
