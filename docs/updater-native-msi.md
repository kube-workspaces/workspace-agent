# Native Windows MSI adapter

`Transaction::windows_adapter` opens a `WindowsMsi` adapter for the transaction's
two pinned packages. The native adapter is a library component, not an enabled
updater command, SCM service, listener or QGA operation. Dispatch still requires
the journal's single-use committed action and a separately implemented current
`PhaseAuthority`.

## Staging and package identity

Provision a protected attempt root outside the agent installation tree, with
protected `target` and `previous` directories. Each contains its manifest's MSI
basename; the two basenames may be identical. Staging must use the
SYSTEM/Administrators-only creation-time ACL contract documented in
[checkpoint persistence](updater-persistence.md). Caller-selected installer URLs,
property strings, ProductCodes and source directories are not accepted.

Opening the adapter:

- Checks staging ACLs, owners, parent paths, reparse points and hardlink count.
- Holds directory handles denying rename and MSI handles denying writes/deletion
  for the adapter lifetime. Hashing and MSI consumption use the same pinned path.
- Streams at most the signed size plus one byte and verifies SHA-256/size.
- Uses the Windows Installer database API in read-only mode to verify exact
  ProductCode, stable UpgradeCode, ProductVersion and `ALLUSERS=1`.
- Requires x64, compressed payloads, embedded cabinets, and no per-file
  uncompressed-source override. External CAB/source files cannot bypass the
  publisher's artifact hash.

Publisher-verified manifests remain a separate requirement: inspecting an MSI
never creates artifact trust or grants permission to install it.

## Inventory and fixed effects

Inventory uses `MsiEnumRelatedProductsW` and machine-context
`MsiGetProductInfoExW`, never `Win32_Product` or an ARP registry guess. Advertised,
unknown or malformed registrations deny. Product families and property strings
are bounded; Windows Installer busy state and Windows servicing/update/pending
file-rename reboot markers are observed separately.

Installation uses `MsiInstallProductW` with fixed machine scope, silent UI and
`REBOOT=ReallySuppress`, plus the validated recorded installation directory.
Removal uses `MsiConfigureProductExW(INSTALLSTATE_ABSENT)` for only the pinned
target, after a fresh exact registration check. No downgrade-guard override,
arbitrary executable/flags, identity-data deletion or MSI process termination is
implemented. The dispatcher admits compensation as target removal followed by
predecessor installation; native downgrade rejection is retained.

The adapter must live in a **dedicated updater process**. MSI UI state is
process-global: the adapter holds an exclusive in-process owner guard and owns
the external UI callback for each synchronous MSI call. Do not embed it beside
uncoordinated MSI API/UI consumers. It is separate from the agent's service and
desktop worker; SCM packaging and service lifetime are still integration work.

## Evidence and outages

The caller supplies a protected, acknowledged `Evidence` sink. Native callbacks
are serialized, bounded to 4096 UTF-16 code units per message and an adapter-wide
32 MiB budget (the enclosing attempt must enforce its shared recording budget).
The callback contains installer content and must not enter normal metadata logs.

Evidence is acknowledged before MSI starts. Any subsequent overflow, sink error
or callback panic marks recording loss, allows the active MSI transaction to
reach its safe boundary, and poisons further calls through that adapter. No
callback returns cancel/abort to force termination. MSI result/recording loss is
returned for journal reconciliation rather than fabricated success or automatic
retry. Final agent health, unchanged identity and completed rollback are verified
by later journal phases, not inferred from exit code 0.

## Windows CI proof

`packaging/windows/test-updater-msi.ps1` builds an isolated random UpgradeCode,
service, installation directory and ProgramData namespace. A Rust unit-test-only
fixture path exercises the actual native adapter against two real MSIs:
pinning; hash/metadata/external-source denial; per-machine inventory; first
installation; major upgrade; downgrade rejection; exact-target removal;
predecessor installation; refusal to remove the predecessor; recording-outage
denial; and preservation of a synthetic ProgramData identity sentinel.

The test-only product-family override is private to the Rust test module; the
production constructor always uses the stable workspace-agent UpgradeCode.
The PowerShell wrapper cleans only its unique test products even on failure.
This disposable CI proof does not close SYSTEM service independence, real guest
identity/handshake/driver health, reboot recovery or live upgrade acceptance.
