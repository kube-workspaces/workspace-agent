# Signed updater phase authority

`kw_management::updates::phase` and the API's `updates.PhasePermit` implement
the same offline contract. No management listener, issuer route, trust bootstrap
or production `CurrentAuthority` implementation is enabled here.

## Wire and binding

Ed25519 signs `kw-agent-upgrade-phase/v1` + NUL + exact canonical JSON bytes.
Trust comes from an independently provisioned management grant keyring (1–16
keys); key IDs are the first 16 SHA-256 bytes of the public key as lowercase hex.
Never accept trust from the response, publisher manifest or desktop ticket.

Payloads are at most 4 KiB, schema version 1, audience `agent-upgrade.phase.v1`.
Every field is required; unknown/duplicate/missing fields, alternate encodings
and trailing data deny. The shared `phase-v1.json` fixture demonstrates:

- Domain-separated plan SHA-256, covering actor, workspace/VM/epoch,
  attempt/recording, both manifests, initial inventory and reboot consent.
- Exact action kind, journal sequence, boot ID and owner fence.
- Guest-minted 256-bit challenge (canonical unpadded base64url) and the
  authenticated management peer certificate SHA-256.
- Positive issuance time and an expiry at most 15 seconds later. No future skew;
  the expiry boundary itself denies. Unknown clock/authority must deny.

Expected values must come from independent current authority, never from the
returned permit. Signing a structurally valid payload does not authorize it.

## Dispatch boundary and remaining integration

`SignedPhaseAuthority` implements the typed MSI dispatcher's `PhaseAuthority`.
It consumes its response before any validation, including on error. It cannot
create a `CommittedAction`, replay recovered actions or bypass persistence and
off-guest recording acknowledgment. Every new effect still needs a new permit.

The required `CurrentAuthority::check` adapter must recheck current enrolled
identity/epoch, boot, policy, cancellation/deadline, owner lease/fence and exact
durable intent acknowledgment immediately before dispatch. It must obtain the
peer identity from mTLS, mint an independent challenge and **durably consume**
that outstanding challenge even on denial. Single-use ownership inside one Rust
object is not replay protection across process restarts or multiple objects.

Production transport, issuer policy/storage integration, enrolled-guest health
and reboot recovery remain unavailable until those adapters are supplied and
tested. No QGA fallback, automatic upgrade, driver qualification or live guest
acceptance is implied.

Go and Rust tests assert the same deterministic signature using synthetic test
seed `[0x5a; 32]`; never deploy this seed as trust. Tests cover canonical byte
agreement, exact-field substitutions, time boundaries, trust/domain failures,
malformed payloads and adapter reuse after success/denial/authority outage.
