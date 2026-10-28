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
durable intent acknowledgment immediately before dispatch. The exchange must
obtain peer identity from mTLS, mint an independent challenge before requesting
a signature and **durably consume** that challenge even on denial. Single-use ownership inside one Rust
object is not replay protection across process restarts or multiple objects.

## Durable guest challenge adapter

`phase::challenges::FileChallenges` and `DurableCurrentAuthority<S>` supply the
replay-storage portion of this boundary. `S: LiveAuthority` is still required;
no production implementation or listener is supplied. Its `check` must recheck
all current authorization/intent conditions above and return the actual
authenticated peer certificate digest and trusted time, never request fields.

1. Explicitly provision a dedicated protected challenge root beneath trusted
   parents, separate from the journal root and MSI replacement directory.
   Use `persistence::create_root` and initialize **once**, not as fallback for
   failed reopen. Retain the root across helper/agent upgrades and restarts.
2. `DurableCurrentAuthority::challenge` rechecks live authority and durably stores
   one independently random 256-bit nonce bound to the exact plan, action,
   sequence, boot, owner fence and authenticated peer. A pending challenge cannot
   be overwritten. Request a phase permit through authenticated transport only
   after this succeeds; the returned `Challenge` is not a signed permit.
3. Give the adapter to `SignedPhaseAuthority`. Its current-authority check
   durably spends the pending challenge **before** checking live authority,
   bindings or the signature. Denial, outage, invalid bytes, wrong peer/fence/boot,
   clock rollback and expiry cannot restore the challenge. The challenge's own
   15-second window is checked independently of signed permit timestamps.
4. A subsequent attempt requires a newly minted nonce. `invalidate` explicitly
   spends an abandoned challenge without admitting an effect. No nonce history
   grows with runtime: only the single pending challenge or spent state is kept.

The root uses the journal's private-file/ACL and machine-exclusive OS lock
primitives. State is bounded to 8 KiB and must be canonical, versioned JSON;
missing/corrupt/linked/unprotected state denies. A flushed temporary file is
atomically replaced before returning authority (write-through on Windows,
directory sync on Unix). An uncertain write poisons the handle. An orphan
temporary file denies reopen and requires independent recovery; it is not
automatically discarded or interpreted as authority. The lock is released on
process death, but the consumed state persists.

This protects against response replay across cooperating helpers and ordinary
process restarts, **not** a privileged administrator editing/deleting storage,
restoring a disk snapshot/backup or cloning a root. Such lifecycle recovery must
invalidate old enrollment/epoch and reconcile with off-guest authority; do not
use this local store as proof of current enrollment or rollback-resistant state.
It cannot construct a committed journal action or bypass off-guest recording.

Production transport, issuer policy/storage integration, enrolled-guest health
and reboot recovery remain unavailable until those adapters are supplied and
tested. No QGA fallback, automatic upgrade, driver qualification or live guest
acceptance is implied.

Go and Rust tests assert the same deterministic signature using synthetic test
seed `[0x5a; 32]`; never deploy this seed as trust. Tests cover canonical byte
agreement, exact-field substitutions, time boundaries, trust/domain failures,
malformed payloads and adapter reuse after success/denial/authority outage.
Durable adapter tests additionally cover reopen/new-adapter replay, new-challenge
substitution, exact bindings, local expiry, sticky spent state, uncertain writes,
bounded/canonical disk state, exclusive ownership and a hard-killed child process
after consumption. Windows runtime execution must be checked in Windows CI; a
Linux cross-check does not establish Windows or installed-guest acceptance.
