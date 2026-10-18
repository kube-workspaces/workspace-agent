# Management-v1 verification foundation

`kw-management` independently verifies Ed25519 management grants issued by the
API. It has no network listener, process runner or dependency on the desktop
protocol. It holds only public verification keys. The existing agent binary does
not enable management execution by adding this library to the workspace.

The compact JWS header requires `alg=EdDSA`, `typ=kw-management-grant+jwt`, and a
pinned `kid` equal to the first 16 bytes of SHA-256 of the public key (lowercase
hex). Claims require management-v1 version/issuer/audience, a random 256-bit JTI,
and integer Unix issuance/expiry with a maximum 60-second lifetime. Unknown
fields, malformed signatures, future issuance and expired grants deny.

Before consuming a grant, supply independently known `Binding` values: immutable
actor UID; workspace scope/UID and provisioning generation; execution and
recording IDs; operation; OS identity and elevation; current policy version and
revocation epoch; this authenticated connection's fresh guest challenge; the
validated API peer certificate DER SHA-256; and exact framed request SHA-256.
Never derive expected bindings from the grant itself. OS token/account enforcement
is still required; string checks alone cannot prove an identity is unelevated.

Keep one non-cloneable verifier for the whole connection, behind a shared mutex
if multiple tasks use it. Consumption uses exclusive mutable access, denies
replay and cache exhaustion, and rejects wall-clock rollback. Do not recreate an
empty replay cache for an old challenge; generate a new challenge on every
connection/restart. Rotation explicitly overlaps independently provisioned public
keys and removes retired keys. Single-use start grants do not replace live
revocation, distributed idempotency or session renewal.

Clone-safe enrollment, mTLS peer validation, current epoch synchronization,
request framing, recording admission/spool and platform runners remain
prerequisites before this verifier can authorize a reachable management endpoint.

The synthetic fixture in `fixtures/management-v1.json` is byte-identical to the
API test vector and signed with a deliberately public test seed. Both languages
verify it; it must never be provisioned as a trusted installation key.

```sh
cargo test -p kw-management --locked
cargo clippy -p kw-management --all-targets --locked -- -D warnings
```
