# AGENTS.md

## Repository: kube-workspaces/workspace-agent

Baked-in cross-platform guest agent for kube-workspaces VM workspaces.
Windows amd64 first; Linux amd64/arm64 after parity. Tracking and
decisions live in private `kube-workspaces/tracking`; this repo holds
generic, public-safe code and docs only.

## Commands

```sh
make lint          # fmt check + clippy -D warnings
make test          # cargo test --workspace --locked + fixture validators
make package       # dist archives from bin/<target>/ + SHA256SUMS + contract check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
python3 tools/validate_fixtures.py          # validate protocol fixtures
python3 -m unittest discover -s tools -p 'test_*.py'  # unit tests
```

CI is three workflows: `.github/workflows/lint.yml` (fmt/clippy),
`ci.yml` (build + tests + `--version`/`--hello` smoke on Linux and
Windows, fixture job) and `build.yml` (per-target release archives,
unsigned Windows MSI, checksums, and publishing on `v*` tags). Archive
layout is a contract enforced by `scripts/verify-release-archives.py`;
the MSI layout by `packaging/windows/verify-msi.ps1` (read-only MSI
table checks, run by both `build-msi.ps1` and CI).

## Conventions

- Work directly on `main`; batch related changes into single coherent
  commits; run the checks above before pushing.
- Releases: tag `v*` after the tracked feature milestone lands (first
  tag: `v0.1.0`); the build workflow publishes three archives
  (`linux-amd64`, `linux-arm64`, `windows-amd64`) plus the unsigned
  native-service MSI and `SHA256SUMS`. MSI `UpgradeCode`
  `f72bb43e-dba8-4dbb-a963-b201e6c0d885` is stable forever. No chart
  bumps or ArgoCD targetRevision changes from tags here — that stays
  separately coordinated (see tracking).
- Release tags MUST be exact semver `vMAJOR.MINOR.PATCH`. The `msi` job
  hard-fails any other tag ("MSI release version must be an exact tag"),
  so a non-semver tag (e.g. `v0.3.3-hotfix-…`) builds no MSI and no
  release. **Never cut ad-hoc "hotfix" tags or releases** — for a fix,
  bump the patch version (`v0.3.4`, …) and tag that. Do not delete or
  deform existing semver releases to work around this.
- `.github/release.yml` must stay byte-identical with the other
  kube-workspaces repos (`deploy/scripts/check-release-config.sh`).
- Wire protocol is versioned separately from installer/image/profile
  versions. Never reuse the literal `selkies` advert for this protocol.
- Never commit secrets, private identities, enrollment tokens, hostnames,
  credentials, or live-environment evidence. Generic examples only.
- No generic remote command execution in the agent protocol. Named,
  versioned actions only. A separate, mutually authenticated **management
  endpoint** may implement a versioned `management.*` naming scheme for
  explicitly enumerated operations (command/script run, PTY/ConPTY shell,
  input/resize, cancel, status) only when all of the following hold:
  - the connection is mutually authenticated TLS bound to the workspace
    identity, and the listener is not reachable unauthenticated;
  - every request carries a short-lived, asymmetrically signed grant bound to
    actor, workspace UID/generation, operation, target OS identity, audience
    and expiry, which the guest verifies independently — grants supplied by
    the API are never trusted without guest-side verification;
  - all I/O is recorded independently of the desktop worker; and
  - no unauthenticated diagnostic/fallback path exists, and root/SYSTEM
    targets additionally require a separately authorized elevated grant.

  This supersedes the blanket prohibition for that endpoint only; there is
  still no capability-discovery or arbitrary-argv execute endpoint.
- **QGA pod-exec pilot transport (`qga-pod-exec/v1`), operator-approved:**
  the `command` operation may instead arrive as a single staged envelope file
  consumed by the fixed `kw-agent management-exec` command, which the API
  invokes through a Kubernetes-authenticated QGA guest-exec of that exact
  installed command (no listener, no other guest command is reachable). The
  runner re-verifies everything guest-side: pinned public keys, the enrolled
  workspace UID, request bounds and persistent single-use grant IDs, and it
  additionally requires Windows + LocalSystem or Linux + root with cgroup v2
  supervision, an executable with explicit
  argv (no shell/PTY/interactive stdin), a guest deadline of at most 20 s,
  and a 16 KiB combined stdout/stderr cap with truncation reporting. Never
  fall back to this transport from a failed dedicated mutually authenticated
  connection; the dedicated management listener remains the follow-up.
- Fixture changes must keep `tools/validate_fixtures.py` and its tests
  green. Headless fixtures do not close driver/A/V acceptance.
