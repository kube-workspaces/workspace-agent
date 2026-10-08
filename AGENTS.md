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
  files-only MSI and `SHA256SUMS`. MSI `UpgradeCode`
  `f72bb43e-dba8-4dbb-a963-b201e6c0d885` is stable forever. No chart
  bumps or ArgoCD targetRevision changes from tags here — that stays
  separately coordinated (see tracking).
- `.github/release.yml` must stay byte-identical with the other
  kube-workspaces repos (`deploy/scripts/check-release-config.sh`).
- Wire protocol is versioned separately from installer/image/profile
  versions. Never reuse the literal `selkies` advert for this protocol.
- Never commit secrets, private identities, enrollment tokens, hostnames,
  credentials, or live-environment evidence. Generic examples only.
- No generic remote command execution in the agent protocol. Named,
  versioned actions only.
- Fixture changes must keep `tools/validate_fixtures.py` and its tests
  green. Headless fixtures do not close driver/A/V acceptance.
