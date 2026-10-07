# AGENTS.md

## Repository: kube-workspaces/workspace-agent

Baked-in cross-platform guest agent for kube-workspaces VM workspaces.
Windows amd64 first; Linux amd64/arm64 after parity. Tracking and
decisions live in private `kube-workspaces/tracking`; this repo holds
generic, public-safe code and docs only.

## Commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
python3 tools/validate_fixtures.py          # validate protocol fixtures
python3 -m unittest discover -s tools -p 'test_*.py'  # unit tests
```

Rust guest-service CI (fmt/clippy/tests, Windows + Linux jobs) is active
(`.github/workflows/rust.yml`). Capture/input/display/audio backends remain
P0-gated: `kw-agent` performs no privileged operations yet.

## Conventions

- Work directly on `main`; batch related changes into single coherent
  commits; run the checks above before pushing.
- No tags/releases from this repo during P1 scaffolding.
- Wire protocol is versioned separately from installer/image/profile
  versions. Never reuse the literal `selkies` advert for this protocol.
- Never commit secrets, private identities, enrollment tokens, hostnames,
  credentials, or live-environment evidence. Generic examples only.
- No generic remote command execution in the agent protocol. Named,
  versioned actions only.
- Fixture changes must keep `tools/validate_fixtures.py` and its tests
  green. Headless fixtures do not close driver/A/V acceptance.
