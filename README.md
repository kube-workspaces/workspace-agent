# workspace-agent

Baked-in cross-platform guest agent for kube-workspaces VM workspaces
(Windows first, Linux after parity). Same-console-session streaming:
H.264 video, Opus playback audio and true guest resolution changes,
in native and integrated web viewers, with KubeVirt VNC retained as the
setup/recovery path.

Tracking and cross-repo plan: private `kube-workspaces/tracking`
(`windows-vm-workspaces-plan.md`, P0–P5). This repo owns binaries,
installers, the versioned wire protocol, OS adapters and driver
integration. No live-environment details belong here.

## Status

Native interactive premium tier in progress (session detection, guest
input injection, real guest resize, telemetry), tracked privately in
`kube-workspaces/tracking`. Versioned protocol spec
(`docs/protocol/kw-agent-v1.md`) and conformance fixtures with a
validator are in place; CI, release archives and the unsigned Windows
MSI pipeline are active. P0 proof gates (capture, audio endpoint,
signed display driver, transport choice) remain open in tracking. Do
not treat fixtures or CI green as guest acceptance.

## Layout

| Path | Purpose |
|---|---|
| `docs/protocol/kw-agent-v1.md` | Versioned wire-protocol spec (working name `kw-agent-v1`) |
| `protocol/v1/vectors/` | Conformance fixtures (JSON) |
| `kw-protocol/` | Protocol types + validation (Rust; parses every fixture) |
| `kw-core/` | Session/seat, bounded queues, resize debounce (pure logic) |
| `kw-agent/` | Service binary skeleton (platform stubs; backends P0-gated) |
| `tools/validate_fixtures.py` | Fixture validator (no dependencies) |
| `tools/test_validate_fixtures.py` | Validator unit tests |
| `Makefile` | `lint` / `test` / `package` targets used by CI |
| `scripts/verify-release-archives.py` | Release archive contract check |
| `packaging/windows/` | Unsigned MSI (WiX) build, verify and lifecycle test |

## Checks

```sh
make lint
make test
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
