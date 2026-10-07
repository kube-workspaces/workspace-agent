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

P1 scaffolding: versioned protocol spec (`docs/protocol/kw-agent-v1.md`)
and conformance fixtures with a validator. No guest implementation yet;
P0 proof gates (capture, audio endpoint, signed display driver, transport
choice) remain open in tracking. Do not treat fixtures or CI green as
guest acceptance.

## Layout

| Path | Purpose |
|---|---|
| `docs/protocol/kw-agent-v1.md` | Versioned wire-protocol spec (working name `kw-agent-v1`) |
| `protocol/v1/vectors/` | Conformance fixtures (JSON) |
| `tools/validate_fixtures.py` | Fixture validator (no dependencies) |
| `tools/test_validate_fixtures.py` | Validator unit tests |

## Checks

```sh
python3 tools/validate_fixtures.py
python3 -m unittest discover -s tools -p 'test_*.py'
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
