# `kw-agent-v1` wire protocol (working name, version 1)

Status: **draft for P1 scaffolding.** Frozen only by the P0 decision record
(language/media/dependency set, driver package, transport). Implementations
must negotiate and reject what they do not support; silent fallback around
ownership, codecs or resolutions is forbidden.

## Design constraints (from the owning plan)

1. Same-console-session streaming. KubeVirt VNC stays the pre-boot,
   installer, recovery and agent-failure path.
2. Initial transport: binary media over WSS plus a separately bounded
   control channel. Complete timestamped H.264 access units (Annex-B for
   native; AVC for browser), SPS/PPS/IDR on connect/reconfigure, Opus
   header/channel metadata, sequence/generation IDs, monotonic presentation
   timestamps, frame/queue feedback, keyframe requests, capability updates
   and resize ACKs.
3. The first premium milestone may be exclusive-controller only, matching
   existing native Selkies scope. Observers, if any, are view-only and
   controller-owned resolution applies.
4. Platform login tokens never become guest passwords and are never
   forwarded to the guest. No generic remote command execution: named,
   versioned actions only.

## Message envelope

Every frame (media or control) carries:

| Field | Type | Rule |
|---|---|---|
| `protocol` | string | Must be `"kw-agent-v1"` |
| `protocolVersion` | integer | Currently `1`; unknown versions are rejected |
| `sessionId` | string | Opaque session UUID, bound at enrolment |
| `generation` | integer | Monotonic per session; resets only on re-enrolment |
| `sequence` | integer | Monotonic per channel; gaps are reported, never hidden |
| `sentAtNs` | integer | Monotonic sender clock, nanoseconds |
| `channel` | string | `"media"` or `"control"` |

Receivers drop and count (never stall on): unknown protocol versions,
replayed `(generation, sequence)`, expired/demoted control epochs, and
slow-reader overflow beyond the bounded queue. Dropping an encoded
reference frame arbitrarily is forbidden; abandon a GOP only by flushing
to a fresh IDR.

## Control messages

`type` is one of: `hello`, `capabilities`, `attach`, `keyframeRequest`,
`resizeRequest`, `resizeAck`, `clipboardGet`, `clipboardSet`,
`clipboardResult`, `displayOwnership`, `telemetry`, `bye`.

- `hello`: agent identity/version, image/profile compatibility, actual
  codec/profile/level, capture/output dimensions, audio endpoint state,
  cursor metadata, display-mode list, role/capabilities.
- `capabilities`: updated subset of `hello` fields; `capabilityEpoch`
  increases on every change.
- `attach`: viewer presents a short-lived ticket (see below). Agent and
  proxy verify workspace UID, generation, session/participant, role,
  control epoch, audience and expiry before admitting input.
- `resizeRequest`: monotonically identified desired mode
  (`requestId`, width, height, DPR policy). Only the newest applies.
- `resizeAck`: echoes `requestId`, reports requested vs actual dimensions
  or a machine-readable reason; sent within the bounded timeout. New codec
  config + IDR follows an actual mode change.
- `displayOwnership`: control-epoch grant/renew/release; input is released
  on disconnect, focus loss or epoch change.
- Clipboard text is an additive capability: `hello.payload.clipboardText`
  must be true before a viewer requests it. The console-session guest opts
  in with `serve --clipboard`; media is optional, so a clipboard-only
  attachment can run beside the independent VNC console.
- `clipboardGet`: admitted controller requests `{requestId}` (nonempty,
  at most 128 UTF-8 bytes). `clipboardSet`: `{requestId, text}`; text is
  Unicode, at most 65536 UTF-8 bytes, without embedded NUL. No files/images
  and no automatic keypress or command execution.
- `clipboardResult`: `{requestId, ok, text? , reason?}`. A successful get
  returns text (including an empty string) or null if no text format is
  available. A successful set returns null text. Errors report bounded
  machine-readable reasons. Clipboard contents never enter telemetry/logs.
  Reads and writes require admission and the ordinary control fence; results
  are paired by request ID. Viewers discard late results and suppress echoes.
- `telemetry`: timings/counters/capability reasons only. Never clipboard,
  input content or credentials.
- `bye`: orderly teardown with reason; receivers release held input and
  cancel the premium generation before any console fallback.

## Media frames

- Video: one complete H.264 access unit per frame envelope, with
  `codecConfig` flag on SPS/PPS/IDR, `keyframe` marker, and capture/output
  dimensions. No B-frame reorder in the baseline profile.
- Audio: Opus frames, 48kHz stereo, 20ms, with header/channel metadata and
  A/V clock linkage. Local mute affects client playback, never guest volume.

## Enrolment and tickets (summary)

Image contains binaries and platform public trust only. At first boot the
clone generates its own key from a one-use, time-bounded,
UID+generation-bound enrolment token, then stores credentials with
machine-protected storage (Windows ACL/DPAPI, Linux root-owned file).
Reset/deletion revokes identity; ordinary restart preserves it. Attach
tickets bind workspace UID, generation, session/participant, role,
control epoch, audience and expiry.

## Conformance vectors

`protocol/v1/vectors/*.json` exercise envelope ordering, capability epochs,
resize request/ACK pairing, keyframe discipline and ticket-expiry
rejection. They validate shape and state-machine rules, not guest A/V
quality, drivers or transport performance.
