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

`type` is one of: `hello`, `capabilities`, `attach`, `attachResult`, `input`,
`keyframeRequest`, `resizeRequest`, `resizeAck`, `clipboardGet`,
`clipboardSet`, `clipboardResult`, `displayOwnership`, `telemetry`, `bye`.

- `hello`: agent identity/version, image/profile compatibility, actual
  codec/profile/level, capture/output dimensions, audio endpoint state,
  cursor metadata, display-mode list, role/capabilities. Capability booleans
  `inputAvailable` and `resizeAvailable` state whether admitted input is
  injected and whether a `resizeRequest` can actually change the guest mode;
  a viewer must not send input or expect a real resize before the matching
  flag is true.
  Optional `capture: {width, height}` gives the true selected desktop size,
  excluding macroblock padding in the raw H.264 stream. A native viewer crops
  matching padded frames to that size and updates it only from a successful
  paired resize result; stale old-mode dimensions must not crop a new-mode IDR.
- `capabilities`: updated subset of `hello` fields; `capabilityEpoch`
  increases on every change.
- `attach`: viewer presents a short-lived ticket (see below). Agent and
  proxy verify workspace UID, generation, session/participant, role,
  control epoch, audience and expiry before admitting input.
- `attachResult`: `{admitted, reason?}`, sent in reply to `attach` in the
  same session claim; a rejected attach carries a bounded machine-readable
  reason and admits no input.
- `input`: viewer→guest input, sent only by the admitted controller and only
  when `hello.inputAvailable` is true. Carries a `kind` tag:
  `{"kind":"key","keysym":N,"down":bool}` (X11 keysym, named/legacy values
  up to `0x0010FFFF` or `0x01000000 | scalar` for Unicode, excluding NUL/surrogates),
  `{"kind":"pointer","x":N,"y":N,"buttons":N}` (logical guest desktop
  coordinates, RFB-style button bitmask `0..255`), or
  `{"kind":"wheel","dx":N,"dy":N}` (steps, positive right/down, `|d| ≤ 1000`).
  Fire-and-forget: there is no per-event ack, the guest counts drops and
  reports them in `telemetry`, and held input is released on disconnect,
  focus loss or epoch change. No generic command execution.
- `resizeRequest`: monotonically identified desired mode
  (`requestId`, width, height, DPR policy). Only the newest applies.
- `resizeAck`: echoes `requestId`, reports requested vs actual dimensions
  or a machine-readable reason; sent within the bounded timeout. New codec
  config + IDR follows an actual mode change.
  Windows opts in with `serve --capture-video --resize` in the interactive
  console session. The selected capture output is changed temporarily (no
  registry persistence); unsupported dimensions are NACKed. Success requires
  capture/encoder reconstruction and a fresh IDR written to the socket before
  the ACK. Requests are bounded to 320–8192 by 200–8192 pixels and a ten-second
  response window. A failure after a mode change can leave that mode applied;
  `codecReconfigured`/`idrSent` stay false unless the full pipeline completes.
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
  With `hello.telemetryAvailable`, an admitted controller may request a
  snapshot by sending an empty telemetry payload. Reply fields include
  `inputEvents`, `inputDropped`, `resizeAcks` and optional process/active-console
  session IDs and `canInject`. Native clients request this at most once a
  second; content and keysyms are never included.
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
