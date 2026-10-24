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

## Windows desktop startup and identity

Windows uses a native automatic **Kube Workspaces Agent** service
(`KubeWorkspacesAgent` in SCM). It runs as LocalSystem in Session 0, owns
enrollment/heartbeat and supervises one user-token worker in the logged-in
**console** session. Desktop capture, audio, clipboard, input and display
changes run in that worker, never in Session 0. There is no console window,
tray requirement, PowerShell supervisor or user startup registration on the
native path. RDP/multiuser and secure-desktop control are not implied.

The MSI installs/starts the service and owns stop/remove on upgrade/uninstall.
An unconfigured installation reports `awaiting-enrollment` and starts no worker.
Run the per-guest provisioning step from elevated PowerShell:

```powershell
cd 'C:\Program Files\workspace-agent'
.\install.ps1 -WorkspaceUid <uid> -WorkspaceGeneration <generation>
Get-Service KubeWorkspacesAgent
```

The same script supports archive installations. It copies all management helpers
and enforces administrator-owned executables with read/execute-only access for
regular users, including custom installation paths. Workspace UIDs must use
canonical UUID syntax; generation is opaque and non-empty. Reinstallation
refuses enrollment mismatches before changing configuration. The private key
survives ordinary service restarts and MSI upgrades/uninstalls.

Only `workspaceUid` and `workspaceGeneration` are published to
`%PROGRAMDATA%\workspace-agent\public\binding.json`, read-only to local users.
The private `identity.json`, enrollment tokens and machine configuration remain
restricted to SYSTEM and Administrators. Startup never stores a second identity.

The service starts the fixed executable using the console user's token and
environment with `CREATE_NO_WINDOW`, using the linked limited token when Windows
provides a UAC split token. The worker never runs as a built-in service account.
A job object, assigned atomically at process creation, bounds worker lifetime.
A SYSTEM-owned, ACL-restricted local stop event allows graceful socket/media/input
teardown before bounded forced cleanup. Worker crashes restart with exponential
backoff (up to 60 seconds). MSI/archive installation configures SCM crash/error
recovery with 5/15/60-second service restart delays using a fixed native installer
operation, outside service startup.
Startup discovers an already logged-in console, and session notifications plus
reconciliation handle session replacement and logoff.
Locked/disconnected consoles are ineligible; unlocking the selected console
starts a fresh worker. Secure-desktop capture is not attempted.

### Boot and logon timeline

**At boot (machine, before any user logs on):**

- SCM starts `KubeWorkspacesAgent` (`Start=auto`, LocalSystem, Session 0). This
  is the only agent-related startup entry; it is a real service, not a scheduled
  task or Run key.
- The service loads `service.json` and the enrolled identity, then owns
  enrollment, heartbeat and the control socket. An unconfigured installation
  reports `awaiting-enrollment` and stays idle.
- No desktop worker starts yet: there is no console session to attach to. The
  service registers session notifications and reconciliation so it can react the
  moment an eligible console appears.

**At user logon (interactive session init):**

- The service discovers the new console session, obtains that user's token
  (the linked limited token when a UAC split token exists), and launches the
  fixed `kw-agent.exe serve` in that session with `CREATE_NO_WINDOW`, assigned
  atomically to a job object.
- The worker runs on `winsta0\default` and owns capture, audio, clipboard, input
  and display changes. It runs as the ordinary interactive user, never as a
  built-in service account and never in Session 0.
- **Nothing user-level is installed or executed at logon:** no `Run` value, no
  scheduled task, no PowerShell launcher, no tray icon and no console window.
  Because every step is a hidden Session 0 service or a `CREATE_NO_WINDOW`
  worker, nothing starts or flashes on the desktop.
- Lock/logoff/disconnect stops the worker; a locked or disconnected console is
  ineligible until it is unlocked, at which point the service starts a fresh
  worker.

Legacy scheduled-task installs (pre-native-service) instead registered a per-logon
task and `HKCU\...\Run` value; those are retired on upgrade — see below.

`service.json` contains `workerEnabled`, `port` and a validated `workerArgs`
array. It cannot override identity or launch arbitrary commands. Use
`install.ps1 -ServeArgs <string-array>` for arguments containing spaces;
`-ExtraServeArgs` remains a whitespace-separated compatibility option.
`-NoDesktopWorker` (alias `-NoServeTask`) installs only the machine service.
A custom `-DataDir` is persisted in
`HKLM\SOFTWARE\KubeWorkspaces\Agent\DataDir`, independently of MSI ImagePath.

**Migrating an older scheduled-task installation:** extract the new archive
and run its `install.ps1` against the existing BinDir/DataDir before applying
the service MSI. It checks identity first, retires legacy tasks/Run startup,
and stops only legacy agent modes at the exact installed executable path.
Do not reset or delete enrollment. `Register-ServeTask.ps1`/`Start-Serve.ps1`
remain for legacy diagnostics; registration refuses to create competing startup
when the native service exists. Legacy logon tasks disable execution time and
battery-stop limits. Unenrolled diagnostics can still pass both binding flags
directly to `serve`.

An **MSI-only upgrade self-heals**: the agent runs `service-configure` as a
deferred SYSTEM custom action on every install/upgrade, and that now also
retires legacy startup — it unregisters the `kw-agent-serve`/`workspace-agent`
scheduled tasks, deletes the `kw-agent-serve` HKCU Run value from every loaded
hive, and removes leftover launchers (e.g. `launch-serve.ps1`) the MSI no
longer ships. Run it explicitly on an existing guest with
`kw-agent.exe retire-legacy-startup`. The native path leaves no user-level
startup: the SYSTEM service (`Start=auto`, online at boot) spawns the console
worker hidden (`CREATE_NO_WINDOW`), so nothing runs or flashes at logon.

Use Windows Installer to remove an MSI installation. Archive installs use
`uninstall.ps1`, which also retains enrollment by default; `-PurgeIdentity`
explicitly removes it when preparing a genuinely fresh enrollment.

Troubleshooting (no private key is printed; specify `--data-dir` for custom paths):

```powershell
.\kw-agent.exe identity-check
.\kw-agent.exe service-config-check
Get-Content "$env:ProgramData\workspace-agent\service-status.json"
Get-Content "$env:ProgramData\workspace-agent\logs\service*.log"
# In the interactive desktop user's session:
Get-Content "$env:LOCALAPPDATA\workspace-agent\worker-KubeWorkspacesAgent*.log"
```

Native logs append and rotate at the next launch after exceeding 10 MiB.
Early setup failures are also recorded in `service-start-error.log` when the
data directory is writable; SCM reports an application-specific failure code.
`worker-process-running` means liveness; `mediaReady: null` explicitly does not
claim capture/streaming readiness. Transport telemetry remains the evidence for
streaming. Attach refusals identify `workspace-uid-mismatch` and
`workspace-generation-mismatch`; a heartbeat alone does not establish desktop
readiness. If the configured port is already bound, the worker exits with a
distinct code and `service-status.json` reports `state: "port-in-use"` with
`workerError: "port-in-use"` instead of crash-looping silently; retire any
legacy listener with `kw-agent.exe retire-legacy-startup`.

## Windows output selection

Run `kw-agent --hello` in the interactive console session to enumerate actual
adapters, outputs and supported modes. With `serve --capture-video`, use
`--capture-output-name '\\.\DISPLAY2'` to explicitly select an output by its
Windows device name across all adapters. Capture, guest resize and absolute
pointer coordinates share that selection, including the monitor's origin in
the virtual desktop. Missing selected outputs fail explicitly.

With no explicit output name, selection prefers an attached output on a
**virtual/indirect display driver** (e.g. the pinned MikeTheTech Virtual
Display Driver reports "Virtual Display Driver"). That monitor exposes the
host-configurable mode list, so premium streams a resizable display instead of
the emulated Basic Display VGA, which is a fixed-mode output. This is why a
managed service with default `workerArgs` no longer locks to the VGA's single
mode. An explicit `--capture-output-name` (or a non-zero `--capture-output`
index) still overrides the preference.

For the same default selection, an admitted **display session** makes that virtual display the
**only active output**. Windows otherwise keeps the emulated console VGA
attached, and applications with saved window placements reopen there even when
the virtual display is primary. Detaching the VGA is the reliable fix. The
topology change is session-only (not saved to the display database). The original
active paths are restored when that viewer disconnects, is taken over, or the
worker stops. Idle workers and telemetry/clipboard helpers do not isolate the
display. The proxy stamps the optional `attach.displaySession` boolean from the
authorized bridge purpose; older proxies omit it, which conservatively keeps the
console attached. Pass `--keep-console-display` to leave the VGA attached even
during an interactive display session. While the virtual display is isolated,
Tier 0 captures of the console output are unavailable until the viewer releases.
The managed worker also attempts a temporary extend topology at startup if the
QEMU Basic Display console was left detached by an interrupted worker.

The Windows service checks the QEMU VGA (`PCI\\VEN_1234&DEV_1111`, `BasicDisplay`)
for post-start failure **Code 43** every 15 seconds. Only that exact device/driver
failure permits a SetupAPI restart, with at most three attempts per service run.
Healthy, disabled, unrelated and absent devices are left alone; the service does
not install drivers, disable a GPU, reboot Windows or elevate the desktop worker.
An accepted restart is not proof of visible console output: validate it with the
hypervisor's independent screenshot and actual console input.

The display identity is checked separately from the DXGI rendering adapter.
An IDD backed by a hardware GPU can report the GPU's vendor name and no
software-adapter flag; its matching GDI display description still identifies
the virtual display.

For a bounded, read-only capture diagnostic, build and run the platform example
in an already logged-in Windows console:

```sh
cargo build --locked --release -p kw-platform --example capture-check
```

```powershell
.\target\release\examples\capture-check.exe
.\target\release\examples\capture-check.exe '\\.\DISPLAY2'
```

It reports selected output, capture size, mode count, five seconds of acquired
frame counts and adapter inventory. It saves no pixels. A single static frame
does not establish animated rendering, encoding or end-to-end viewer readiness.

Interactive `hello` and `telemetry` messages optionally report `video.capture`
(backend, output, adapter, PCI vendor/device IDs and software flag) and
`video.encoder` (backend name, codec and hardware flag). These facts come from
the opened duplicator and encoder, not a list of installed capabilities. Capture
loss clears the video facts; successful recovery/resize republishes the actual
backends. The current encoder is the Microsoft software H.264 MFT even when
capture uses a hardware GPU. Neither capture-adapter identity nor encoder choice
establishes an application's rendering adapter or GPU utilization.

The legacy `--capture-output N` selects that output index on the first adapter
exposing it. GPU vendor, onboard/discrete/vGPU/passthrough presence and KVM CPU
acceleration are not substitutes for actual output, driver or codec capability.
An emulated Basic Display adapter may expose a fixed resolution; changing an
arbitrary viewer size requires a guest display driver exposing the desired mode
(virtual-display mode lists are configured by the image, not negotiated live).

`hello.capture` reports true desktop dimensions, excluding encoder padding.
Successful resize ACKs similarly report actual dimensions; native viewers crop
the padded H.264 frame to those dimensions.

## Checks

```sh
make lint
make test
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
