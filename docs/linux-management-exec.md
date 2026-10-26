# Linux recorded management commands and script runner

The explicitly enabled `qga-pod-exec/v1` backend supports bounded commands as
**root** on Linux agent-equipped VMs. It is independent of GNOME, desktop
capture, user login and SSH. The v1 command request takes an executable
and argv, optional cwd, no interactive stdin or PTY. Running `/bin/sh -c` or
another interpreter is an explicit command and uses the same bounds.

The guest runner also implements the v2 script contract below. A matching API
checks `kw-agent management-exec --capabilities` through the authenticated QGA
path before admission. This fixed probe reports request/policy support without
reading identity, keys, execution input or state, and creates no user process.
It is not proof of actual root/cgroup/storage readiness. Older runners return no
compatible advertisement and must not receive script requests. Browser Script
mode additionally requires client capability gating.

## Installation and prerequisites

- Install a verified matching agent at `/usr/local/bin/kw-agent`.
- The controller must provision `/etc/workspace-agent/public/binding.json`
  with this workspace's UID and stable generation. Do not bake a live binding
  into an image. The runner refuses a missing binding.
- Create `/var/lib/workspace-agent` as root, mode `0700`. The Linux archive's
  `install.sh` does this. Existing installations need this directory created
  when installing the new binary. It holds verification keys, staged requests
  and persistent single-use grant state; never make it desktop-user writable.
- Run `qemu-guest-agent` as root with guest file and guest-exec RPCs enabled.
  API connectivity to the current owned KubeVirt launcher is required.
- Require writable cgroup v2 at `/sys/fs/cgroup`, `cgroup.kill` (Linux 5.14+),
  and the `pids` controller enabled in the parent. The runner creates a unique
  execution cgroup and sets `pids.max=16` before spawning. Missing supervision
  produces `spawn-failed`; it never falls back to unsupervised process groups.
- Explicitly enable the API QGA backend and VM execution/elevation policy.
  Both scoped `workspace.exec` and `workspace.exec.elevated` are required.
  The API must have recording storage ready before admission.

The API selects `root` from the controller-bound Linux workspace, never from
caller-supplied identity text. Its signed grant binds the invocation, workspace
UID, VM UID, launcher, actor and recording. The guest checks the signature and
its own root-owned workspace binding and refuses SYSTEM grants on Linux.
Concurrent Linux invocations serialize replay claims using an OS file lock.
QGA remains an explicit transport, never a fallback after failed mTLS.

## Runtime contract

Executable paths must be absolute. Arguments are passed directly without shell
interpolation. The default cwd is `/`; stdin is closed. Environment is a fixed
root baseline (`PATH`, `HOME=/root`, `USER`, `LOGNAME`, `LANG=C.UTF-8`), without
inherited QGA/service credentials. File creation uses umask `0077`.

Commands have a maximum 20-second guest deadline and 16 KiB combined output
budget. stdout/stderr are recorded separately as bytes. Output overflow reports
`output-limit` and `truncated=true`; deadline reports `deadline`. Signal exits
use `128 + signal` in the existing integer exit-code field. Root exit, deadline
and output overflow kill the execution cgroup before draining bounded,
nonblocking pipes. A separate watchdog kills the group if the runner dies or
exceeds its bounded lifetime. Descendants that call `setsid()` remain in the
cgroup. Root execution is administrative authority, not a sandbox against an
authorized root deliberately altering the agent or cgroup hierarchy.

The API records the admitted invocation and final result before returning
success. Lost guest transport is an explicit unknown result; never auto-retry.
The workspace `execution_identity` field is a configured support hint, not a
claim of live guest readiness. Admission checks the current target and the
installed runner checks actual prerequisites.

## Linux script request v2

The transport, grant audience/type and existing command request v1 are unchanged.
Script requests use `version: 2`, `operation: script`, explicit elevated `root`,
empty/omitted `executable` and `args`, and this nested payload:

```json
{
  "body": "#!/bin/sh\nprintf 'hello\\n'\n",
  "name": "maintenance.sh",
  "interpreter_policy": "linux-shebang-v1"
}
```

The script shares the request's optional `cwd`; there is no nested cwd or
interpreter argv. The exact serialized request digest binds body, basename hint,
cwd, policy, identity, operation and bounds into the signed grant. Version 1
requests labelled `script` are rejected: executable/argv framing is insufficient
to authorize an inline script. Older command-only runners reject request v2.
Windows scripts use the separate
[SYSTEM PowerShell policy](windows-management-scripts.md); this Linux policy is
never accepted as authority for SYSTEM execution.

- UTF-8 body: at most 64 KiB, no NUL. The entire encoded envelope must also fit
  96 KiB; JSON escaping can exhaust this separate limit before the raw-body limit.
  A matching API must check both before admission/dispatch.
- Accepted first lines are exactly `#!/bin/sh`, `#!/bin/bash`,
  `#!/usr/bin/bash`, or `#!/usr/bin/python3`. No PATH/`env` lookup, shebang
  arguments, BOM or CRLF shebang. Missing interpreters yield a supervised spawn
  failure. Script input is never interpolated into a command string.
- `name` is optional, at most 128 ASCII alphanumeric/`.`/`_`/`-` characters,
  excluding `.` and `..`; it is a recorded hint, never a guest path.
- After signature verification and durable single-use claim, the runner creates
  an exclusive directory and file, both mode `0700`, under the management state
  directory's private `scripts` root. The file is closed before kernel shebang
  execution. The existing cgroup supervisor enforces the same deadline, output
  budget, fixed environment, stdin closure and descendant cleanup as commands.
- One script can hold the nonblocking per-guest staging lock at a time. A second
  request fails without dispatch and is not automatically retried. Commands
  retain their existing concurrency behavior.
- Files are removed after success, nonzero exit, deadline, output limit or spawn
  failure. Cleanup failure is a runner error, never success. A later verified
  script request removes crash leftovers while holding the lock; leftover scripts
  are never replayed. Unexpected entries/permissions deny recovery rather than
  recursively deleting unrelated files. This is recovery on the next script
  request, not an independent boot-time scavenger.

Protected off-guest admission must include the complete script before issuing its
grant. Script bodies belong only in encrypted recordings, not metadata or logs.

## Verification

Normal checks: `make lint`, `make test`. Privileged process tests on a
disposable Linux host/VM with the prerequisites above:

```sh
sudo cargo test -p kw-agent linux_real_process_supervision -- --ignored
sudo cargo test -p kw-agent linux_runner_loss_kills_descendants -- --ignored
```

The API repository's opt-in test exercises its authenticated local HTTP harness
and encrypted ephemeral recording against a real installed Linux guest:

```sh
KW_EXECUTION_LIVE_NAMESPACE=execution-proof \
KW_EXECUTION_LIVE_WORKSPACE=linux-vm \
go test -v -run '^TestLinuxExecutionLive$' .
```

Use only a disposable proof VM: this test stages a fresh verification key. Its
account/authentication fixtures and recording store are local; policy, fresh
target resolution, Kubernetes pod exec, QGA and guest verification are real.
Production rollout and browser acceptance are separate from that harness.
