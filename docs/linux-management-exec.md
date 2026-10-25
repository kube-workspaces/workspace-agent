# Linux recorded management commands

The explicitly enabled `qga-pod-exec/v1` backend supports bounded commands as
**root** on Linux agent-equipped VMs. It is independent of GNOME, desktop
capture, user login and SSH. This is the command-only backend: an executable
and argv, optional cwd, no interactive stdin or PTY. Running `/bin/sh -c` or
another interpreter is an explicit command and uses the same bounds.

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
