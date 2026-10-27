# Bounded Windows SYSTEM scripts

The opt-in `qga-pod-exec/v1` runner supports request v2 with
`operation=script`, explicit elevated `SYSTEM` and
`interpreter_policy=windows-powershell-v1`. This is independent of desktop logon
and capture; it opens no management listener or interactive shell. A matching
API must admit and record the full script before issuing the signed grant.

## Contract and prerequisites

- Install the matching agent and retain its protected enrolled workspace binding
  and management public keys. QGA and the fixed installed runner must run as
  LocalSystem; an ordinary desktop process cannot stage scripts or substitute an
  ordinary-user script for SYSTEM execution.
- The management state parent must be machine-owned (SYSTEM/Administrators or
  the Windows TrustedInstaller service) and
  not grant other principals write/delete/ACL-change access. The normal installed
  agent data-directory protection supplies this. Redirected/reparse-point state
  directories or ancestors, UNC/ADS and parent traversal paths fail closed.
  Ancestor owners/ACLs must also prevent ordinary principals from replacing
  children or changing security; permission to create unrelated sibling entries
  alone is allowed, matching normal ProgramData behavior.
- The request must use a script body and empty executable/argv. The first line
  must be exactly `#!powershell`, using LF or CRLF, without interpreter arguments
  or an input BOM. A Linux interpreter policy bound to SYSTEM, or this policy
  bound to root, is rejected. The body is at most 64 KiB UTF-8, without NUL;
  the signed envelope has an independent 96 KiB bound.
- The filename hint uses the shared bounded ASCII basename rules; it is recorded
  but never used as a path. The runner creates a fixed `script.ps1` in an exclusive
  execution directory beneath private management script state, only after grant
  verification and persistent replay consumption.
- Directory/file ACLs are explicit, protected and SYSTEM-only from creation;
  existing entries with other ACLs are rejected rather than repaired. Reparse
  points, hardlinked files and unexpected recovery entries fail closed. A
  non-inheritable exclusive file handle serializes script staging/recovery until
  supervision and cleanup finish. Concurrent scripts fail without dispatch.
- Windows PowerShell 5.1 needs a BOM to read UTF-8 source reliably. This signed
  interpreter policy therefore stages **UTF-8 BOM + exact submitted body**; the
  independent protected recording retains the original body and policy.
- Execute only
  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with fixed argv
  `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <private path>`.
  No `-Command` interpolation, `cmd`, `env`, `pwsh` discovery or fallback is used.
- Reuse the existing Job Object supervisor: maximum 20 seconds, 16 active
  processes, 16 KiB combined stdout/stderr, descendant teardown on completion,
  timeout and output overflow. Script input encoding does not establish a new
  output encoding; results preserve the emitted stream bytes.
- Remove the staged script/directory after the supervisor returns. Cleanup
  failure is a runner error, not success. The next verified script removes crash
  leftovers under the exclusive lock, never executes or retries them, and never
  recursively deletes unexpected contents. Replay-state updates also use an
  exclusive cross-process Windows file handle.

Example nested script payload (the surrounding v2 request/grant binds identity,
workspace/VM/actor/execution/recording, cwd, bounds and exact request bytes):

```json
{
  "body": "#!powershell\nWrite-Output 'hello'\nexit 0\n",
  "name": "maintenance.ps1",
  "interpreter_policy": "windows-powershell-v1"
}
```

`kw-agent management-exec --capabilities` reports v2/`windows-powershell-v1` on
Windows without reading keys, identity or execution input. The API probes only
this fixed command through authenticated QGA, never treats discovery as authority,
and repeats admission/preflight before dispatch. Older Windows builds advertising
version 0 remain unsupported. No fallback follows failed management mTLS.

## Verification

Normal Linux checks include the independent signed Windows request fixture,
policy/identity substitutions and replay; cross-compilation checks the Windows
implementation but cannot prove its native ACL/process behavior.

On a disposable Windows checkout in an explicitly authorized **LocalSystem** test
session, run the native SYSTEM script matrix:

```powershell
cargo test -p kw-agent system_script_acl_file_execution_and_recovery -- --ignored --nocapture
```

The matrix covers protected ACLs/BOM/fixed-File/nonzero results and locking/
recovery, followed by full signed request verification/replay consumption through
real staging and supervision. Signed cases exercise explicit UTF-8 output,
root-exit/deadline/output-limit descendant teardown and removal of staged scripts.
It also rejects inherited/unprotected script roots and hardlinked files, then
verifies cleanup recovery after the extra hardlink is removed. Script deadlines
remain 20 seconds; the isolated SYSTEM task bounds the whole matrix.

Ordinary Windows CI runs the non-SYSTEM denial and concurrent replay-claim tests.
The privileged test is deliberately ignored in an ordinary user session. Windows
CI additionally runs `packaging/windows/test-management-scripts.ps1` as an
administrator: it compiles/selects the unit-test executable and invokes exactly
this test in a temporary SYSTEM scheduled task with a machine-owned test root,
bounded wait, result log and cleanup. It touches no installed agent/service or
workspace. The same script can be used on a disposable administrator test host.
Follow
with installed API/browser checks for recording, deadline/descendant cleanup,
output flooding, missing/old guest rejection, transport loss and recovery. These
are separate from compilation and fixture-backed UI tests.

The API repository's opt-in `TestScriptExecutionLive` provides installed QGA,
script/descendant and protected-recording proof on either OS, using
`KW_EXECUTION_SCRIPT_LIVE_NAMESPACE` / `KW_EXECUTION_SCRIPT_LIVE_WORKSPACE`.
It stages a fresh test verification key and must use a disposable workspace.
The HTTP account/authentication fixtures and encrypted ephemeral recording store
are local; deployed browser and persistent-storage acceptance remain separate.
