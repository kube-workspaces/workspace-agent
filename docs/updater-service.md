# Independent updater SCM lifetime

`kw-agent-updater.exe` is a separate Windows own-process LocalSystem service,
outside the agent MSI's replacement directory. Its updater protocol is versioned
independently (`1`); builds stamp `KW_UPDATER_VERSION`, separately from the agent
binary's version. Windows builds upload it as the separate
`updater-windows-amd64` CI artifact. It is not included in the agent MSI or its
replacement tree; signed helper release/bootstrap packaging remains separate.

## Production entry point

The binary accepts only `--version`, `service`, and `configure-recovery`.
Production service name is fixed to `KubeWorkspacesAgentUpdater`; there are no
service-name, root, request-file, authority-file, script or installer overrides.
The machine ProgramData path comes from the Windows known-folder API, not a
desktop process environment variable.

Bootstrap must verify the operator-pinned helper artifact and configure a quoted
SCM ImagePath pointing to the attempt-specific image:

```text
<ProgramData>\workspace-agent\updates\<attempt-id>\kw-agent-updater.exe
```

The attempt root and image must satisfy the existing protected-owner/DACL,
no-reparse/no-hardlink contract. Its directory name must exactly match the
launch attempt ID. The helper runs only as LocalSystem, holds a protected global
machine mutex for its full lifetime, and never adopts a pre-existing named
mutex object. The SCM service and binary must be staged by privileged bootstrap;
the helper does not self-install from a request.

Call `configure-recovery` only during privileged bootstrap, outside SCM startup
and the MSI service database lock. It restricts service access to SYSTEM and
Administrators and configures two restart delays (5 and 15 seconds) followed by
no action, with a one-day reset. There is no recovery command, reboot action or
unbounded restart loop.

## Launch binding versus authority

Bootstrap writes a canonical, bounded, protected `resume.json` once, using
`updates::lifetime::LaunchBinding::write_new`. It binds the admitted attempt,
workspace/VM identity, epoch, actor/recording identity and plan digest. It cannot
carry arbitrary paths, installer properties or commands. Partial, noncanonical,
unknown-field, duplicate-field or mismatched configuration denies startup; the
helper never repairs/adopts an invalid launch record.

**The launch file is an identity hint, not fresh authority.** A verified
`RecoveryAuthority` must supply the independently authenticated current plan and
checkpoint digest plus sequence floor before `FileStore::reopen` runs. Recovery
checks the journal's full binding and retains its existing active action. It
does not deserialize a permit or replay installation.

Until authenticated management transport is integrated, the shipped host uses
`UnavailableAuthority`. It remains running in `waiting_for_authority`, does not
adopt a local checkpoint hash, and cannot dispatch an installer. The host can
retry unavailable recovery coordination; denied/mismatched authority fails closed.

The protected `updater-status.json` reports the process ID, attempt, waiting or
verified-checkpoint state, and optional journal phase/sequence. `effects_enabled`
is always false for this recovery-only host. Status is an operational hint,
not readiness, phase authority or durable audit. After a stop its status file
can be stale: correlate its process ID with current SCM state.

## Stop and recovery behavior

The service reports StartPending/Running/StopPending/Stopped, accepts stop and
shutdown, and releases checkpoint/mutex ownership at its safe stop boundary.
It neither joins the agent's child tree nor uses its Job Object or logon session.
SCM crash recovery reopens the same protected binding and independently verified
journal; it never consumes the original start request again.

This host currently performs read-only recovery. Future integration must keep
the native MSI transaction alive to its safe boundary on stop, preserve bounded
evidence, and recheck signed phase authority before another effect. Production
phase grants, driver qualification, updater dispatch and installed-guest
identity/handshake/reboot health proof remain open.

## Windows CI proof

`packaging/windows/test-updater-service.ps1` uses the same SCM implementation via
an isolated example host with a synthetic off-guest authority provider. This
test-only host is never uploaded as the production updater artifact. CI:

- Starts a uniquely named LocalSystem own-process service against a protected
  active write-ahead journal.
- Runs the real isolated native agent MSI upgrade/uninstall/compensation campaign
  while the helper remains alive at the same PID and image digest.
- Kills the helper and verifies automatic SCM restart at a new PID, reopening
  the unchanged active journal without replay.
- Verifies normal stop does not restart the helper.
- Restarts without an authority provider and verifies the explicit waiting state
  and unchanged journal despite the existing protected local launch file.

This proves isolated service lifetime/recovery behavior, not a live managed
upgrade or guest phase-grant transport.
