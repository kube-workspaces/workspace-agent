# Updater checkpoint persistence

`kw_management::updates::persistence::FileStore` supplies the file-backed
`journal::Store` boundary. It is a persistence building block for the independent
updater, not an installation command or an updater service entry point.

## Provisioning and ownership

The helper must use one fixed, dedicated machine updater root, outside the agent
MSI replacement directory (for example, beneath the machine's protected
`ProgramData\workspace-agent\updates` directory). Provision its parents through
the machine bootstrap path. Parents must be trusted and protected against
unprivileged rename/replacement; checking for reparse points alone does not prove
that a parent is trusted. Do not derive the root from an incoming request, a
desktop session environment variable, or a tenant-writable directory.

`create_root` creates only the final component, with its ACL present at creation:

- Windows: protected SYSTEM/Administrators full-control DACL and Administrators
  ownership. Files receive explicit protected ACLs as well, not ambient defaults.
  Existing roots/files must have these exact owner/access descriptors (the
  auto-inherited bookkeeping flag may also be present). The process must have
  the rights to create Administrators-owned objects; production runs as SYSTEM.
- Unix: private `0700` directory and `0600` files for the host test harness.

Existing directories are never automatically adopted or permissions-repaired.
Relative paths, parent traversal, symlink/reparse components, redirected files,
and multiply linked files deny. Windows network/UNC paths, alternate streams,
NULs, and ambiguous trailing-dot/space components deny.

The store holds an exclusive, nonblocking OS lock on `owner.lock` for its entire
lifetime. All helper instances must use the same root, across attempts. Lock
contention fails; process death releases the lock. Never unlink or replace the
lock file to recover ownership. This lock complements API worker fencing and
does not grant permission for an installation phase.

## Writes and recovery

`initialize` persists a validated sequence-zero journal, refusing an existing
checkpoint or temporary checkpoint. Each CAS verifies the actual disk head,
immutable plan, exact next sequence, nondecreasing owner fence and timestamps.
Only bounded, canonical journal bytes are accepted.

Writes use a newly created `checkpoint.next`, flush its contents, then replace
`checkpoint.json` atomically in the same directory. Unix also flushes the parent
directory; Windows uses `MoveFileExW` with replacement and write-through. There
is no cross-volume copy fallback. Storage must support the local atomic replace
and flush semantics; cross-compilation is not filesystem/power-loss proof.

Any error after write I/O starts poisons the handle. In particular, a rename may
have succeeded before an acknowledgment was lost. No effect descriptor is
returned by a journal transition when persistence fails. Drop the handle and
reconcile the same attempt with independent off-guest evidence; do not retry the
installer or infer that the old checkpoint is still current.

`reopen` requires the plan digest, expected checkpoint digest and sequence floor
from trusted coordination. It never trusts the journal's own digest as authority.
A partial `.next` is removed only after the committed checkpoint matches that
trusted head. Reopening an active action returns its checkpoint, not a fresh
action permit. Use the journal recovery advisory and current guest observations
to decide whether to wait for Windows Installer, reconcile, or require recovery.

Checkpoints are not automatically deleted or replaced for a new attempt. The
future helper lifecycle must retain/archive completed evidence and enforce the
rollback window before reusing an active slot.

## Verification boundary

Tests cover actual filesystem writes, competing owners, a killed lock-holder
process, restart with write-ahead intent, stale head/floor/plan rejection,
oversize/corrupt/hardlinked files, permission/reparse rejection, partial writes,
and a failed acknowledgment after replacement. The same tests compile for the
Windows target and are part of the normal workspace test suite.

SCM helper lifetime, typed MSI/IDD adapters, signed management phase permits,
recording transport, SYSTEM installed-guest execution, and crash/power-loss
qualification remain integration/proof work.
