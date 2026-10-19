# Typed MSI dispatch boundary

`kw_management::updates::installer` connects the write-ahead journal to a typed
installer adapter. This is the independently testable dispatcher, not an enabled
management endpoint, native MSI implementation or SCM updater service.

## Admission and single-use effects

Use `Transition::commit_for_dispatch` for effects. It returns a non-cloneable
`CommittedAction` only after the journal's durable CAS and exact off-guest intent
acknowledgment succeed. Serialized `Action` descriptors and reopened checkpoints
cannot construct a permit. An adapter dispatch consumes the permit even when
preparation/authority fails; it cannot be reused to retry an uncertain effect.
Recovery must reconcile the recorded active action and obtain any subsequent
authority through the same attempt, not deserialize an action and execute it.

`Transaction::new` binds the plan to both publisher-verified manifests, exact
ProductCodes and target/predecessor manifest digests. The predecessor must appear
in the target's signed rollback list, and its version must satisfy the target's
installed-version compatibility range. Driver-bearing plans deny until a
qualified driver adapter exists. The recorded installation directory comes from
authenticated initial machine inventory, never a start payload.

Before each MSI mutation the dispatcher:

1. Requests verification/pinning of both the target and predecessor packages.
2. Obtains fresh per-machine MSI inventory; busy, reboot-pending, unknown,
   multiple, substituted or differently located products deny.
3. Requires `PhaseAuthority` to recheck current identity, epoch, boot, worker
   fence, deadline, cancellation, policy and recorded phase authorization.
4. Dispatches exactly one typed install or exact-product uninstall operation.
5. Observes the result without automatically retrying an operation.

Only `install_target_msi`, `uninstall_target_msi` and `install_previous_msi`
reach this adapter. SCM actions, health verification, drivers and reboot require
their own adapters and cannot become arbitrary installer commands.

## Compensation

The journal's explicitly admitted rollback flow stops the agent, uninstalls the
exact target ProductCode, then installs the pinned predecessor into the recorded
machine directory. The uninstall precondition requires exactly the target
product/version/UpgradeCode/directory. Predecessor installation requires both
products to be absent; it cannot silently repair an existing registration or
remove a different product. No global downgrade override is accepted.

Exit codes `3010` and `1641` produce reboot-required receipts, never success.
Code `0` also requires matching observed product state. Lost adapter replies,
lost post-install observations, or contradictory successful return codes remain
uncertain with the journal action active. The dispatcher does not infer final
health, unchanged machine identity, or upgrade/rollback success from MSI results.

## Native adapter obligations

No production `MsiAdapter` or `PhaseAuthority` implementation is supplied yet.
The native implementation must use protected staged files pinned against
replacement throughout the installer operation, bound artifact size/digest and
MSI Property-table checks, Windows Installer APIs rather than `Win32_Product`,
fixed machine-wide silent/reboot-suppressed operations, and bounded evidence
capture. Target and predecessor artifacts may have the same basename; resolve
them by their separately pinned identities/staging locations.

Native effects must preserve ProgramData, enrolled identity and private keys.
Never kill a running MSI to implement cancellation. SCM lifetime, native
installer/driver integration, authenticated management phase grants and actual
installed-build compensation/reboot proof remain separate integration work.
