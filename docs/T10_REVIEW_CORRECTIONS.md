# T10 review corrections

PR 61 received Changes Requested on `588e179` from VidhiTF (review 5245253549).
Scope is T10, Claims 5 and 12; Claim 12 passed. The remaining findings are confirmed:
P2 activity still determines the canonical numeric score despite an 84.9 cap, and
P3 successful TOTP timesteps can be reused across distinct approvals.

## Reuse and implementation decisions, recorded before edits

- Replace the scorer's canonical points with reviewed-evidence qualification:
  a fully qualified, implemented control without blocking findings earns 100;
  otherwise it earns zero. Keep existing control weights for framework aggregation.
  Product usage belongs in a separately labeled diagnostic object and cannot
  add canonical points, clear evidence gaps or influence readiness. Zero evidence
  therefore yields zero and insufficient_evidence in private/public/history surfaces.
- Reuse the existing MFA verifier and authenticated User row rather than a second
  authentication service. Persist a monotonic consumed TOTP timestep, protected
  by the same tenant-scoped database transaction and row locking/atomic updates.
  The state is per principal/credential, independent of approval/operation ids.
  Backup-code consumption must also survive refreshed ORM state and races.
  A nullable replay-state column and migration are necessary because neither
  the existing operation-specific Redis failure counters nor timestamps on
  individual approvals enforce a durable global single-use invariant.
- Preserve validated role configuration from Claim 12. Add regressions for actual
  counts-only framework/public/API behavior and real TOTP reuse across different
  approvals, concurrency, old/current/next timesteps and transaction rollback.
- Existing policy fingerprinting versions the changed decision rules. Preserve
  historical rows; no silent reinterpretation of old scores. Update schema gates,
  operations guidance, PR evidence and the current-head review marker after tests.

Fresh T01 activation verification passed 2026-09-18 before remediation: PR 52,
reviewed SHA `b8b23993a7a467396598eefdd23b97da83d47042`, merge
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
`2026-09-16T12:57:25Z`; live ruleset 21141288 active, zero bypass actors.
Human reviews and release gates remain unsatisfied until independently accepted.

## Reproduction and acceptance

Before correction, three scoring regressions failed: counts-only controls and
frameworks produced 84.9 instead of zero, and a qualified control with minimal
activity produced 25 instead of 100. Two MFA regressions failed: a TOTP was
accepted again after commit, and a consumed backup code reappeared after ORM
refresh and commit. The initial Windows sandbox run crashed before collecting
MFA tests; the subsequent execution reproduced both behavioral failures.

The corrected scorer retains all control weights in the denominator, so missing
controls cannot inflate coverage. Missing assessments produce zero canonical
points and insufficient evidence readiness even when activity diagnostics reach
100. A qualified control earns 100 regardless of activity volume. Partial
implementation, findings, stale evidence and all prior qualification blockers
still prevent canonical points. Public views and persisted history use the same
method and version; historical methods are labeled separately.

Successful MFA consumption now uses the tenant-scoped persistent User row under
a database lock. It rejects detached or stale principals, consumed or older TOTP
steps, and reused backup codes. Consumption is flushed before authorization
refresh and committed with the protected action. Failed transactions can retry.
The deterministic requester/reviewer lock order prevents cross-over approval
deadlocks. Migration 051 retains replay state and refuses destructive downgrade
after consumption. Drain old MFA writers during rollout.

Assessment reviews use one stable MFA rate-limit operation category so a new
approval ID cannot reset the failure budget. Trust Summary retains safe
qualification metadata and gaps without exposing evidence/audit identifiers.

Current execution results and limitations are recorded in
[implementation evidence](T10_IMPLEMENTATION_EVIDENCE.md#test-evidence).
