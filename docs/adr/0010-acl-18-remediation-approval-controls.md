# ADR-0010: Remediation plan and human approval controls

- Status: Accepted
- Date: 2026-07-20
- Jira issue: ACL-18
- Owner: Vidhi Sharma
- Collaborators: Kunal, Ravi
- Branch: `feat/agent/ACL-18-remediation-approval-controls`

## Context

AuthClaw can recommend and execute remediation actions against tenant resources. A
consequential change must remain recommendation-first: an operator needs to see the
proposed mutation, its risk, and its rollback strategy before authorizing execution.
The authorization must not be transferable to another tenant, user, action, or time
window, and it must not be reusable.

The existing workflow already paused before remediation and supported approve/reject
decisions. It did not cryptographically bind the decision to the plan, persist a
one-time consumption state, or consistently apply tenant filters to workflow approval
lookups.

## Decision

### Review-ready remediation plan

Every action exposes:

- `proposed_change`: target, summary, ordered steps, and before/after preview;
- `risk`: level, destructive flag, and expected impact;
- `rollback`: restore strategy, trigger, and evidence produced.

Executable connector fields remain in the same plan object, so the reviewed object is
the object passed to execution.

### Immutable approval binding

The approval service normalizes the plan and computes a canonical SHA-256 hash over:

1. tenant identifier;
2. complete action payload, including workflow identifier and schema version;
3. approval expiry timestamp.

The human approver is persisted separately as `approver_id`. Together,
`tenant_id`, `approver_id`, `action_hash`, and `expires_at` form the authorization
boundary required by ACL-18.

### One-time execution

Immediately before remediation, the runner:

1. loads the tenant-scoped remediation approval with a database row lock;
2. verifies workflow, tenant, approver, expiry, plan, hash, status, and fresh MFA for
   destructive actions;
3. rejects and audits invalid attempts;
4. atomically changes a valid approval from `APPROVED` to `CONSUMED`;
5. records `consumed_at` and `consumed_by_id`;
6. allows that single execution to continue.

A second consumer observes `CONSUMED` and is rejected as a replay.

### Audit and telemetry

Approval decisions and rejected execution attempts are written to `approval_audit`
with the action hash, reason, and minimal non-sensitive context. Counters identify
consumed, expired, replayed, altered, unapproved, or incorrectly bound attempts.

## Failure behavior

- Expired approval: marked `EXPIRED`; execution stops.
- Replayed approval: rejected; execution stops.
- Changed plan or invalid hash: marked `ALTERED`; execution stops.
- Pending or rejected approval: rejected; execution stops.
- Wrong tenant, workflow, or approver: rejected; execution stops.
- Missing or stale MFA on a destructive plan: marked `EXPIRED`; execution stops.

No rejection path calls the remediation connector.

## Migration and rollback

Migration `027` adds nullable binding and consumption fields so existing non-remediation
approval records remain readable. New remediation approvals always populate the action
hash.

Application rollback:

1. stop remediation workers;
2. deploy the previous application version;
3. run the migration downgrade only after confirming no active ACL-18 approvals require
   the new audit fields.

Database downgrade removes the ACL-18 columns and index. Approval audit rows should be
exported before destructive schema rollback when required for evidence retention.

## Consequences

- Remediation approval becomes non-transferable and one-time.
- Concurrent execution attempts serialize on the approval row.
- A plan change requires a new approval rather than silently reusing an old decision.
- Legacy approvals without an action hash cannot execute under the ACL-18 path.
