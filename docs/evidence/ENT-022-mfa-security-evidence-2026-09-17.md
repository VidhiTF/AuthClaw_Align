# ENT-022 privileged MFA implementation evidence

Date: 2026-09-17
Branch: `security/ent-022-privileged-mfa`
Repository baseline: `align/master` at `45976f0`

## Scope and resulting controls

- Removed `approval.default_mfa_code` and its `123456` fallback from the agent policy loader.
- Removed the local/test MFA-disable flag from the agent activation path.
- Made console enrollment two phase: a pending encrypted secret is activated only after a rate-limited TOTP confirmation. The legacy one-step workflow enrollment route returns HTTP 410.
- Added persistent TOTP time-step consumption. Backend callers hold the user row lock; the agent verifies and updates its identity row in one transaction under tenant context.
- Kept Redis-backed per-user/per-operation rate limits, bounded escalating cooldown, and fail-closed Redis behavior in the backend. Added durable five-attempt/five-minute lockout to the agent identity path.
- Recovery-code rotation requires a fresh rate-limited MFA challenge. Lost-factor reset requires a different owner, that owner's fresh MFA, and revokes the target user's sessions.
- Privileged users cannot self-disable MFA. Requesters cannot approve their own privileged requests.
- MFA lifecycle events and rejected self-approval/replay events contain actor/subject/action metadata but no secret, TOTP, or recovery-code value.

## Required evidence

### Secret scan result

Focused ENT-022 production/configuration scan: **PASS**.

Command scope: `.env.full.example`, `backend/app`, `console/src`, `services/agent`, and `infra`, excluding test, cache, virtual-environment, and dependency directories.

Forbidden patterns: `default_mfa_code`, `DISABLE_MFA_FOR_TESTING`, `AUTHCLAW_ALLOW_TEST_MFA_BYPASS`, a quoted literal `123456`, and a non-empty `AUTHCLAW_LITE_DEMO_TOTP_SECRET` assignment.

Result:

```text
PASS: no ENT-022 forbidden static MFA defaults or bypass flags found in production/configuration scope
```

Full repository Gitleaks scan: **PASS**.

The checksum-verified Windows build of the CI-pinned Gitleaks `v8.24.3` scanned the complete working tree with `.gitleaks.toml` and redaction enabled.

```text
scanned ~881659404 bytes (881.66 MB) in 22.8s
no leaks found
```

The CI container scan remains a mandatory independent pre-merge check.

### MFA abuse test report

Command:

```text
backend/.venv/Scripts/python.exe -m pytest -q -vv \
  tests/test_ent022_mfa_security.py \
  tests/test_release4_abuse_controls.py \
  tests/test_auth_baseline.py \
  -k "totp_counter_is_consumed_once or replayed_totp or mfa_cooldown_escalates or mfa_redis_failure or pending_factor_requires_confirmation or separate_owner_recovery or self_approval_is_rejected or mfa_lifecycle_audit"
```

Result: **8 passed, 63 deselected**.

Covered abuse cases:

- accepted TOTP time-step cannot be reused;
- replay is counted as a failed attempt and emits `mfa:replay_rejected` evidence;
- cooldown escalates but remains bounded;
- unavailable/ambiguous Redis fails closed and never reaches factor verification;
- pending factor is inactive until possession confirmation;
- lost-factor reset requires a separate owner and invokes session revocation;
- self-approval is denied and audited;
- lifecycle audit payload carries actor and subject identifiers without factor material.

The complete backend security/compliance selection subsequently ran against Redis 7.4.11 on localhost. All real-Redis abuse cases passed, including atomic replay rejection, cooldown expiry/escalation/reset, and ambiguous-response handling.

The agent startup migration also ran against a disposable PostgreSQL database. A live encrypted-secret rehearsal accepted one current TOTP counter, rejected its replay, persisted consecutive failures, and enforced the five-attempt lock for a non-UTC database session.

### Privileged action audit trail

Implemented event paths:

| Event/action | Actor | Subject | MFA evidence | Persistence |
| --- | --- | --- | --- | --- |
| `mfa:enrollment_started` | current user | current user | pending factor only | immutable audit outbox |
| `mfa:enrollment_confirmed` | current user | current user | confirmed TOTP possession | immutable audit outbox |
| `mfa:recovery_codes_regenerated` | current user | current user | fresh challenge | immutable audit outbox |
| `mfa:recovery_reset` | separate owner | target user | fresh owner challenge | immutable audit outbox + session revocation |
| `mfa:disabled` | non-privileged current user | current user | fresh challenge | immutable audit outbox |
| `SELF_APPROVAL_REJECTED` | requesting actor | approval | `mfa_verified=false` | approval audit table |
| `APPROVED` | separate approver | approval | verified flag and timestamp | approval audit table |
| `mfa:replay_rejected` / cooldown / Redis failure | challenged user | challenged user | failure only | immutable audit outbox |
| `approval_identity_missing` | authenticated approver | malformed/historical approval | not reached | approval audit table |
| `self_approval_rejected` | canonical OIDC `sub` | approval requester | not reached | approval audit table |

The automated audit-contract cases passed. No production audit row is attached because this branch was not deployed and no production action was performed.

## Other verification

- Backend security/compliance selection with PostgreSQL and Redis: **394 passed**.
- Backend PostgreSQL integration: **108 passed**, including concurrent review OTP, tenant isolation, migrations, invitation lifecycle, session revocation, and advisory locks.
- Backend migration chain: Alembic head `050` applied successfully over `049`.
- Agent CI selection: **27 passed, 7 subtests passed**; Python compile passed.
- Agent live database rehearsal: startup migration, encrypted TOTP, replay rejection, durable lockout, and tenant-context binding **passed**.
- Console: lint **0 errors / 15 warnings**, **44 unit tests passed**, dependency audit **0 vulnerabilities**, TypeScript **passed**, production build **passed**.
- Audit consumer: **74 passed**; Kafka and SQS FIFO local transport rehearsals passed.
- Repository policy tests: **121 passed**; Python SDK: **2 passed**; compose contract/configuration passed.
- Gitleaks `v8.24.3`, Tokei line-budget gate, Python compile, and `git diff --check`: **passed**.
- Gateway quota/security tests that do not require live Redis passed after placing the Go build cache in the writable test sandbox. Redis-backed gateway cases could not run locally because the Docker engine did not become responsive; the Linux PR check remains required and this local result is not claimed as a pass.

## Post-master compatibility verification

On 2026-09-17, `origin/master` advanced to `0103304` (PR #55, fail-closed
tenant and provider quotas). That commit was merged into this PR branch as
`73f20d0` before compatibility testing.

- Git's `ort` strategy auto-merged all files with **no textual conflicts**.
- The meaningful overlap was limited to `.env.full.example`,
  `services/agent/database/migrations.py`, `services/agent/main.py`, and
  `services/agent/startup/validation.py`.
- Inspection confirmed that quota startup/configuration and request handling were
  retained alongside ENT-022 tenant/request context, encrypted TOTP verification,
  replay counters, lockout, and separation-of-duties enforcement.
- Combined agent compatibility selection: **70 passed, 35 subtests passed**.
  This selection exercised MFA authorization, quota service/HTTP/provider/
  monitoring behavior, graph security, control-plane authentication, and audit
  transport contracts in one merged runtime.
- Focused backend ENT-022 and migration-chain selection: **8 passed**.
- Console consumer contracts: **44 passed**; TypeScript checking passed.
- Gateway non-Redis quota/security selection: **passed**.
- Repository policy suite: **121 passed**; `git diff --check` passed.

The local Redis/PostgreSQL integration rerun remains environment-limited because
Docker Desktop started but its engine API did not become responsive. The PR's
Linux CI jobs for Agent, Gateway, Backend PostgreSQL Integration, and Security
Scans are therefore mandatory before reviewers approve the merged head.

### Second compatibility refresh

Before final review, `align/master` advanced again through `a056efd` (ENT-018
service request signing v2) and `5ff6f4b` (verified gateway database TLS). The
branch merged both commits. Git reported one textual conflict in
`services/agent/main.py`: the upstream control-plane authentication import
overlapped the request-context import used by this remediation. Resolution kept
the upstream `authenticate_control_plane` API and retained
`get_current_request_id`; no security behavior was dropped.

Fresh combined verification after that resolution:

- Agent compatibility selection: **90 passed, 6 environment-dependent skips,
  56 subtests passed**;
- repository and security policy suites: **130 passed**;
- console service-signing and UI contracts: **45 passed**;
- gateway database TLS/configuration targeted selection: **passed**;
- Python compilation and `git diff --check`: **passed**.

The complete local gateway selection could not pass without Redis: its
Redis-backed audit recovery case failed to connect to `localhost:6379`. This is
recorded as an environment limitation, not a test pass; the PR Gateway Redis job
remains required. A fresh local containerized Gitleaks attempt also could not
start because the Docker engine did not respond, so the new PR-head Security
Scans result remains mandatory.

## Agent separation-of-duties remediation verification

A post-review finding identified two agent-side fail-open paths: missing
requester context on document approvals and mismatched OIDC `email`/`sub`
identity comparison. The remediation adds these controls:

- approval creation rejects missing requester, tenant, or request context before
  persistence;
- new approvals persist canonical `requested_by` in a dedicated, non-updatable
  field, while the metadata copy is retained only for historical compatibility;
- approval decisions require a canonical OIDC `sub`, require exact non-null
  tenant binding, reject requester-less historical records before MFA, and
  compare the requester against authenticated `sub`, `user_id`, and `email`
  aliases;
- document upload/scan, remediation, and graph callers propagate authenticated
  requester context; autonomous monitoring uses `service:document-monitor`;
- a human-triggered connector sync propagates that human's `sub` and cannot be
  attributed to the autonomous monitor service.

Fresh pre-fix characterization produced **8 failures** covering canonical actor
selection, missing-requester behavior, required creation context, and document
override propagation. After remediation:

- focused agent separation-of-duties and caller compatibility selection:
  **39 passed, 19 subtests passed**;
- exact Agent CI selection: **84 passed, 5 Redis-dependent tests skipped,
  41 subtests passed**;
- repository policy suite: **121 passed**;
- targeted Python compilation and `git diff --check`: **passed**.

The focused cases cover distinct opaque `sub` and email values, historical
email aliases, missing requester before MFA, a valid distinct approver, missing
and cross-tenant context, immutable requester mutation attempts, graph state,
manual and autonomous monitor attribution, and document approval linkage.

The legacy `tests/test_document_intelligence.py` database selection was not
claimed as passing locally: its two pure tests passed, while two database cases
stopped during fixture setup because the local database lacked the document
tables. The PR's PostgreSQL integration and migration checks remain required.

## Approval atomicity and audit durability remediation (2026-09-18)

The final candidate working tree based on `b0b33c429f62e5cb59078ffb63e3c50cf446bf69`
closes the follow-up approval-integrity findings:

- graph workflow creation persists the authenticated requester and start,
  resume, recovery, and remediation fail closed when immutable requester
  provenance is unavailable;
- remediation preserves the original workflow requester and records the
  current remediation initiator separately;
- approval and rejection are tenant-scoped pending-only database
  compare-and-swap transitions; approval expiry is rechecked in the same
  transaction after MFA;
- approval creation, expiry, execution start, and both terminal execution
  outcomes commit canonical approval audit evidence in the same transaction as
  their state transition; process cache entries update only after commit;
- approval persistence failures propagate. Document scanning returns an
  unavailable response rather than converting a failed high-risk approval into
  a low-risk completed fallback.

Fresh local verification:

```text
backend ENT-022 security: 10 passed
backend workflow/remediation regression: 24 passed, 1 unrelated pre-existing test deselected
agent authorization/atomicity: 26 passed
exact Agent CI selection: 95 passed, 6 environment-dependent skips, 56 subtests passed
targeted Python compilation: passed
git diff --check: passed
focused forbidden-MFA-default scan: no matches
```

The agent transaction tests cover duplicate approval, expiry during MFA,
creation persistence failure, approval-audit rollback, execution-start audit
rollback, and successful/failed terminal-state audit rollback. They use a
deterministic transactional fake to exercise the application contract. A live
PostgreSQL/RLS concurrency rerun is **not** claimed: Docker was unavailable and
the repository's destructive agent pytest database bootstrap could not create
its database under the available local role. The PR's PostgreSQL integration
job remains mandatory.

The focused production/configuration scan found no static MFA default, test MFA
bypass flag, quoted `123456`, or non-empty lite-demo TOTP assignment. Gitleaks
was not available locally and Docker was not running, so the earlier full-tree
Gitleaks result is not asserted against this final candidate diff. The current
PR-head Security Scans job must pass before merge.

## Deployment and rollback consequences

1. Apply backend migration `050` before deploying backend code. The backend startup gate intentionally accepts only revision `050`; new code reads the added columns and must not run against `049`.
2. Agent startup migration adds global counter and lockout columns plus the additive
   `gateway_approvals.requested_by` column before serving approval traffic.
3. The old `/v1/workflows/mfa/setup` path now returns HTTP 410. Clients must use `/v1/users/me/mfa/setup`, then `/v1/users/me/mfa/confirm`.
4. Deploy backend, agent, and console together so enrollment state and BFF routes remain compatible.
5. Roll back application code without downgrading `050`; the columns are additive. Downgrade only after confirming no pending enrollments or replay counters must be retained.

## Review obligations

Authentication, API/schema, agent, and console boundaries changed. Per `CONTRIBUTING.md` and `CODEOWNERS`, merge still requires independent component/consumer review, security risk-owner review, current-head approvals, the CI Gitleaks result, and any applicable line-growth evidence marker. No approval or completion claim is made here.
