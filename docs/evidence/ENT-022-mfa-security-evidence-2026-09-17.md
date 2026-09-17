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

## Deployment and rollback consequences

1. Apply backend migration `050` before deploying backend code. The backend startup gate intentionally accepts only revision `050`; new code reads the added columns and must not run against `049`.
2. Agent startup migration adds global counter and lockout columns before serving approval traffic.
3. The old `/v1/workflows/mfa/setup` path now returns HTTP 410. Clients must use `/v1/users/me/mfa/setup`, then `/v1/users/me/mfa/confirm`.
4. Deploy backend, agent, and console together so enrollment state and BFF routes remain compatible.
5. Roll back application code without downgrading `050`; the columns are additive. Downgrade only after confirming no pending enrollments or replay counters must be retained.

## Review obligations

Authentication, API/schema, agent, and console boundaries changed. Per `CONTRIBUTING.md` and `CODEOWNERS`, merge still requires independent component/consumer review, security risk-owner review, current-head approvals, the CI Gitleaks result, and any applicable line-growth evidence marker. No approval or completion claim is made here.
