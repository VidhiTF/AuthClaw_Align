# ENT-022 privileged MFA implementation evidence

Date: 2026-09-17
Branch: `security/ent-022-privileged-mfa`
Repository baseline: `align/master` at `45976f0`

## Final pre-push credential-rotation review (2026-09-21)

A fresh security-diff architecture pass found one surviving credential race in
the uncommitted reviewer-remediation tree: API-key rotation serialized on the
acting user's row, but two different tenant owners lock different user rows and
could both read the same old API key as active. That could create two active
rotation descendants from one credential.

Rotation now acquires a PostgreSQL `FOR UPDATE` lock on the tenant-qualified
target API-key row before checking active/revoked/rotated state. Different owners
therefore serialize on the credential itself; the second transaction observes
the committed inactive/rotated state and is rejected. The existing interactive
session, fresh MFA, tenant predicate/RLS, one-time plaintext response, and atomic
credential-audit transaction remain unchanged.

Fresh focused verification:

```text
AUTHCLAW_ENV=test backend/.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q \
  tests/test_ent022_mfa_security.py tests/test_auth_baseline.py
72 passed, 0 skipped, 31 warnings in 4.02s
```

The regression test requires the target-key query to use `with_for_update()` and
confirms the old key is deactivated. The prior invocation with the host's stale
`AUTHCLAW_ENV=demo` was rejected during collection by the production-environment
guard; rerunning with the explicit supported test environment passed. A new
current-head CI run and human owner/risk approvals remain mandatory after push.

Additional final-tree checks:

- Agent CI authorization/policy selection, including the new privileged-policy
  invariant file: **126 passed, 15 environment-gated skips, 71 subtests passed**.
- Console unit contracts: **52 passed**; TypeScript passed; ESLint reported
  **0 errors and 14 pre-existing navigation warnings**.
- Repository policy selection: **122 passed**.
- T01 live activation verifier: active PR #52 / reviewed `b8b239` / merged
  `1e40bdb5c8fd6b4e28c827035ab7d06645530ccb` / effective
  `2026-09-16T12:57:25Z`; ruleset 21141288 active with zero bypass actors.

The exact backend CI selection was also started locally after the focused pass,
but without the disposed Redis/PostgreSQL services its timeout-path cases reached
only 10% after ten minutes. It was stopped and is not reported as a pass or
failure. The earlier disposable-service results below remain the integration
evidence; the pushed current-head CI run must supersede them.

## Docker-backed final local verification (2026-09-21)

The verified working-tree base is `93c8531d2ef88e4d20bfc9f88111dbea0f332e73`.
The tree remains uncommitted, so it has no immutable final commit SHA yet; these
results bind to that base plus the current diff and must be repeated by current-head
CI after commit. T01 activation verification passed against GitHub: PR #52, reviewed
head `b8b23993a7a467396598eefdd23b97da83d47042`, merged commit
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
`2026-09-16T12:57:25Z`, active ruleset 21141288, zero bypass actors.

Docker Desktop 4.82.0 / Engine 29.6.1 ran isolated disposable PostgreSQL 16.10
and Redis 7.4.7 containers on non-default host ports. `TEST_OWNER_DATABASE_URL`,
`TEST_DATABASE_URL`, `OWNER_DATABASE_URL`, and `DATABASE_URL` all explicitly
targeted `authclaw_local_test`; the runtime role was restricted and migrations used
the dedicated migrator role. No development or production database was used and no
safety guard was bypassed.

Fresh results on the current working tree:

```text
backend/.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q tests/test_mfa_recovery_postgres.py
8 passed, 0 skipped, 110 warnings in 23.70s

Exact Backend PostgreSQL Integration pytest selection from .github/workflows/ci.yml
137 passed, 1 skipped, 0 failed, 677 warnings in 264.88s
The sole skip is the existing opt-in synthetic performance measurement; no MFA,
PostgreSQL, Redis, recovery, race, rollback, or tenant-isolation case skipped.

Focused backend MFA/API-key authorization selection
136 passed, 0 skipped, 31 warnings in 16.28s

Agent authorization, PostgreSQL MFA, and privileged-policy selection
46 passed, 0 skipped, 26 subtests passed in 16.06s

Console unit contracts: 52 passed
Console TypeScript: passed
Changed settings-page ESLint: 0 errors, 4 pre-existing navigation warnings
Repository-policy unit tests: 27 passed
Tokei 12.1.2 archive SHA-256 verified; repository line-budget gate: passed
```

The Docker run reproduced the pushed-head PostgreSQL failures before correction:
stale ORM identity-map state left workflow responses at `PENDING`, the concurrent
gateway loser could return a non-success response while the durable winner remained
correct, and the real-MFA test adapter returned the old Redis reset-script contract.
ORM synchronization now follows each status-qualified database transition; the race
asserts exactly one successful durable transition and one audit row; the test adapter
models the current atomic cooldown reset result. Recovery evidence separately proves
that machine credentials are denied API-key administration before mutation, while
interactive-session issuance and rotation remain serialized against recovery.

## PR #58 final review remediation (2026-09-21)

The four reported findings at reviewed head `ff78de4dccf9d59821e00cee6c3971881410189d`
were rechecked against the active branch and closed without introducing a second
MFA verifier, approval authority, or audit transport.

- Privileged dispatch now writes a unique operation identifier and reconciliation
  deadline in the same transaction as the `executing` state and canonical audit.
  Gateway and remediation execution receive that stable idempotency identity.
  Provider identifiers and bounded non-secret outcomes are retained on terminal
  transitions. Unknown provider outcomes are never reported as success; they
  become `execution_indeterminate`, and abandoned dispatches are lazily reconciled
  to the same explicit state with durable `manual_reconciliation_required` audit.
- Policy loading rejects disabled MFA or separation of duties in every shared or
  production-like environment. The exception is limited to explicitly named
  local/test environments; an unset environment fails closed.
- API-key issuance and rotation now require an interactive user session plus a
  fresh factor through the existing replay, rate-limit, and lockout controls.
  The user row lock keeps recovery and credential administration serialized.
  Key mutation and a non-secret credential-administration audit/outbox row commit
  atomically. MFA input uses `SecretStr` and neither the code nor raw key is audited.
- The earlier rejection race/audit finding was already corrected on the active
  branch: pending and unexpired conditions are enforced by the database transition,
  with state and immutable audit committed together.

Fresh local evidence for this final working tree:

```text
T01 activation verifier: active; PR #52; reviewed b8b239; merged 1e40bdb5c8fd6b4e28c827035ab7d06645530ccb; effective 2026-09-16T12:57:25Z
backend MFA/auth/abuse selection: 125 passed, 4 environment-gated skips
agent authorization/policy/provider selection: 39 passed, 29 subtests passed
console TypeScript: passed
console changed-file ESLint: 0 errors, 4 pre-existing window.location warnings
Tokei 12.1.2 line-budget gate: passed
Python compilation and git diff --check: passed
Gitleaks 8.24.3 PR range, working diff, and new-file scans: no leaks
```

The PostgreSQL recovery selection was intentionally refused by its safety guard
because this host has no explicit `TEST_OWNER_DATABASE_URL` and
`TEST_DATABASE_URL` ending in `_test`; eight cases did not execute. Docker is not
available to provision the disposable database. The PR's current-head PostgreSQL,
Redis, secret-scan, and independent owner/risk review gates remain mandatory and
are not represented as locally satisfied.

## Review finding remediation (2026-09-21)

The final review findings were reproduced from the reported source paths and
closed in the existing approval, abuse-control, request-authentication, console
signing, and audit seams. No additional factor store or approval state machine
was introduced.

- Backend gateway and workflow approve/reject/expiry transitions now use
  tenant-scoped, status-and-expiry-qualified `UPDATE ... RETURNING` operations.
  Expiry, workflow synchronization, and immutable approval audit insertion are
  committed in the same transaction. An approval that expires while MFA is
  being verified cannot transition to approved.
- Agent rejection now rejects only an unexpired pending record. If the decision
  arrives after expiry, the same transaction records `expired` state and its
  immutable audit event; it cannot overwrite approval or execution consumption.
- A successful MFA verification rechecks the Redis cooldown atomically before
  clearing attempt state. A request admitted before a concurrent lockout now
  returns 429 and leaves that cooldown intact.
- Validated API keys now produce a non-secret immutable approval requester
  subject (`api-key:<sha256>`). Existing quota accounting deliberately remains
  on the shared `service:tenant` bucket; the full Agent CI selection caught and
  verified this compatibility boundary.
- The production console exposes authenticated approve and execute BFF routes.
  The route removes the MFA code, obtains the body/action-bound backend
  assertion, and uses the existing HMAC-v3 agent signer.
- Backend assertion audit persistence now places assertion ID, operation, and
  body SHA-256 in canonical `execution_trace`; the PostgreSQL readback test
  asserts all three bindings. Gateway rejection now inserts tenant-bound
  immutable `REJECTED` evidence in the transition transaction.

Fresh current-working-tree evidence:

```text
T01 live activation verifier: active; PR #52; merged 1e40bdb5c8fd6b4e28c827035ab7d06645530ccb
backend focused MFA/abuse selection: 20 passed, 4 environment-gated skips
agent exact CI selection: 120 passed, 15 environment-gated skips, 60 subtests passed
console unit/contract selection: 52 passed
console lint: 0 errors, 14 pre-existing warnings
console TypeScript and production build: passed; privileged BFF route present in route manifest
repository-policy unit tests: 27 passed
Gitleaks 8.24.3 full working-tree scan: 944.52 MB scanned, no leaks found
Tokei 12.1.2 line-budget gate: passed
Python compile and git diff --check: passed
```

The new deterministic abuse test proves a success admitted before lockout cannot
clear that lockout. The new route contract invokes both production BFF stages.
The new API-key test proves the requester is stable and non-secret while quota
behavior is unchanged. The PostgreSQL tests cover expiry-during-MFA,
approve/reject/expire races, gateway rejection audit readback, agent rejection
after expiry, and durable assertion binding readback.

This Windows host has PostgreSQL running but no authorized disposable-test owner
credentials, and no Redis service. Consequently the new real PostgreSQL cases
were collected but skipped locally, and the exact database suite refused to run
without explicit `_test` URLs as designed. The broad backend selection was
stopped at the unavailable live-service boundary and is not claimed as a pass.
PR CI must run the PostgreSQL/Redis cases and the independent current-head
security scan before approval. No human approval, merge readiness, or zero-risk
claim is inferred from local evidence.

## Interactive-credential recovery follow-up (2026-09-18)

The reported API-key recovery takeover was confirmed: the generic tenant
dependency mapped an active key's creator to the user, and owner recovery left
that key usable for factor enrollment. The new credential-purpose matrix failed
all 18 cases before the patch because no session-only boundary existed.

The existing tenant binder is now reusable for post-lock revalidation, matching
both immutable user and tenant IDs. All five MFA lifecycle mutations and agent
assertion issuance require a tenant session. Recovery revokes target-owned API
keys as well as sessions in the same factor/audit transaction. API-key issuance
and rotation acquire the creator lock and revalidate, preventing a waiting
request from minting a surviving key after recovery. Existing tenant RLS,
encryption, factor verification, Redis controls and outbox append are reused;
there is no new migration, factor authority or credential protocol.

The real database test also demonstrated that top-level `subject_id` was not
part of the canonical persisted audit payload. Lifecycle events now include the
subject in the existing `execution_trace` field, preserving both recovery actor
and target without changing the audit schema.

Fresh verification on this patch before latest-master integration:

- Full Backend Security and Compliance CI selection: **538 passed**, no skips.
- `pytest -p no:cacheprovider -q tests/test_mfa_recovery_postgres.py`:
  **8 passed**, real migrated PostgreSQL with restricted runtime RLS and Redis.
  Six cases observe actual PostgreSQL lock waits before recovery commits, then
  require 401 for stale session/key requests. HTTP cases require 403 for active
  API keys on every MFA mutation/assertion endpoint, 401 after revocation,
  target-only credential invalidation, cross-tenant 404, durable actor/target
  audit, and rollback after an actual SQL audit-write error. A fresh session
  completes enrollment, confirmation, recovery-code rotation and assertion.
- Recovery plus `test_agent_mfa_assertion_postgres.py`: **9 passed**; the latter
  includes three console-signed agent approval/execution timezone scenarios.
- `python -m unittest scripts.test_repository_policy -q`: **27 passed**.
- Python compilation, `git diff --check`, Tokei 12.1.2 line budgets: **passed**.
- Gitleaks 8.24.3 `dir . --config .gitleaks.toml --redact`: **no leaks**,
  893,488,887 bytes scanned. The final pushed head still requires its own CI scan.

Actual synthetic recovery audit rows are emitted as `backend-recovery-audit.json`
and uploaded by CI with the checkout SHA/run in the artifact name. They are test
evidence, not production audit records. The independent candidate source reviewer
reported no concrete surviving bypass/regression; its local test process was
permission-blocked, so executable evidence above comes from the implementer.

Compatibility work is separately recorded: the first legacy HTTP invocation
used a noncanonical definer role and correctly failed startup. After fixing only
the disposable test setup, seven cases passed and the workflow approval case
failed its final COMPLETE-state assertion. Master concurrently advanced to
`1a3970c` (workflow response contracts), creating PR conflicts. Integration and
post-integration results supersede this preliminary compatibility result below.

Final integrated verification against master `1a3970c`:

- Full Backend Security and Compliance CI selection: **649 passed**, no skips.
- Existing `test_endpoints.py` plus `test_phase10.py` in a freshly migrated
  disposable database: **13 passed**, no skips.
- Merged workflow response contract/HTTP tests: **99 passed** (also included in
  the 649 above). Incoming fixtures now provide required requester IDs and use
  a separate approver; no production security guard was relaxed.
- Recovery and signed cross-service PostgreSQL/Redis tests: **9 passed** again,
  including the six observed lock waits and three child agent timezone cases.
- The legacy HTTP failure was the owner test session's cached workflow object,
  not the response or durable transition: the probe observed APPROVED consumption
  and EXECUTE_REMEDIATION. Expiring that fixture's cached state after session
  provisioning made both original database assertions and HTTP tests pass.
- The only textual merge conflict was the workflow typing-import block. The
  merged code retains the incoming response types and does not restore retired
  one-step MFA enrollment. The final immutable source archive and CI results are
  linked to the pushed SHA in PR #58; earlier scan results are not substituted.

CI run `35346052709` passed all selected technical jobs except one PostgreSQL
fixture: `test_request_dependency_uses_single_connection_and_resets_write_isolation`
provided no authenticated user ID. The now-required canonical actor comparison
correctly rejected it. Its fixture now supplies the actual identity's user ID;
the complete local `test_t10_postgres.py` rerun is **18 passed, 1 skipped**. The
skip is the existing opt-in synthetic performance measurement, not an MFA test.
The previous CI PostgreSQL selection was **133 passed, 1 failed, 1 skipped**;
this failure is retained here and is superseded only by the final-head rerun.
No production code changed in this final fixture correction.

Operational consequences: recovery invalidates all target-owned API keys,
including integrations, which need newly issued keys. Deploy all backend workers
before treating the new policy as effective. Rolling back would reopen the
reported boundary; prefer roll-forward and never reactivate revoked keys.
Already-issued agent assertions retain their existing maximum 60-second lifetime
and single-use rules; immediate cross-service assertion revocation is not claimed.
The optional console factor-replacement UX suggestion is not changed here.

## Current verification scope (2026-09-18 follow-up)

The earlier sections below are historical results, not claims about the newest
commit. Current master compatibility includes `a8822e5`; backend migrations are
`050` (T10), `051` (shared durable MFA replay), and `052` (pending enrollment).
The current-head CI run linked in PR #58 is authoritative for its secret scan,
component checks, and required human review gates.

The reported opaque-UUID factor lookup was already fixed by the control-plane
MFA assertion protocol at `54d5d6b`. A fresh investigation traced backend factor
verification, the console signer, tenant mapping, and both agent action handlers.
No second factor store or user synchronization was added. The follow-up reuses
those implementations and replaces helper-only proof with HTTP integration.

The stronger test exposed an additional confirmed defect: PostgreSQL converts an
aware datetime to its session timezone when storing it in the agent's existing
timezone-less timestamp columns. A fresh approval under Los Angeles session time
returned HTTP 200, but execution immediately returned HTTP 400 because its window
appeared expired. `approval_store._parse_optional_dt` now normalizes every write
and atomic-transition comparison to UTC wall time, matching the existing read
contract. This changes no schema and adds no parallel timestamp helper.

Fresh local results for this follow-up:

- Full Agent CI selection: **130 passed, 60 subtests passed**, no skips.
- Backend auth, MFA replay/lifecycle, real-Redis abuse and migration selection:
  **99 passed**, no skips.
- `backend/tests/test_agent_mfa_assertion_postgres.py`: **1 passed**, including
  three child HTTP scenarios under UTC, America/Los_Angeles, and Asia/Kolkata.
- Repository-policy unit tests: **27 passed**; Python compilation and
  `git diff --check`: **passed**.
- Console signer/client contracts: **8 passed**; Tokei 12.1.2 line budget: **PASS**.
- Gitleaks 8.24.3 full working-tree scan with `.gitleaks.toml` and redaction:
  **PASS**, approximately 893.17 MB scanned, no leaks. The final commit's separate
  CI Security Scans result must also pass before merge.

The cross-service test creates a real backend UUID user in a fully migrated
disposable PostgreSQL database, uses encrypted enrollment and valid TOTP through
the production assertion endpoint function and Redis abuse controls, verifies
TOTP replay rejection, and preserves the two durable backend issuance events.
The actual console TypeScript signer supplies the assertions to the actual agent
ASGI middleware and `/approve/*` and `/execute/*` handlers. No agent-local
`tenant_users` table or factor exists in that scenario. Three durable agent audit
events (`approved`, `executing`, `executed`) retain the backend actor UUID and
`mfa_verified=true`. CI uploads these actual test rows as JSON artifacts bound to
its checkout SHA/run, never as production audit evidence.

Agent coverage also denies request replay, re-signed assertion replay, altered
body/stage, viewer role, and cross-tenant access. Real PostgreSQL concurrent
decisions produce exactly one winner and one audit row. A database constraint
rejecting the execution audit insert proves the state transition rolls back.
These checks run in all three database timezones. Each timezone is an independent
deployment rehearsal; only its own random assertion replay keys are cleaned up
after the replay-denial assertions.

Limits: the backend uses its migrated authenticated RLS harness; agent approval
tables use a minimal FORCE-RLS schema and non-superuser/NOBYPASSRLS role, with the
production tenant-upsert function transplanted into that schema. Agent deployment
grants and signed database-context functions are not proven by this test. Quota,
provider execution, and legacy blockchain adapters are substituted; canonical
approval state/audit transactions, request authentication, MFA and replay controls
are real. This is not a browser interaction or deployed-system test.

Failed attempts are retained in the test narrative: the initial HTTP test exposed
the timestamp defect; the first cross-service parameterization incorrectly reused
consumed assertion IDs across independent timezone scenarios (corrected fixture
cleanup); an initial backend test invocation inherited unsupported `demo` mode
and was rerun with explicit `AUTHCLAW_ENV=test`. No production guard was weakened.
The isolated backend replay fixture initially failed on the new pending-backup
ARRAY column; it now maps both backup columns to SQLite JSON, while PostgreSQL
coverage remains real. A Windows connection stall against the intentionally
unavailable unit-test audit database was diagnosed with a Python stack dump;
rerunning with a two-second test-DSN connection timeout completed all 99 cases.

Rollback: revert the follow-up application change only if a verified regression
requires it; retain migrations `051`/`052`. Historical timezone-shifted timestamps
cannot be reliably reconstructed without their original session timezone. Expire
and re-request affected historical approvals through the normal workflow; do not
extend windows or rewrite audit timestamps speculatively.

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
- Backend migration chain: the original ENT-022 `050` rehearsal passed over `049`. After compatibility integration with T10, master owns `050`/`051`; ENT-022 pending-enrollment state is revision `052` over the shared durable replay column from `051`.
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

## Control-plane MFA assertion integration remediation (2026-09-18)

The control plane remains the credential authority. A new authenticated backend
endpoint consumes the canonical user's TOTP or recovery factor with the existing
replay and abuse controls, persists an audit-outbox event in the same transaction,
and returns only a short-lived assertion identifier and action binding. The console
removes the MFA code, then signs the assertion, immutable backend user ID, exact
agent route, and sanitized request-body digest into HMAC request version 3. The
agent accepts the assertion for at most 60 seconds and consumes its identifier
once in Redis. Agent-local JWT users continue through the existing local-factor
path and cannot inject assertion-shaped claims.

Fresh verification for this remediation:

```text
backend ENT-022 security: 11 passed
agent control-plane and approval authorization: 38 passed, 1 Redis integration skip,
  32 subtests passed
console signer/client contract: 8 passed
console TypeScript: passed
live PostgreSQL 16 / non-superuser FORCE RLS approval+execution: 1 passed
targeted Python compilation and git diff --check: passed
```

The PostgreSQL test signs an external backend UUID principal, verifies its
action/body-bound MFA assertion, performs the pending-to-approved and
approved-to-executing-to-executed transitions through the production atomic
store, confirms the three durable audit rows, and proves a second tenant cannot
read or update the approval/audit rows or insert into the first tenant. It also exposed and corrected a real
psycopg terminal-transition parameter typing error before this evidence was
recorded. CI now provisions PostgreSQL for this test; the local run used the
existing PostgreSQL 16 service and a temporary non-superuser role/schema that
the test removed afterward.

## Deployment and rollback consequences

## Final reviewer-remediation pass (2026-09-21)

The current-head preparation closed the remaining review findings without
introducing a second credential or approval implementation:

- API-key revocation now requires the same fresh, actor-bound MFA contract as
  issuance and rotation, locks the target credential row before deciding its
  state, and commits the revocation audit record atomically with the state
  transition. This prevents a rotation/revocation race from reporting success
  while leaving a rotated descendant active.
- Console DELETE requests carry the MFA body through the existing allowlisted
  BFF route instead of creating a new transport path.
- Approval reads no longer mutate an active execution to
  `execution_indeterminate` after an arbitrary wall-clock deadline. Stale
  classification remains an explicit compare-and-swap reconciliation operation,
  preventing a legitimate long-running provider call from being finalized by a
  concurrent list or detail request.
- Approved execution identity is preserved through graph state and sent to the
  gateway as both `Idempotency-Key` and `X-Request-ID`. Offline provider fallback
  is fail-closed for privileged execution, and the provider-visible operation ID
  is persisted for outcome reconciliation rather than substituting an unrelated
  local request identifier.

Fresh focused verification after these changes:

```text
backend MFA/API-key/security selection: 102 passed, 31 deprecation warnings
agent authorization/provider/graph selection: 43 passed, 21 subtests passed
agent exact CI selection after AST-isolated test seam update: 125 passed,
  15 environment-gated skips, 61 subtests passed
console unit contracts: 52 passed
console TypeScript: passed
console ESLint: 0 errors, 14 pre-existing warnings
git diff --check: passed
```

The production-line delta introduced by this final pass is small and reuses the
existing MFA verifier, transactional audit helper, approval CAS, graph state,
and gateway provider. Test growth is intentional negative/race-contract evidence.
The aggregate branch still requires the repository-generated material-growth
marker, current-head CI, and independent human approvals before merge.

1. Apply backend migrations through `052` before deploying backend code. The backend startup gate intentionally accepts only revision `052`; T10 owns `050`, durable MFA replay state is `051`, and ENT-022 pending-enrollment state is `052`.
2. Agent startup migration adds global counter and lockout columns plus the additive
   `gateway_approvals.requested_by` column before serving approval traffic.
3. The old `/v1/workflows/mfa/setup` path now returns HTTP 410. Clients must use `/v1/users/me/mfa/setup`, then `/v1/users/me/mfa/confirm`.
4. Deploy backend, agent, and console together so enrollment state and BFF routes remain compatible.
5. Roll back application code without downgrading `051`/`052`; the columns are additive. Downgrade only after confirming no pending enrollments or replay state must be retained.

## Review obligations

Authentication, API/schema, agent, and console boundaries changed. Per `CONTRIBUTING.md` and `CODEOWNERS`, merge still requires independent component/consumer review, security risk-owner review, current-head approvals, the CI Gitleaks result, and any applicable line-growth evidence marker. No approval or completion claim is made here.
