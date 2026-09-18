# ENT-019: truthful telemetry verification

## Scope and reuse

The specification review of PR 60 at `5f4dab35` identified eleven confirmed
defects. This follow-up integrates `align/master` at `a8822e5` in the approved
isolated worktree, preserving the original checkout's unrelated invitation/debug
edits. The canonical repository remains VidhiTF/AuthClaw_Align.

T01 activation was freshly verified with
`python scripts/repository_policy.py --verify-github`: reviewed
`b8b23993a7a467396598eefdd23b97da83d47042`, merged
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
2026-09-16T12:57:25Z, active ruleset 21141288, zero bypass actors.

Reuse decisions made before implementation:

- Reuse master's qualified-evidence lifecycle, immutable review audit, policy
  fingerprint, repeatable-read inputs and atomic snapshot upserts. Do not build
  another assessment workflow or convert operational activity into compliance.
- Extend the existing agent scorer, nullable migration, report serializers,
  queue classifier and health aggregator. No new production service/dependency.
- Extend the existing authenticated audit endpoint with one server-side aggregate:
  a bounded page or mirror-specific transport key cannot establish complete metrics.
- Reuse independent fetch results and existing score formatting in console consumers.
- New production lines are limited to these missing validation/state/transaction
  branches, the aggregate query and nullable migration 052.

## Finding disposition and contract

| Review finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| Agent current score persists zero for no evidence | Empty controls persist NULL, explicit unknown reason; no-evidence legacy 0/100 rows repaired, measured zero retained | Agent telemetry + restricted PostgreSQL migration test |
| Auditor defaults LOW/completed | JSON/CSV/PDF use UNKNOWN for absent risk/status | Auditor export unit and tenant report integration |
| ClickHouse representation loses P99 | Dashboard latency aggregates authoritative PostgreSQL provider outcomes; recent mirror records cannot change it | PostgreSQL aggregate + console source-shape tests |
| Product activity awards compliance | Only current, independently reviewed, integrity-checked control evidence qualifies; missing/stale/untrusted/unknown is NULL, validated failure is zero | Backend assessment/scoring + real review/MFA/RLS tests |
| Truncated/all-event dashboard counts | Full selected 1–720-hour window; distinct gateway request IDs, no admin/attempt duplication; completeness metadata | 201 outcomes plus attempts/admin/cross-tenant/out-of-window SQL fixture |
| All-or-nothing console loading | Independent source/metric states; successful sources retained, failed-source stale values cleared; unknown latency remains unknown | Partial failure, recovery, race and five-state rendering tests |
| Legacy writer incompatible with tenant RLS | Omitted tenant defaults only from authenticated transaction context; contextless/forged/cross-tenant writes rejected | Actual restricted-role old-shape INSERTs after migration |
| Partial/racy snapshots | Reuse one atomic all-framework batch, native upsert and tenant/version lock shared by single/batch writers | Real SQL failure rollback and concurrent first-write tests |
| Unknown chain logged failed | True/False/None audit outcomes logged passed/failed/unknown | Actual endpoint function regression |
| Malformed queue/config escapes | Invalid configuration unavailable; malformed container/counters unknown; measured dead letters stay degraded | Unit cases and authenticated endpoint integration |
| Misleading score timestamp | Trusted selected observation times plus one consistent `inputs_as_of`; missing observation time stays NULL | Assessment provenance tests |

Health precedence is `unavailable > degraded > unknown > healthy >
not_applicable`. Missing observations cannot become success; measured failures
outrank unknowns. Basic liveness says `alive`, not that dependent systems are
healthy. Successful diagnostics still do not certify compliance.

Backend UUID tenant context and agent integer tenant context remain separate,
explicit contracts. Agent scores are capped, non-authoritative activity diagnostics,
not interchangeable backend assessments. Master's retirement of the old aggregate
drift writer is retained; compatibility hooks cannot create new compliance posture.
Operational reports are tenant-bound and explicitly unassessed.

The authoritative audit aggregate counts distinct observed gateway request IDs
(including denied/in-flight requests), not all audit events. P99 uses completed
provider outcomes only and preserves actual zero milliseconds. Missing legacy
request identity marks request totals incomplete/unknown, not silently complete.
A healthy source with no latency observation returns unknown latency.

The independently reviewed candidate also fixed a duplicate `compliance_status`
key, and selective migration repairs old unobserved scores. Consumer review found
nullable trust-summary/public-share fields, which now render Unknown instead of
a bare percent or misleading zero. Shared templates preserve provenance labels.

## Fresh verification (2026-09-18)

No application's database, running container or external mail service was used for
destructive/outage tests. PostgreSQL 16 and Redis test containers use isolated
loopback ports; PostgreSQL suites create and remove UUID-named test databases.

- Backend scoring, assessment, policy, trust, API and migration-chain selection:
  **125 passed**.
- Full backend CI unit selection: **508 passed**.
- Backend PostgreSQL lifecycle/concurrency/migration/public-share/MFA plus audit
  aggregates: **25 passed, zero skips**. Tests use separate owner, restricted
  migrator and non-bypass runtime roles. Synthetic performance rehearsal enabled:
  five qualification queries, approximately 128 ms for a 100-assessment fixture
  on the first isolated run; this is not a production SLO.
- Agent CI-equivalent selection: **122 passed, 84 subtests passed**. This includes
  real middleware, two tenants, old/new writer SQL, forced RLS, legacy backfill,
  concurrent scoring, transaction rollback, source recovery, real report exports,
  interleaved tenant audit chains and cloud-worker behavior.
- Full agent unittest smoke discovery: **119 passed**.
- Enabled ClickHouse outage tests use loopback HTTP for failed probe, failure
  after successful probe, malformed aggregate and recovery; fallback is real
  PostgreSQL. Both-source failure remains sanitized HTTP 503.
- Queue/telemetry regressions distinguish absent/malformed/future/stale checkpoints,
  invalid thresholds, measured zero, unknown chain and unavailable dependencies.
  Local SMTP receiver checks actual delivery; failure tests never send external mail.
- Console: **53 unit tests passed**, TypeScript passed; full ESLint had zero
  errors and 14 existing internal-navigation warnings. Webpack production build
  passed; Docker's normal Turbopack build passed. The existing dashboard HTML
  export was regenerated from the current rendered outage component. JSON samples
  and HTML are synthetic contract examples, not deployed-production evidence.
- Actual built Next.js/BFF browser checks passed on Chromium at 1440x1050 and
  390x844, using isolated loopback authentication/telemetry fixtures: partial
  source loss, true 0 ms, recovery, refresh/range changes and public auditor
  overall/framework/control Unknown rendering. Page identity, meaningful content,
  absence of framework overlays and interaction assertions passed; no JavaScript
  runtime errors, only expected injected 503 responses. Existing Playwright was
  used because the Browser plugin runtime was unavailable; no dependency added.
  Temporary scripts, screenshots and loopback servers were removed afterward.
- Backend, agent, gateway and console images rebuilt from this isolated worktree.
  The rebuilt agent passed **25 focused tests** in read-only, network-isolated
  containers with only the test directory mounted; production code came from the
  image. Running application containers were not recreated.
- Compose/repository policy unit selection: **27 passed**. Gateway schema-revision
  test passed. Python compilation, diff whitespace and Tokei line-budget checks passed.

Representative commands (from this worktree; use disposable test URLs):

```powershell
python -m pytest --noconftest -p no:cacheprovider backend/tests/test_compliance_scoring.py backend/tests/test_control_assessments.py backend/tests/test_compliance_policy.py backend/tests/test_trust_center.py backend/tests/test_t10_api_contract.py backend/tests/test_migration_chain.py -q
# backend working directory; owner/runtime/migrator test URLs required:
python -m pytest --noconftest -p no:cacheprovider tests/test_t10_postgres.py tests/test_audit_metrics.py -q
# Exact agent selection and service prerequisites are maintained in .github/workflows/ci.yml.
# services/agent working directory:
python -m unittest discover -s smoke_tests -p 'test_*.py' -q
tokei backend/app gateway audit_consumer console/src --output json | python scripts/check_line_budget.py
```

The backend aggregate test is included in the PostgreSQL CI job. Agent regression
tests are included in the existing Agent CI selection. Tests no longer assume the
retired legacy drift writer provides authoritative posture.

Verification corrections are retained here, not hidden as passes: initial smoke
discovery from the repository root used the wrong Python import root; rerunning
from services/agent passed. Windows connections to the deliberately unreachable
backend unit-test port stalled without a timeout; adding connect_timeout=2 to
the test-only URLs produced the 508-pass run. An initial worktree Turbopack build
rejected the external node_modules junction; webpack and the isolated Docker
Turbopack build passed. Image test discovery initially omitted the intentionally
excluded test directory; mounting tests read-only fixed the harness. Existing
dependency deprecation warnings were not suppressed or reclassified.

## Simplification and growth

Compared with current master, production Python/Go/TypeScript and migration 052
have 630 added / 486 deleted physical lines (net +144), using git numstat with
end-of-line whitespace ignored; tests, configuration and prose are excluded.
The dashboard route is 23 lines smaller and agent main is 53 lines smaller.
Removed obsolete fallback branches, retired aggregate-writer behavior, duplicate
metadata/status assignments and repeated state handling. Correctness additions
were kept rather than code-golfed. This is not a claim of net reduction overall.

Positive per-file non-prose growth exceeds the 100-line review threshold, primarily
because retained regression/integration tests cover independent failure, tenant
and concurrency boundaries. The required owner exception is still pending.
Tokei passed every configured 10,000-code-line per-file budget; the largest file
in the measured scopes was 2,124 code lines.

## Rollout, data integrity and rollback

1. Deploy null-aware console/readers before enabling nullable score writers.
2. Run backend Alembic upgrade to 052 and the existing agent migration job before
   starting new backend/agent writers. New backend requires 052; gateway accepts
   051/052 for a bounded rollout. A previous backend can continue using its old
   supported revision until replacement; do not bypass its startup revision guard.
3. Agent migration preserves unattributed legacy history without assigning it to
   a guessed tenant. New legacy-shape writes bind only to authenticated tenant
   context. FORCE RLS remains mandatory.
4. Repair only current agent rows whose evidence_count is zero. Migration takes
   the table's transactional DDL lock, temporarily removes owner FORCE, updates
   unknown values, restores FORCE and commits atomically. Concurrent runtimes
   cannot observe an unenforced intermediate state; errors roll back the DDL.
5. Preserve nullable storage on rollback. Migration 052 downgrade deliberately
   keeps NULL-compatible storage rather than corrupting unknown to zero. Do not
   restore old readers that treat NULL as numeric or re-enable retired activity
   compliance claims. Historical backend versions remain labeled and separate.

Source failure returns an unavailable response rather than pretending persisted
history is fresh. A database outage cannot persist a new marker in that same
database; clients must honor the response state. Unknown transitions with reachable
storage persist a NULL snapshot and an atomic notification.

## Remaining release boundaries

Live AWS deployment/outage, managed alert delivery, remote CI for the eventual
commit, and renewed independent human component/security/consumer approvals remain
release evidence. Local tests and independent AI review do not satisfy those
approvals. Material test growth needs the existing line-growth owner exception.

Architectural suggestions are not new feature scope: backend/agent identifiers
remain separate, agent SMTP remains operator-configured, and broader caching or
trust-health inventory changes need their own contract. Full Compose's agent
ClickHouse HTTP default is not a successful connectivity claim; operators must
configure the actual reachable authenticated endpoint or explicitly disable the
optional mirror. Its unavailable state and PostgreSQL fallback are tested.

Verification above was completed before publication. PR merge and deployment
remain separate; the running application's deployment was not changed.
