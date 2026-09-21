# ENT-019: truthful telemetry verification

## Review follow-up at bb889054

The four follow-up findings concern audit coverage, read-scope snapshot writes,
alert delivery propagation, and the 051/052 rollout boundary. Reuse the existing
canonical audit records, scope dependencies, scoring functions, tenant-bound
event delivery/retry tables, and schema guard. Do not add another telemetry or
notification subsystem. New lines are limited to enforcing these boundaries and
their failure-path tests. The code-work and fix-finding workflows required a
fresh read-only boundary investigator, one independent candidate reviewer, and
repeat regression checks. The candidate review identified the upload fallback,
scan/outbox race, and incorrect Compose service placement; all were corrected.

### Current follow-up disposition

- Gateway identities are server-owned; incoming `X-Request-ID` is bounded
  correlation metadata, not the canonical idempotency key. Connect-test
  classification still uses the original correlation value. An exact event
  retry stays idempotent; two requests with the same header remain distinct.
- A successful database query cannot detect a request lost before persistence.
  Therefore the API never labels current collection complete: total traffic,
  redactions, throughput and total-population P99 are NULL. Useful persisted-row
  measurements remain under `observations` with `persisted_gateway_events_only`
  scope. Missing legacy identities produce degraded; unproven coverage produces
  unknown; query failure produces unavailable. The dashboard explains this.
  A durable all-traffic admission/coverage ledger is not claimed or introduced.
- Compliance GETs cannot persist, even with `persist_snapshot=true`. Explicit
  POSTs to `/v1/compliance-scores` and `/v1/compliance-scores/{framework}` require
  write scope and nullable schema 052. Existing transactional snapshot/notification
  writes are reused. Callers needing history must use POST, not polling GET.
- Each scan atomically queues one tenant-bound security alert alongside its
  result. SMTP failure is persisted as dead-letter and `alert_delivery_failed`,
  exposed through document APIs and operational metrics. The existing retry
  endpoint includes queued alerts after a crash. PostgreSQL row locks serialize
  workers; delivery and scan-state repair commit together. A dispatcher failure
  leaves pending work visible. Upload errors return 503, never a fabricated
  clean scan. SMTP is at-least-once across a send-success/DB-commit crash, not an
  exactly-once mail protocol; concurrent healthy workers do not duplicate sends.
- Recipients are re-authorized on retry: active, verified tenant administrators
  only. No global ADMIN_EMAIL routing, matched secrets, filenames, or shared
  alerts.log fallback. Missing recipients/configuration is a visible failure.
- Backend rollout explicitly accepts configured `051,052`; writers remain
  disabled on 051. Full Compose passes the disabled-by-default optional
  ClickHouse setting to the agent, not the unrelated audit consumer.

### Fresh follow-up checks (2026-09-18, after bb889054)

- Backend CI unit selection: **513 passed**. Real PostgreSQL T10 lifecycle,
  read-only GET, 051/052 startup, nullable writer gate, concurrency and rollback:
  **24 passed**; PostgreSQL audit metrics: **2 passed**. No skip in these targeted
  runs. Restricted-role middleware/RLS fixtures remain separate from unit mocks.
- Agent CI selection: **122 passed, 84 subtests passed**. Final focused telemetry
  and PostgreSQL repetition: **20 passed, 8 subtests passed**. The real-DB alert
  path covers SMTP failure, API/metrics state, recipient revocation, tenant denial,
  crash recovery, immediate retry and concurrent delivery. Network-isolated
  rebuilt-agent image: **25 unittest cases passed** using image production code.
- Gateway CI selection and `go vet` passed. Full gateway suite with local
  PostgreSQL/Redis/OPA: **280 passed cases/subcases**, optional integration tests
  skipped unless enabled. Authenticated PostgreSQL audit/Bedrock tests were run
  separately and passed, including repeated correlation IDs and a fail-open
  missing outcome. TLS and legacy optional canonical-load rehearsals were not
  enabled in this follow-up.
- Console **53 unit tests**, TypeScript and production Docker build passed.
  ESLint: zero errors, 14 pre-existing navigation warnings. BrowserAct's installed
  launcher pointed to a missing Python runtime; existing Playwright was used.
  Built Next.js/BFF at localhost:3309 passed Chromium 1440x1050 and 390x844:
  correct page/title, visible coverage notice and Unknown values, no framework
  overlay or runtime errors, Refresh outage/recovery. The fixture used the actual
  backend aggregate over gateway-created PostgreSQL rows; authentication and
  unrelated endpoints were synthetic. Notice placement was corrected to preserve
  the existing metric-strip CSS during failures. The HTML export was regenerated.
- All four affected images rebuilt with separate review tags; application
  containers were not replaced. Compose contract passed; repository/release
  policy tests: **35 passed, 46 subtests**. Python compilation, diff whitespace
  and Tokei budgets passed. Test containers and temporary browser files are
  removed after verification; implementation tests and required artifacts remain.

Initial failures were corrected rather than counted as passes: a new PostgreSQL
GET fixture omitted repeatable-read setup; the replay test requires a localhost
Redis URL; a browser selector also matched Next.js's route announcer. Running
destructive gateway tests during browser checks invalidated the fixture, so the
fixture was recreated and UI checks rerun serially. Full gateway execution
required the existing OPA policy and correct test-role password. The production
agent image intentionally excludes pytest; its unittest-only image check was
rerun without the pytest-based diagnostic module (covered in the host CI suite).

Compared with bb889054, production Python/Go/TypeScript is **193 added / 191
deleted lines (net +2)**, excluding tests, documentation and configuration.
The alert sender is 51 lines smaller; duplicate delivery/reset logic and the
fabricated upload fallback were removed. Required regression coverage accounts
for most growth. Human line-growth and component/risk-owner approvals remain
release gates, not something these tests or AI reviews can supply.

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
not_applicable`. This is completeness health, not process liveness: any failed
required source makes the aggregate unavailable even while other measurements
remain visible. Degraded denotes measured unhealthy/incomplete data; unknown
denotes unmeasured/unverified data. Optional disabled sources are not applicable,
and the aggregate is not applicable only when all sources are. Missing
observations cannot become success; measured failures outrank unknowns.
Basic liveness says `alive`, not that dependent systems are
healthy. Successful diagnostics still do not certify compliance.

Backend UUID tenant context and agent integer tenant context remain separate,
explicit contracts. Agent scores are capped, non-authoritative activity diagnostics,
not interchangeable backend assessments. Master's retirement of the old aggregate
drift writer is retained; compatibility hooks cannot create new compliance posture.
Operational reports are tenant-bound and explicitly unassessed.

The persisted audit observations count distinct observed gateway request IDs
(including denied/in-flight requests), not all audit events or total traffic.
Observed P99 uses completed provider outcomes only and preserves actual zero.
The follow-up contract above supersedes the original completeness calculation:
neither identified rows nor a valid chain proves collection coverage.

The independently reviewed candidate also fixed a duplicate `compliance_status`
key, and selective migration repairs old unobserved scores. Consumer review found
nullable trust-summary/public-share fields, which now render Unknown instead of
a bare percent or misleading zero. Shared templates preserve provenance labels.

## Previous verification (2026-09-18, through bb889054)

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
   enabling snapshot writes. Deploy the new null-aware backend with
   `AUTHCLAW_EXPECTED_DB_REVISION=051,052` while still on 051; POSTs return 503
   until the expansion. Retire old readers, migrate, then enable writer callers.
   Both backend and gateway accept 051/052 for this bounded rollout. Do not
   bypass an old binary's startup guard or roll back to a non-null-aware reader.
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
storage persist a NULL snapshot and an atomic notification through the explicit
write-authorized POST; read polling cannot create those transitions.

## Remaining release boundaries

Live AWS deployment/outage, managed alert delivery, remote CI for the eventual
commit, and renewed independent human component/security/consumer approvals remain
release evidence. Local tests and independent AI review do not satisfy those
approvals. Material test growth needs the existing line-growth owner exception.

Architectural suggestions are not new feature scope: backend/agent identifiers
remain separate, agent SMTP remains operator-configured, and broader caching or
trust-health inventory changes need their own contract. Full Compose's agent
ClickHouse mirror is explicitly disabled by default. Enabling it requires a
reachable authenticated HTTP endpoint; an unavailable enabled source is not a
successful connectivity claim. Its unavailable state and PostgreSQL fallback
are tested. SMTP deployment must supply transport configuration and verified
tenant administrators; disabled delivery is intentionally visible as failed.

Verification above was completed before publication. PR merge and deployment
remain separate; the running application's deployment was not changed.

## Follow-up verification — 2026-09-21

This section supersedes the earlier local deployment statement for this follow-up.
The review's reachable-but-stale ClickHouse mirror and global checkpoint findings
were confirmed in the existing analytics and event-pipeline paths and corrected:

- Governance analytics always serves tenant-filtered PostgreSQL observations.
  ClickHouse reachability remains `unknown`, mismatching aggregates are `degraded`,
  and connection/query failures are `unavailable`; all three are alertable.
  Matching aggregates do not prove complete ingestion. No watermark or total-traffic
  coverage is claimed. Existing summary queries are reused; the mirror comparison
  runs after releasing the PostgreSQL connection.
- Checkpoints use the authenticated agent tenant key, tenant/stream/group uniqueness,
  explicit query filters and FORCE RLS. Legacy unattributed rows stay NULL and hidden.
  A per-tenant/stream transaction lock precedes aggregation so concurrent refreshes
  cannot overwrite newer counts with an older read. Existing persistence is reused.
- Backend checkout identity probes now roll back their own read transaction before
  request isolation is configured. The real PostgreSQL request-dependency regression
  attaches the production checkout hook; the rebuilt backend confirms REPEATABLE READ.

Fresh verification:

- Backend security/compliance CI unit selection: **624 passed**.
- Backend `test_t10_postgres.py` and `test_db_safety.py`: **26 passed**, one optional
  performance measurement skipped. Restricted roles, migrations and isolation ran.
- Agent CI selection: **122 passed, 84 subtests passed**, including real PostgreSQL
  middleware, two-tenant checkpoint reads/writes, forced RLS, legacy migration,
  deterministic concurrent refresh, HTTP ClickHouse outages/stalled mirrors and Redis.
- Post-simplification focused telemetry integration: **26 passed, 36 subtests passed**.
- Rebuilt agent image, source from image and tests mounted read-only, network disabled:
  **25 passed**. Backend and agent image builds passed.
- Console: **53 tests passed**; TypeScript passed; ESLint exited successfully with
  14 existing navigation warnings and no errors. Existing Python dependency
  deprecation warnings remain outside this patch; they were not suppressed.
- Python compilation, diff whitespace, live T01 activation and Tokei budgets passed.
- Independent read-only adversarial review found no additional confirmed defects.
  This is AI review, not the required independent human owner approval.

Initial failures were test setup errors: the new checkpoint helper omitted the
nonempty request ID required by signed database context, and the Redis replay test
requires the literal `localhost` address. Both were corrected and suites rerun.

Production changes relative to the pre-follow-up checkout: **54 added / 52 deleted
physical lines, net +2**, across four production files (`git diff --numstat`).
The checkpoint service itself is 11 lines smaller. Tests add realistic negative and
concurrency evidence rather than replacing it with mocks. No new runtime dependency
or abstraction was introduced. Code Work guidance drove scoped reuse and fresh tests.

### Coordinated local rollout and release constraint

Old checkpoint writers use a global conflict key and **cannot run with the new
tenant-scoped constraint**. Stop old application writers, run the existing database
security preparation job, backend and agent migration jobs, finalize grants and
run the database security checker, then start
the compatible agent image. Do not perform a mixed-version rolling agent deployment.
Rollback must use a tenant-checkpoint-compatible image and retain RLS/schema; do not
restore global checkpoints or guess tenant ownership of legacy rows.

This sequence was exercised on the local Compose installation: old agent was stopped,
migration and grants succeeded, identity/privilege/cross-schema/RLS verification passed,
then backend/agent were recreated from rebuilt images and gateway restarted. Backend,
agent readiness, gateway health and console login each returned HTTP 200. Application
volumes were preserved. AWS deployment/outage evidence, remote CI for a future commit
and independent human approvals remain separate release gates. No commit or push is
claimed by this verification record.

### Closure of the six published-head findings

The remaining recorder, filtered-share metadata and alert-recovery findings are
also fixed. Regression tests first reproduced the metadata and queue failures.
The independent reviewer then found a mixed pending-SMTP/high-audit-lag case;
its failing regression was added and the classifier corrected so a measured
failure retains precedence over unknown SMTP lag.

- Public trust packages recompute evidence timestamps after framework filtering.
- Completed SMTP alerts no longer require a Kafka checkpoint. Pending or failed
  alerts remain visible; a known lag failure elsewhere cannot become unknown.
- Gateway recording removes string-length token guesses, word-count-as-token
  estimates and the default 150ms latency. Zero remains zero; missing, negative,
  boolean or non-integer usage is unknown. PostgreSQL and mirrored event payloads
  receive the same validated values through existing registrar seams.
- Additive `gateway_requests.token_usage_recorded` defaults false: historical
  numeric values are preserved but cannot be asserted as measured. New writers
  explicitly record provenance; aggregates return NULL when any contributing
  count is unknown/unverified. Migration must precede deploying new writers.
  Older writers remain compatible but their unmarked usage stays unknown.
- Current provider adapters return text, not usage metadata. Their counts remain
  intentionally unknown; this change does not claim to extract provider usage.
  ClickHouse lacks that provenance, so diagnostic token fields stay unknown and
  cannot create a false mirror mismatch. Count/latency discrepancy checks remain.

Final integrated checks: **135 agent tests / 90 subtests**, including the real
PostgreSQL fixture's migration, legacy/partial/zero token aggregates and alert
recovery through `/metrics`; **143 backend tests, one optional benchmark skipped**;
**53 console tests**, TypeScript, Python compilation and line budgets passed.
The new token suite is included in the existing Agent CI selection. Independent
review checked the integrated fixes; human owner approvals remain required.
Production diff relative to the pre-follow-up checkout is **104 additions / 78
deletions, net +26 physical lines** across nine files, measured with git numstat.
The checkpoint service is 11 lines smaller. Test growth is necessary to cover
the reported integration failures and requires the existing owner growth approval.

The final local rollout initially omitted the preparation job and failed on the
finalized authentication function permissions. This was an operator-sequence error,
not a schema defect: the full existing prepare -> backend/agent migrations ->
finalize grants -> security-check sequence passed using restricted migrator roles.
The final backend/agent images were then activated, with application data retained.
The automated PostgreSQL fixture now also runs two prepare/migrate/finalize cycles
with a non-superuser, non-BYPASSRLS migrator before its tenant isolation assertions;
that upgraded-schema integration passed. Repository/Compose policy tests: 27 passed.

## Source-failure and recovery follow-up (2026-09-21, after 6a812ea)

The code-work/code-verification cycle addressed the three remaining review findings:

- Dashboard audit records from an unverified mirror remain unknown, including an
  empty reachable mirror. Observed records remain visible with a coverage warning;
  another source's outage cannot turn unknown audit activity into a definite empty
  result. Reused the existing BFF source-state envelope and UI instead of adding
  another backend endpoint. Regression assertions failed before the fix.
- Document synchronization accumulates ordinary source failures and cannot advance
  the last-success timestamp after a failed pass. Manual failure returns structured
  HTTP 503. Pending/interrupted scans retry even when size is unchanged. Independent
  review caught a retry race; the existing PostgreSQL advisory-lock pattern now
  serializes complete sync passes per authenticated tenant across workers.
- Real connector discovery, listing, download, and security-check errors cannot
  return mock evidence. Explicit mock mode remains labeled mock. Missing inventories
  have null counts, not zero. Incomplete pagination, malformed entries, partial S3
  enumeration, and unavailable sizes fail closed before unsafe reconciliation or
  document writes. Drive explicitly requests size/completeness fields. Successful
  empty data and measured zero remain valid. A clean bucket scan clears only that
  tenant/bucket's old findings; failed checks preserve them.

Reused connector validators, source functions, monitor state, tenant context,
database locking, and existing test harnesses. No dependency or schema changes.
Connector production code is five lines smaller. The five production files total
326 additions / 301 deletions (net +25 physical lines versus 6a812ea); most diff
churn is dedenting real connector branches after removing exception swallowing.
Tests cover the necessary extra failure, isolation, and concurrency boundaries.

Fresh verification on the final implementation:

- Exact Agent CI selection, extended with `test_connector_truthfulness.py`, using
  disposable PostgreSQL 16.10 and Redis 7.4.7: **170 passed, 90 subtests passed**.
  Real middleware/restricted-role tests verify sync 503, no false document deletion,
  unavailable connector counts, same-tenant lock contention, another tenant's
  progress, lock release, and tenant-isolated clean-scan recovery. Existing RLS,
  migrations, queue, audit, token, and quota regressions also pass.
- Console: **53 unit tests passed**, TypeScript passed, targeted ESLint zero errors.
  Existing auth-navigation lint and Starlette dependency deprecation warnings remain.
- Repository/Compose policy: **27 tests passed**. Diff whitespace checks passed.
- Agent and console production Docker builds passed; the final agent image also
  passed syntax verification in a read-only, network-isolated container.
- Independent review found the retry race and malformed Graph-item filtering gap;
  both were corrected, regression-tested, and independently re-reviewed.

The new database fixture initially omitted required request identity and non-null
seed fields. Those fixture failures were corrected without weakening database
guards, followed by a passing focused run and the full final suite. Native Windows
Turbopack rejected the worktree's external node_modules junction; the normal Docker
build with image-local dependencies passed without changing bundler configuration.

Compatibility/limits: connector status now uses health states plus an explicit
`mode`; unavailable inventory/counts are null. Paginated/incomplete inventories
and files without measured size are explicitly unavailable, not partially processed
or assigned invented values. Completing provider pagination/export support is not
claimed. No live cloud-provider or AWS deployment proof was collected. This local
follow-up does not constitute a push, human approval, or application rollout.

## Returned pipeline failure follow-up (2026-09-21)

Confirmed the remaining PR #60 defect with eight failing regression cases: new
and modified watched/cloud documents through manual and background synchronization
all ignored `alert_delivery_failed`. Reused `_sync_sources`' existing failure set
and final exception at all four scan calls; no helper, dependency, schema, or retry
path was added. Production delta for this follow-up is 8 added / 4 removed physical
lines (net +4), outside the configured component line-budget scopes.

Manual synchronization now raises through the existing failure response and the
worker records degraded health without advancing success timestamps. Further
passes do not rescan unchanged completed or alert-pending/failed documents; the
outbox retains retry ownership. Existing tenant scoping and locking are unchanged.
The focused suite passed 15 tests including all eight new regression cases.
The broader agent selection passed 164 tests and 98 subtests, with one skip and
the existing Starlette deprecation warning. Diff whitespace checks passed.

T01 activation was freshly verified active: merged commit
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
`2026-09-16T12:57:25Z`, active ruleset 21141288 with zero bypass actors.
No fresh PostgreSQL/Redis integration or deployed outage verification was run for
this follow-up; the regression harness uses the actual monitoring functions with
I/O seams. Earlier evidence above is historical, not a fresh deployment claim.
Risk is limited to synchronization reporting; rollback reverts the four returned
status checks. Changes remain local and require the existing human review process.

## Kafka acknowledgement follow-up (2026-09-21)

Confirmed HTTP 200 record rejection becomes `delivered` in the existing publisher
and pipeline. Seventeen negative regression cases reproduce false success before
the fix. Reuse `KafkaRestAuditPublisher.publish`, `EventPipeline.deliver_event`'s
retry/dead-letter handling, and the existing queue-health test suite/CI selection.
The publisher lacks record acknowledgement validation; a small inline check is
necessary before returning success. No new helper, dependency, schema, or retry
path is needed. T01 was freshly verified active at merged commit
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective `2026-09-16T12:57:25Z`.

Final delta for this follow-up: seven added production lines in `audit_transport.py`,
outside the configured component budget scopes; no deletion or new abstraction.
Missing/malformed responses and record-level errors raise into existing retries;
successful partition/offset zero remains valid. The existing CI-selected queue
tests exercise actual publisher/pipeline code with HTTP/database seams, persistence
parameters, degraded health, retry exhaustion and recovery. An actual loopback
HTTP server also verified HTTP 200 record rejection and subsequent successful
acknowledgement through the publisher. No external Kafka service was used.

Fresh full Agent CI selection (`pytest --noconftest -p no:cacheprovider`, file list
in `.github/workflows/ci.yml`): **165 passed, 116 subtests passed, seven skipped**;
existing Starlette deprecation warning. Independent bounded review found no
confirmed issues and independently passed the queue suite. Diff whitespace passed.
Docker's Linux daemon is unavailable; real PostgreSQL/Redis integration and
deployed outage checks remain unverified. Historical evidence is not a fresh run.
No tenant authorization, SQL, schema, or locking paths changed. Risk: stricter
acknowledgements can expose nonconforming proxies as failed delivery, intentionally.
Rollback reverts the seven validation lines but restores the false-success risk.
All follow-up fixes remain local; publication and human owner approvals are pending.

## Consolidated eight-finding audit and remediation (2026-09-21)

Reviewed `2569214` against base `1a3970c`, tracing each supplied finding through
its active producer, authorization boundary, persistence and consumer. These
dispositions supersede the earlier claim that no in-scope defects remained.
T01 activation was freshly verified active before this work. PR #60 stays unmerged.

| Finding | Disposition and origin | Fix and evidence |
| --- | --- | --- |
| 1. Cross-tenant Trust Center | Confirmed High; tenant selection and shared-cache flaw predated the PR. | Validate authenticated tenant before lookup; select its active row and check cache tenant. Alternating/concurrent tenant regressions and actual authenticated PostgreSQL requests return only their own signed packages. |
| 2. Diagnostic compliance reported healthy | Confirmed Medium; numeric reducer introduced by PR, while base already conflated signing with health. | The diagnostic-only producer's compliance health remains unknown, including numeric/zero scores. Imported-producer and authenticated HTTP tests verify this. |
| 3. Correlation changes canonical audit action | Confirmed Medium; inherited prefix classification moved to correlation in PR. | Delete the untrusted special classification; record the actual allow outcome. Ordinary and connect-test-prefixed calls through real auth middleware, proxy, Redis and local upstream preserve correlation but both emit allow. |
| 4. Shared connector source identity | Confirmed Medium; inherited shared credentials/watch-directory design remained unsafe despite tenant-scoped destinations. | Bind process sources to configured owner before source I/O and local sync. Baseline reproduction returned owner-7 inventory to tenant 8. New tests deny other/missing tenants before provider or filesystem I/O; real middleware denies tenant 7 while owner 8 retains sync/locking/recovery behavior. |
| 5. Unproven latency zero | Confirmed Medium; legacy default and reader provenance gap inherited and retained by PR. | Add latency_recorded default false, remove legacy default, mark validated measurements in both current writers. Aggregate only complete recorded observations; missing/legacy/invalid values remain null, genuine zero stays zero. Five baseline cases failed; SQLite recorder and restricted PostgreSQL migration/aggregate checks now cover them. |
| 6. Platform tenant count in tenant metrics | Confirmed Low; inherited unscoped query. | Filter by authenticated tenant. Baseline SQL returned three active tenants where caller scope contains one; authenticated PostgreSQL metrics return one for each tenant. |
| 7. Unknown score rendered as zero-width bar | Confirmed Low; inherited visual fallback. | Reuse overview's conditional rendering: omit the entire track for unknown, retain measured zero. Actual component-render outage/unknown/zero assertions failed before and pass after. |
| 8. Public score provenance omitted | Confirmed Medium integration gap; old view omitted fields added by ENT-019 producer. | Render evidence timestamp and missing-control treatment alongside calculation version, with Unknown for legacy payloads. Public component test reproduces supplied metadata disappearing before the fix. |

Independent adversarial review additionally reproduced same-tenant cache
deactivation: active tenant 7 warmed the cache, became inactive, and still got a
published package. Moving the existing active-row check before cache lookup fixes
that same authorization boundary; denial and reactivation recovery are covered.
The scoped cache remains one bounded slot; switching tenants rebuilds instead of
growing a global per-tenant cache. No new cache abstraction was introduced.

Reuse and minimality: use existing tenant ContextVar/validator, source validator,
monitor failure state, recorded-token provenance pattern, existing recorder and
SQL aggregates, and existing UI conditionals. Trust production delta is net zero;
gateway deletes five net lines, UI adds three net lines. Total production
Python/Go/TypeScript delta versus `2569214`: **52 added / 37 removed, net +15**,
using git numstat excluding test paths/suffixes. Configuration and tests are
separate. Existing CI selections now include the new trust-boundary suite.

Rollout and compatibility:

- Apply existing agent startup migrations before new latency readers/writers.
  The additive latency_recorded flag defaults false; old stored latency remains
  preserved but unverified. Do not backfill true from plausible numbers. Unknown
  historical rows keep complete-history averages unknown until qualified data or
  existing retention changes that input set. Keep the additive column on rollback.
- Configure `AUTHCLAW_CONNECTOR_TENANT_ID` for the tenant owning the process's
  upstream credentials and watched files. Existing explicit
  `AUTHCLAW_BACKGROUND_MONITOR_TENANT_ID` can supply the owner when the connector
  setting is absent. A different tenant is denied; missing ownership fails closed.
  Compose and environment examples expose both settings. Supporting different
  upstream accounts per tenant in one process is not claimed; separate owner-bound
  processes or a future tenant credential registry are required.
- Connection-test requests still execute and retain correlation metadata. New
  canonical actions reflect policy outcome, not caller-supplied test labels;
  consumers filtering only test_request must use correlation metadata instead.
- Old public score payloads remain readable and show Unknown provenance. Reverting
  these guards would restore the reported defects; preserve tenant boundaries,
  nullable values and evidence rather than clearing failures by deleting data.

Fresh integrated checks:

- Complete Agent CI selection with isolated PostgreSQL and Redis: **189 passed,
  116 subtests passed, zero skips**. Restricted runtime and migrator roles exercise
  legacy migration, repeated upgrades, RLS, concurrent persistence/checkpoints and
  alert delivery/recovery. New authenticated routes exercise tenant-switched
  signed packages, diagnostic health, scoped metrics and source-owner denial.
- Backend affected audit/scoring/assessment/schema/API/trust suites: **125 passed**,
  including real PostgreSQL audit aggregation. No backend production code changed.
- Console: **54 unit tests**, TypeScript and targeted ESLint passed; three existing
  navigation warnings remain. Tests render real components with upstream doubles.
- Gateway: **10 tests and eight subtests passed** with actual isolated Redis and
  local HTTP providers, including payload-fidelity and audit failure regressions.
- Repository/Compose policy: **27 tests passed**. Whitespace passed. Conservative
  nonempty physical-line upper bounds in every configured component stayed below
  10,000 (maximum 2,132); a fresh Tokei run is not claimed.
- Independent cross-review checked tenant/cache, source ownership, provenance,
  audit outcome and UI changes, and reverified the cache-deactivation correction.

Test failures were resolved without weakening production controls: a prior latency
fixture needed to mark its explicitly measured 17ms as recorded; the Redis replay
test requires localhost spelling instead of 127.0.0.1. Legacy migration now proves
an old default-zero row stays unrecorded and newly omitted latency is null.
The revoked-tenant HTTP test initially expected the service's 404; restricted
PostgreSQL binding actually denies the inactive tenant earlier in quota middleware
with 503 rate_limit_unavailable. The test now asserts that exact fail-closed
response, while direct service tests independently verify cached-payload denial.
Existing dependency deprecation warnings remain. Tests use disposable loopback
services, not application data. No live cloud-provider, deployed browser/outage,
AWS/SMTP configuration, complete-repository security clearance or merge readiness
is asserted. Human current-head owner/risk reviews and rollout verification remain
required; these results establish the bounded eight-finding remediation.
