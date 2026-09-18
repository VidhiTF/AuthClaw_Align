# ENT-019: truthful telemetry

## Enabled ClickHouse outage follow-up

Reuse decision before implementation: keep `governance_analytics`, the existing
ClickHouse probe/aggregate loaders, PostgreSQL summary and five-state classifier.
Skip the aggregate query after a failed probe; also handle failure between probe
and aggregate. PostgreSQL must be queried successfully, never replaced with empty
success. Preserve ClickHouse `unavailable` at source and aggregate levels and label
the gateway summary's actual source. The small selection/error branch is necessary
because the current combined `_safe` expression aborts before fallback. Extend the
existing real PostgreSQL/HTTP integration test with an enabled loopback ClickHouse
outage, partial failure and recovery; no new dependency or health abstraction.

Verification on 2026-09-18: the enabled, unreachable source reproduced generic HTTP
503 before the fix. Real endpoint tests now return a structured `unavailable`
response with measured PostgreSQL values for two isolated tenants. Loopback HTTP
fixtures cover failed probes (no aggregate retry), successful probe followed by
query failure, malformed aggregates, healthy empty aggregates and disabled mode.
An injected SQL division-by-zero in the actual fallback query confirms both-source
failure remains sanitized HTTP 503; this does not fail earlier in admission.
The fixture's initially missing required gateway timestamp was corrected.

Agent smoke: 116 passed; final CI-equivalent selection: 101 passed plus 67 subtests.
Console: 48 passed and TypeScript passed; policy: 31 passed; Tokei budgets passed.
Rebuilt agent image and ran 18 focused tests inside it with no network. Independent
read-only re-review identified a test injection gap, which was corrected; no
production defect remained confirmed. Production change is 10 added / 3 deleted
physical lines (`git diff --numstat`), net +7; no safe additional consolidation was
identified. The additive `gateway.source` field identifies measured provenance.
No schema change; rollback only this selection branch if necessary, acknowledging
that it restores outage HTTP 503 behavior. Deployment, human approvals and remote
CI for this local follow-up are not claimed complete; running containers unchanged.

## Final review corrections (2026-09-18)

The final candidate additionally serializes evidence refreshes per tenant and
uses one transaction for mapping, control scores and snapshot comparison. A real
concurrent PostgreSQL reproduction previously doubled one negative finding;
regression tests now verify serialization, no duplicate mappings and atomic
rollback after a mid-score failure. A savepoint preserves unavailable snapshots
after SQL source errors; the database context hook allows rollback before rebinding
the next tenant statement. Notifications remain after commit. Existing transaction,
RLS and scoring code is reused; redundant catalog writes and per-control commits
are removed, with no new dependency.

Fresh dead letters remain degraded when checkpoint lag is unknown. Compliance
outages render unknown inputs and unavailable history rather than zero findings.
Dashboard latency accepts measured gateway provider outcomes, excluding placeholder
durations while preserving measured zero. Each defect has regression coverage.

Final local results supersede earlier counts below: agent smoke 116 passed;
CI-equivalent agent selection 101 passed plus 67 subtests; backend selection 47;
console 48; policy/evidence 31. TypeScript, Tokei 12.1.2 line budgets and diff checks
passed. Agent and console images rebuilt successfully; 22 telemetry/queue tests
passed inside the agent image with read-only test mounts and no network. Independent
adversarial re-review found no additional confirmed defects. Existing dependency
deprecation warnings remain. Temporary review files and isolated databases were
removed; running application containers were not replaced. Remote CI, required
human approvals and deployed AWS verification remain separate, pending evidence.

## Follow-up review: state precedence and tenant-bound legacy consumers

Confirmed defects: the metrics HTTP regression returns `degraded` for unknown
audit/queue observations; legacy scoring selects the first tenant, and snapshot
history/alerts have no tenant key. Reports are authenticated by existing middleware,
but RLS cannot isolate those two aggregate tables.

Reuse/new-line decision (recorded before implementation): modify existing drift,
report, observability and migration paths; retain the canonical evidence scorer,
authenticated tenant context, HMAC-bound database context and existing RLS policy
pattern. A small health classifier is necessary to express five-state precedence;
this is a behavior correction, not a semantic duplicate-function refactor. Tenant
arguments, SQL predicates, indexes and RLS are necessary to remove first-tenant
selection and cross-tenant history comparisons. No new dependency or parallel
scoring pipeline is needed. Unattributed legacy rows must remain preserved but
invisible to runtime tenant reads; do not guess their owner.

Implemented on top of `fafbc48875191a7d12cb4e91ef1350244077cf6d`:

- Shared precedence is `unavailable > degraded > unknown > healthy > not_applicable`.
  Empty/unrecognized observations remain unknown. Metrics, governance and trust
  aggregation use the same classifier; known failure still takes precedence over
  unknown. Readiness retains its explicit checked-dependency scope, and liveness
  remains `alive`, not an unsupported claim of overall health.
- Reports and both snapshot callers supply the trusted tenant. The existing
  ContextVar identity is checked before scoring, report access or snapshot writes.
  SQL also filters tenant IDs. History and alerts now have tenant foreign keys,
  composite indexes, USING/WITH CHECK policies and FORCE RLS using the existing
  HMAC-bound `agent.agent_current_tenant_id()` context. Removed global exemptions.
- The independent read-only adversarial review found one additional defect:
  metrics passed no tenant into the audit verifier, falsely rejecting valid tenant
  chains with interleaved global IDs. Its reproduction failed without tenant scope
  and passed with scope. Metrics now passes the authenticated tenant; a real A/B/A
  hash-chain fixture verifies metrics, governance and auditor-report agreement.
- Removed seven redundant numeric report initializers and shortened obsolete
  scaffolding: 10 fewer physical production lines than the first candidate. Final
  incremental production diff is 95 added / 71 deleted, net +24, using `git diff
  --numstat` against the above head and excluding tests/docs/CI/unrelated edits.
  The unavoidable growth is predominantly tenant migration/RLS and state handling.
  No AGENTS.md budgeted production path changes in this follow-up. Incremental
  non-prose positive growth is 322 lines, predominantly the real integration test;
  independent material-growth approval remains required, not self-approved.

Fresh verification (2026-09-18; Python 3.14, PostgreSQL 16, pinned psycopg2 2.9.12):

- Focused telemetry: 19 tests passed, including eight classifier subtests and a
  subprocess importing the real agent app, middleware, JWT/RBAC, scoring, reports,
  database event hooks and cloud-deletion worker. ReportLab 5.0.0 and pypdf 6.14.2
  are available. JSON/CSV/PDF exports were generated; PDF text was parsed to check
  both the allowed tenant filename and absence of the other tenant's filename.
- Real migration runs twice on an isolated UUID-named database created by the
  test. Old unattributed history/alerts are preserved, not reassigned. Runtime role
  is verified NOSUPERUSER/NOBYPASSRLS; startup security validation verifies FORCE
  RLS. Cross-tenant/null-owner inserts fail with SQLSTATE 42501; cross-tenant
  reads/updates/deletes expose/change zero rows. Forged plain tenant GUCs expose
  no legacy history. Missing/mismatched application context fails with 403.
- Alternating tenant snapshots do not manufacture cross-tenant drift. A real
  within-tenant score drop emits three tenant-bound alerts and audit entries.
  Both aggregate HTTP endpoints retain unknown audit/queue states, support healthy
  controls, and preserve degraded/unavailable precedence. No AST extraction is used
  by the PostgreSQL integration test.
- Full agent smoke suite: 112 passed. Exact updated Agent CI selection: 97 passed,
  56 subtests passed. Backend compliance/trust/evidence selection: 47 passed.
  Console: 47 passed and `npx tsc --noEmit` passed. Policy/evidence tests: 31 passed.
  Python compilation and `git diff --check` passed. Agent CI now starts the existing
  pinned PostgreSQL image and requires the new integration test.
- Rebuilt agent image manifest list
  `sha256:79b37767ba82920b68498a6a5269a1a3731920f7b3d0921233e263bc664cc117`;
  18 focused tests passed in a read-only network-isolated container. Running
  application containers and databases were not migrated or replaced.

Reproduction: set `ENT019_TEST_DATABASE_URL` to a loopback disposable PostgreSQL
database whose name ends in `_test`, then run
`python -m unittest discover -s services/agent/smoke_tests -p '*telemetry*.py' -v`.
The test creates/drops only its own UUID-named database. CI installs the existing
hash-pinned agent requirements; no dependencies were added. Initial local failures
were a different PostgreSQL driver, missing pinned parser dependency and incomplete
fixtures; these were corrected and checks rerun, not waived. Existing dependency
deprecation warnings remain. Cloud discovery is an empty synthetic source, quota
uses explicit isolated memory mode, and notifications write a temporary local log;
these are not production cloud/Redis/SMTP deployment claims.

Deployment/rollback: drain old report/snapshot workers, run the existing agent
migration job and security finalization, then start the updated image and verify
readiness. Old snapshot writers omit tenant IDs and are deliberately denied by RLS;
do not overlap them after migration. Historical null-owner rows remain quarantined
until separately proven ownership exists. Rollback must retain tenant columns,
indexes and RLS: disable affected report/worker paths or roll forward with a
tenant-aware fix, never restore aggregate access. Remote CI, human component/risk
approval and AWS deployment/outage evidence remain pending. Unrelated
invitation/configuration work is excluded from this change.

The sections below retain evidence from earlier ENT-019 iterations; this follow-up
supersedes their statements that legacy history/alerts are aggregate-only.

Baseline: local merge `2d34f31` (tree identical to `align/master` `5ff6f4b`).
T01 activation was verified against GitHub before implementation: PR 52,
merge `1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
2026-09-16T12:57:25Z; active two-approval protection with zero bypass actors.

## Contract and implementation

- Agent `/metrics` returns HTTP 503 and `status: unavailable` on query, audit,
  approval, or pipeline-source errors, with no fabricated success values. Its
  former 142 ms/90%/valid-chain fallbacks are removed. Measured zero latency is
  preserved; no latency sample is null. Approval counts use the checked database
  transaction rather than the approval helper's silent-error/stale-cache path.
- Detailed health reuses measured readiness checks with explicit `agent_readiness`
  scope; unmeasured provider/runtime features remain separately unknown. Readiness adds `health_status`
  while retaining its existing ready/not_ready contract and not_applicable local
  production validation. Basic `/health` and its canonical alias return
  `status: alive, scope: process_liveness`, not dependency-health claims.
- Analytics query/connection failures are HTTP 503, not empty successful counts.
  Missing queue checkpoints are unknown/null and alertable, never zero lag with
  alerts cleared. Observed threshold violations remain degraded. Disabled
  ClickHouse is not_applicable; failed checks are unavailable. An empty audit
  ledger (including document audits) is unknown, not a verified chain.
- Canonical compliance preserves its catalog formula and adds calculation version,
  latest framework evidence-record timestamp, and missing-control treatment.
  Aggregate evidence time is the oldest framework timestamp, or null if any
  framework lacks one; it is not the calculation clock or proof of freshness for
  every signal. Existing snapshot JSON retains provenance without a migration.
  Historical snapshots lacking provenance expose null metadata, never invented
  versions/timestamps.
- The legacy agent evidence calculator no longer awards 100 to controls without
  evidence: they return null/unknown and contribute zero to a mixed framework's
  denominator; a framework with no evidence returns null. Its v2 treatment and
  timestamp are returned and retained in existing score metadata. The legacy
  non-null integer storage retains zero with explicit unknown status; API users
  must not interpret this storage penalty as a measured compliance score.
- The overview and compliance dashboards clear stale values on source failure,
  display unknown/error states, and reject out-of-order refresh results. The
  overview no longer claims an unmeasured active redaction engine or paints every
  compliance state green. Dashboard sample counts are labelled as the latest 100
  audit records, not a complete traffic total. Real zero durations survive.
- Review also covered legacy drift snapshots, executive/auditor reports, framework
  explorer, and public trust health. Source errors abort reports instead of returning
  100 or empty findings; missing evidence is explicitly unknown. Drift persists null
  scores with unknown/unavailable state and alerts instead of retaining stale posture.
  JSON/CSV/PDF executive exports retain score
  provenance. Audit summaries and reports preserve unknown versus corrupted chains.
  Framework explorer rejects source errors and never labels null/zero scores LOW.
  Public trust health forces fresh evidence and combines signature, audit, compliance
  evidence presence and the existing queue classifier under `trust_evidence` scope.
  Healthy means these checks passed, not that compliance is 100% or that unprobed
  backend/gateway/provider services are healthy. Those remain unknown; source
  outages return sanitized HTTP 503.

## Reuse, review, and compatibility

Modified existing handlers, score models, snapshot JSON, analytics helpers and
dashboard state. Reused existing queue-lag aggregation rather than another metric
calculation. No dependency, production module, database schema or authorization
change. React guidance informed parallel request handling and stale-response
protection. Removed empty-success constructors, redundant dashboard calculation
wrappers, repeated filtering, and explorer fallback branches. Final production-source
numstat: 249 lines added and 269 deleted (net reduction of 20); tests and generated
evidence excluded. Review began with the prior implementation at net zero.
Material test growth must still receive independent owner review before merge.

Regression evidence first reproduced the successful metrics dictionary on database
failure. Review found additional empty-ledger, missing-checkpoint, legacy 100-point
baseline, historical-provenance and approval-cache cases; all were corrected and
retested. A broad test caught an unnecessary liveness response change; that change
was reverted to preserve the existing contract. No human approval is claimed.
An independent read-only adversarial reviewer reproduced four additional consumer
defects (legacy score fallbacks/null arithmetic, explorer risk, audit tri-state and
public health), then confirmed their fixes and independently passed the 12 focused
tests. Final report wording also no longer asserts unmeasured monitoring or successful
chain verification. Empty/partial ClickHouse aggregates fail closed; malformed audit
timestamps cannot become zero-traffic success. No new abstraction or dependency was
added: PDF tests use the existing pinned ReportLab runtime package.

## Verification and retained evidence

Executed locally on 2026-09-18, with isolated disposable Redis and synthetic data:

- Agent smoke discovery: 105 tests passed, including 12 telemetry tests.
- Updated Agent CI pytest selection (`--noconftest`, from `services/agent`):
  90 tests plus 48 subtests passed: signing/replay, authorization, quota, graph, sensitive-data, transport and
  telemetry coverage. CI explicitly includes the new telemetry suite.
- Backend compliance/trust/audit-export/evidence-access selection: 47 passed.
- Console `npm run test:unit`: 47 passed; TypeScript and production build passed.
- CI-plan, repository-policy and compliance-hardening tests: 50 passed.
- Targeted lint: zero errors; five existing Next.js navigation warnings remain.
  Existing Pydantic and Starlette dependency deprecation warnings also remain.
- Changed budgeted files are 59–834 physical lines each (a conservative code-line
  upper bound), below the 10,000-line limits. Remote Tokei verification is pending.
- Additional tests cover stale success arriving after a failed refresh, malformed
  ClickHouse/audit payloads, null versus zero, report JSON/CSV/PDF generation, and
  all four independent-review consumer regressions. The PDF test initially failed
  because local ReportLab was absent; installing the already-pinned 5.0.0 resolved
  that environment gap and the check passed. No tests were skipped to hide it.

Artifacts are generated from exercised code, not fabricated production observations:

- [Unavailable metrics response](ENT-019-unavailable-telemetry.json): an injected
  database outage returns 503 with null latency, score and audit validity.
- [Degraded trust health](ENT-019-degraded-health.json): publication and evidence
  checks succeed but a failed audit integrity check keeps the aggregate degraded.
- [Dashboard outage HTML export](ENT-019-dashboard-outage.html): the actual React
  overview rendered after synthetic success followed by HTTP 503; assertions
  prove the previous 12345 request count disappears and an alert/Unknown appears.
  This is a component-render export, not a deployed-browser screenshot.

Regenerate the two JSON files by setting `ENT019_TELEMETRY_EXPORT` to the absolute
unavailable-response path and running `python -m unittest discover -s
services/agent/smoke_tests -p test_truthful_telemetry.py`. Set
`ENT019_DASHBOARD_EXPORT` to the absolute HTML path and run the console unit suite.

No live AWS deployment, managed-source outage drill, remote CI, or human owner
approval was performed for this uncommitted change. Live rollout must verify
clients handle null/unknown states and HTTP 503, and alert delivery responds to
missing queue telemetry. Roll back code as a coordinated producer/consumer change;
do not reintroduce success fallbacks to hide an outage. New snapshot metadata is
additive; older code ignores it and older snapshots remain readable.

## PR 60 blocker remediation (2026-09-18)

This section supersedes the initial review's claims that skipping unknown snapshots
and retaining a `healthy` liveness label were acceptable. Both review findings at
`064189454d42de79341b68d8a89490d6042c0943` were reproduced before patching (three
focused failures). Independent investigation confirmed the source paths and schema.

Reuse/new-line decision: modify the existing drift writer and alert/audit helpers,
reuse readiness and queue classification, and retain status in existing history
JSON. No new production module, dependency, or duplicated classifier. Four
idempotent nullable-column alterations are necessary: history score and alert
drop/previous/current score cannot represent missing data while NOT NULL.
The final production diff is 90 added / 109 deleted lines (net -19).

- Unknown and acquisition-error observations persist null plus unknown/unavailable
  status, without inventing a numeric drop. Real zero remains numeric. Recovery
  starts from the latest null row, not an older successful score. Persistence
  failure triggers an unavailable alert and raises; it cannot write a marker when
  the database itself is down. Consumers must not treat stored history as a live
  observation during a database outage.
- Snapshot and alert records commit before external audit/notification work.
  Independent adversarial review found that missing audit tenant context and
  premature loop exit could lose later framework notifications. The writer now
  passes the trusted runtime tenant, attempts every framework independently, and
  raises delivery errors. Unknown observations notify on each invocation so audit
  or transport recovery is not suppressed by committed history. Existing HIGH
  alert transport and numeric SCORE_DRIFT pattern are retained.
- Basic liveness intentionally changes its label to `alive`; readiness's existing
  `ready/not_ready` API and Docker/Terraform readiness targets are preserved.
  Detailed readiness can recover to healthy; invalid/failed production validation,
  database or rate-limiter checks return unavailable. Nonproduction validation is
  not_applicable. Trust health distinguishes successful, failed, missing and
  unavailable evidence without using its cache to hide source failure.

Fresh verification commands/results:

- `.venv-t02/Scripts/python.exe -m unittest discover -s services/agent/smoke_tests
  -p test_truthful_telemetry.py -q`: 13 passed (real SQLite transactions plus ASGI
  alias/success/outage/recovery tests). With `ENT019_TEST_DATABASE_URL` pointing to
  disposable PostgreSQL 16: 13 passed; actual migration statements run twice against
  TEMP tables, followed by numeric/unknown/unavailable/recovery and delivery-failure
  transitions. Test doubles isolate external audit/notification boundaries; the
  trusted tenant argument is asserted, not claimed as a full deployed RLS drill.
- Full agent smoke discovery against disposable Redis: 106 passed.
- Exact Agent CI selection from `.github/workflows/ci.yml`, with `--noconftest
  -p no:cacheprovider`: 91 passed and 48 subtests passed. The unsafe legacy database
  conftest was never loaded. Syntax compilation and `git diff --check` passed.
- Agent image rebuilt with `docker compose --env-file .env.full.example -f
  docker-compose.full.yml build agent`; focused tests also execute its actual code
  in a read-only network-isolated container. Existing unrelated Compose/environment
  edits were preserved, not included in this remediation.

Rollout: run the existing agent migration job before replacing agent writers;
nullable expansion preserves all existing rows and supports old numeric writers.
No backfill or destructive migration is required. Keep nullable columns on rollback
(restoring NOT NULL would reject retained null history); coordinated code rollback
would reintroduce the reviewed defects. Legacy aggregate history still intentionally
lacks tenant columns/RLS, as documented in `tenant_isolation_report.py`; this patch
does not redesign those tables. Audit identity uses the existing trusted tenant
context, never a request-supplied tenant. No authentication/RLS policy was weakened.

Remaining release evidence: live AWS deployment/outage and alert delivery proof,
remote checks for the new commit, and renewed independent human owner approval.
The synthetic dashboard export remains component evidence, not deployment proof.
These local fixes are not a claim of PR approval or production deployment.

## Follow-up staff review (2026-09-18)

Used the code-work/code-verification workflow, with a fresh independent adversarial
review and local reproduction of its findings. This review adds five confirmed
corrections to the PR 60 remediation above:

- Alert delivery no longer swallows configured SMTP failure or failed log-only
  delivery. A log-directory failure cannot prevent an available SMTP path. Test-only
  email suppression still requires successful logging. The shared alert subject
  now says security alert, not a fabricated claim of a data leak. Existing callers
  already catch/report transport errors; snapshot persistence remains committed.
- Legacy score evidence time comes from source collection/lifecycle metadata,
  normalized to UTC, not the time derived rows are rebuilt. Missing or malformed
  timestamps remain null; undated legacy document findings remain undated. The
  derived row's created_at remains a remapping timestamp, not collection proof.
- Checkpoints must be recent, nonnegative, complete, and agree with observed stream
  counts. Missing streams, conflicting queued/dead-letter counts, bad timestamps,
  and timestamps older than AUTHCLAW_QUEUE_LAG_ALERT_SECONDS (default 300 seconds)
  are unknown and alertable. Idle checkpoints can become unknown: no recent
  observation is not proof of a worker outage or of worker health.
- Unknown control-change history now stores null plus status metadata. A fifth
  idempotent nullable alteration covers compliance_score_changes.current_score.
  Readers also normalize legacy catalog_baseline history to null. Repeated unknown
  observations do not invent changes; recovery to a measured zero does create a
  change. Existing control-score storage retains its documented zero/unknown pair.
- Removed duplicate alert-fallback branches, repeated queue-threshold computation,
  and unused readiness imports. No new production module or dependency. Compared
  with the start of this follow-up, correctness checks add 30 net production lines;
  compared with reviewed PR head 0641894 the combined remediation adds 11. Across
  the full ENT-019 production scope versus align/master, git numstat is 400 added /
  409 deleted: net reduction 9. Tests and unrelated working-tree edits are excluded.

Fresh final verification:

- Focused telemetry suite: 17 passed on SQLite and disposable PostgreSQL 16.
  Actual nullable migrations execute twice; real snapshot/control-history writes
  verify missing/recovery transitions. An actual loopback SMTP receiver accepts and
  checks the generated unknown-compliance message; failure injection verifies
  unavailable SMTP/logging without contacting any external mail service.
- Full agent smoke discovery: 110 passed with isolated Redis/PostgreSQL.
- Exact Agent CI selection: 95 passed plus 48 subtests, using --noconftest.
- Backend compliance/trust/evidence selection: 47 passed.
- Console unit suite: 47 passed; npx tsc --noEmit passed.
- Repository-policy/compliance-hardening checks: 31 passed.
- Rebuilt agent image: all 17 focused tests passed in a read-only, network-isolated
  container (the SMTP test uses only its loopback interface). Python compilation
  and diff whitespace checks passed. Dependency deprecation warnings remain.

The independent review reproduced the missing-stream and null-history defects;
both received failing-before/passing-after regression tests. Source-timestamp,
SMTP failure and stale-checkpoint cases were similarly reproduced before fixes.
Windows test-source reads explicitly use UTF-8. The extended source-event fixture
initially lacked an approval reason; it was corrected and retested, not skipped.

Deployment still requires running the existing agent migration job before replacing
writers, keeping nullable columns on rollback, remote CI and renewed owner approval.
SMTP proof is local, not managed production delivery proof. No live AWS outage or
rollout was performed, and unrelated invitation/email/configuration edits were left
untouched. Material test growth requires the existing independent owner exception;
neither this review nor passing local tests substitutes for that approval.
