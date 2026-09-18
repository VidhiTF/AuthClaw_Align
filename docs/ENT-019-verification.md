# ENT-019: truthful telemetry

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
- Detailed health reports observed database health, unavailable checks, and
  unknown unmeasured provider/runtime features. Readiness adds `health_status`
  while retaining its existing ready/not_ready contract and not_applicable local
  production validation. Basic `/health` remains process liveness only, not proof
  that dependencies are healthy.
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
  100 or empty findings; missing evidence is explicitly unknown. Drift skips unknown
  scores and handles historical nulls. JSON/CSV/PDF executive exports retain score
  provenance. Audit summaries and reports preserve unknown versus corrupted chains.
  Framework explorer rejects source errors and never labels null/zero scores LOW.
  Public trust health treats signatures as artifact integrity, not runtime health;
  unprobed services remain unknown and source outages return sanitized HTTP 503.

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
- [Degraded detailed health](ENT-019-degraded-health.json): database probe succeeds
  while unmeasured runtime/provider health remains visibly unknown.
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
