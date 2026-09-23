# T14 runtime lifecycle and request efficiency

Scope: Claims 8 and 16, operability and performance debt. Reuse the gateway's
HTTP server, DB/Redis clients and audit transport; reuse DocumentScanner and
Requests. New lifecycle coordination is needed because HTTP draining alone
does not wait for asynchronous audits. New bounded scan scheduling is needed
because a pooled sequential session does not overlap network waits.

Evidence scanning preserves input order and invokes persistence/audit callbacks
on the caller thread. Sessions are isolated per concurrent slot and per workflow;
no new dependency or Presidio batch API is introduced. At most one bounded batch
is retained. Existing scan failure isolation and ten-second request timeout remain.

Acceptance: live HTTP shutdown/drain/timeout tests; request-order, isolation,
cleanup and failure tests; comparable sequential/concurrent local HTTP benchmark.
## Configuration and compatibility

`EVIDENCE_SCAN_WORKERS` defaults to 4, accepts 1 through 16, and rejects invalid
values. Set it to 1 for sequential processing with pooling. Each workflow owns
its sessions, cookies are cleared between documents, and at most that many
documents execute concurrently. The limit is per workflow, not process-wide.
The ten-second Requests timeout is an inactivity timeout, not a total workflow
deadline. Existing per-document failure isolation is unchanged. No API, database,
event schema, new dependency, or migration is introduced.

Gateway SIGINT/SIGTERM and startup/listener failures run cleanup. HTTP requests
drain before tracked background audits and shared resources close. The 30-second
deadline bounds HTTP/audit draining; synchronous DB/Kafka close can extend it.
HTTP deadline expiry force-closes connections and cancels request contexts.
Fail-open audit execution keeps at most four dependency operations active and a
bounded backlog of 64 immutable recovery copies. Further events are synced
directly to the durable local outbox. If the drain deadline expires, all remaining
active and queued copies are batch-written and synced to
the durable local outbox before dependencies close. Timeout spill atomically
claims and cancels each task; queued workers re-check that claim before emission,
and the persistence and built-in transport paths honor cancellation. The same
claim coordinates failure fallback, so a timed-out task creates exactly one local
recovery record. End-to-end delivery remains at-least-once, with the existing
idempotency key preventing a duplicate canonical append. Audit-producer mode uses
the same signal handling and drains HTTP before closing its stream.
Shutdown spill state becomes durable only after the complete batch is written and
synced. A failed or short append is truncated back to its original offset and
synced before individual retry. If that rollback cannot be confirmed, recovery is
marked indeterminate and returned as a hard shutdown error without a blind append
that could duplicate or further corrupt the record. A close error after successful
sync is logged as cleanup failure and does not retry already-durable data.

## Fresh local evidence (2026-09-23)

- T01 activation verifier exited 0: PR 52, merge
  `1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
  `2026-09-16T12:57:25Z`; live ruleset 21141288 active without bypass.
- From `backend`, process-only `DEBUG=false`, existing `.venv-t02` Python:
  `python -m pytest tests/test_evidence_scan_lifecycle.py tests/test_orchestrator.py tests/test_remediation_connector.py tests/test_remediation_failure_rollback.py tests/test_s3_remediation_protocol.py tests/test_s3_remediation_recovery.py -q -s`
  exited 0: **29 passed**. Final `py_compile` of both changed production modules
  and both orchestrator test modules also exited 0.
- Real HTTP/1.1 benchmark: 12 documents with 50 ms analyzer delay, sequential
  **0.640 s**, four workers **0.170 s**, **3.76x** speedup. Test asserts equal
  results, caller-thread ordered persistence, bounded in-flight requests, and
  exactly one reused TCP connection per slot. This measures a local controlled
  workload, not production S3/Presidio capacity.
- Negative/cleanup coverage includes HTTP 503, malformed JSON, request timeout,
  blank text, invalid worker counts, concurrent tenant workflows, early generator
  close, S3 read failure and listing failure. The audit unit test mocks the public
  publisher boundary; it verifies the runner payload, not real Kafka persistence.
- Gateway lifecycle and selected adjacent Windows tests passed; `go vet ./...`
  and `go build ./...` exited 0. The initial Linux Docker
  `go test -race -run TestShutdownGateway -count=1 ./...` exited 0.
  The Windows command was `go test -run 'Test(ShutdownGateway|HealthCheck|InternalQuota|PublicGateway|ConfiguredProvider|ProviderRouter|AdvertisedNonV1|InitDBRejects|DatabaseConfig|CompatibleDatabase|EmitAuditEvent|RequiredAudit|StreamingOutcome|AttemptAndOutcome)' -count=1 ./...`
  from `gateway`, using Go 1.26.5 and disposable Redis on port 16389. A dummy
  `authclaw_test` database URL satisfied the harness guard; these selected tests
  do not require successful PostgreSQL access.
- Post-review fixes add deterministic queued/deadline outbox recovery and
  audit-producer signal/drain coverage. The focused lifecycle set passed 20
  consecutive Windows runs, the selected adjacent gateway suite passed, and
  `go vet ./...` plus `go build ./...` exited 0. Linux Docker race evidence:
  `go test -race -run 'Test(AuditDrainDeadline|ShutdownGateway|AuditProducerSignal)' -count=20 ./...`
  passed after replacing a context-timeout `WaitGroup` waiter exposed by the
  first race run. This is engineering evidence, not CODEOWNERS approval.
- The follow-up shutdown-race regression first failed because the queued event
  emitted after dependency closure. After task cancellation/re-check and
  context-aware DB/transport changes, it passed 50 focused Windows runs. The
  lifecycle set passed 50 Windows runs and 20 Linux race-detector runs; the
  updated CI gateway selection passed in Linux against the local Redis service.
  `go vet ./...` and `go build ./...` also exited 0.
- Failure-injection regressions now cover total spill failure, partial append with
  successful rollback/retry, post-sync close failure, and rollback failure. All
  audit-drain tests passed 50 Windows runs; the lifecycle set passed 50 Windows
  runs and 20 Linux race-detector runs. The exact updated gateway CI selection
  passed in Linux Docker against the running Redis service. `go vet ./...` and
  `go build ./...` also exited 0 after the final state-machine change.

## Risk, growth and rollback

The new production lines coordinate work that the existing sequential loop and
HTTP-only drain could not handle; existing scanner, Requests, audit emitter and
resource clients are reused. Most added lines are regression tests, including a
real local HTTP benchmark; deleting those would remove acceptance evidence.
Material positive net line growth is 1,187 non-prose lines (408 production, 779 tests),
so owner exception review is required.
Unrelated working-tree edits are excluded from the T14 scope.
Production diff: 557 additions / 149 deletions across ten files (Git numstat,
excluding the pre-existing two-line DB revision replacement). Changed production
files range from 124 to 1,076 physical lines, below the 10,000 code-line per-file
cap even counting blanks/comments. Tokei is unavailable locally; the canonical
whole-repository Tokei budget check remains a CI requirement.

Monitor aggregate concurrent workflows, analyzer capacity and graceful termination
duration after rollout. Roll back scan parallelism with `EVIDENCE_SCAN_WORKERS=1`;
revert only the T14 patch to roll back lifecycle changes. No data migration or
backfill is needed. Existing tenant-prefix selection and caller-thread persistence
are preserved; these tests do not establish database RLS correctness.

Pending release evidence: full service/PostgreSQL integration, real deployment
SIGTERM and AWS/Presidio workload measurements, CI and component/risk-owner reviews
(`@KunalTF`, deputy `@VidhiTF`). No deployment, merge, human approval or live AWS
evidence is asserted here.
