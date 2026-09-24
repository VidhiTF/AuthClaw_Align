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
ECS grants gateway and audit-producer containers 60 seconds before forced
termination, reserving 30 seconds after the application deadline for durable
audit spill and resource cleanup.
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
synced to a unique temporary file, then atomically renamed and directory-synced.
Immutable per-tenant ready files prevent separate gateway processes from
overwriting one another. ECS mounts an encrypted, backed-up EFS access point at
`/var/lib/authclaw-gateway` and sets `AUDIT_OUTBOX_PATH` there, so task replacement
does not discard recovery records. A successful authenticated request schedules
recovery without waiting; one process-wide worker drains a deduplicated queue
bounded to 64 tenants. Saturated admission skips additional scheduling instead
of delaying the request; immutable recovery files remain durable and a later
audit schedules another attempt. The worker publishes only after restoring a
recovery record to the canonical outbox. It replays at most 100 records per fair
queue turn through the existing canonical idempotent append and automatically
requeues a remaining suffix. A partial file is atomically checkpointed to its
uncommitted suffix, so retries do not repeatedly scan an already committed prefix.
Stale complete temporary files
are promoted after restart; incomplete files remain visible as corrupt recovery
backlog. Upgrade recovery atomically claims and deterministically splits the former
multi-tenant NDJSON file. Backlog age/count, replay failures, and scan failures are
exposed on the authenticated metrics endpoint, scraped by the existing collector,
and covered by installed critical alert rules.

## Fresh local evidence (2026-09-23/24)

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
- Recovery regressions cover partial writes, failed replay retention, legacy
  multi-tenant migration, tenant-isolated restart replay, and eight simultaneous
  OS processes writing the same configured outbox path. The focused set passed
  repeated Windows and Linux runs and the Linux race detector. The exact gateway
  CI selection, `go vet ./...`, and ACL-21 promtool rule validation also passed.
- Follow-up recovery regressions cover concurrent legacy migration, stale complete
  and corrupt temp promotion, directory-sync indeterminacy without blind retry,
  authenticated metric exposure, and cancellation of the bounded background
  drainer. The new set passed 20 Windows runs and 10 Linux race-detector runs.
  Terraform format/validation and a CI-equivalent speculative plan passed; the
  plan contains the encrypted EFS filesystem, access point, and two-AZ mount targets.
- Final liveness regressions cover a pre-existing claimed legacy file, concurrent
  tenant scheduling (including a same-tenant rerun), bounded 65-tenant saturation,
  partial replay progress, and automatic continuation beyond 100 records. The
  final focused set passed 10 Windows runs and 3 Linux race-detector runs; the
  cross-process legacy migration test separately passed 50 Windows runs. The exact
  gateway CI test selection passed with disposable Redis, followed by clean
  `go vet ./...` and `go build ./...`. Terraform validation, the strengthened
  speculative-plan assertion, and all 20 Terraform tests also passed.
- Final review fixes classify an indeterminate directory sync as unavailable so
  post-response fallback retries, keep saturated recovery admission off request
  latency, skip transport publication when no record was restored, and reserve a
  60-second ECS stop window. The four focused regressions passed 50 Windows runs
  and 10 Linux race-detector runs. The broader lifecycle set passed 10 runs, the
  exact gateway CI selection passed with Redis, and Terraform format, validation,
  CI-equivalent plan assertion, and all 20 Terraform tests passed.

## Risk, growth and rollback

The new production lines coordinate work that the existing sequential loop and
HTTP-only drain could not handle; existing scanner, Requests, audit emitter and
resource clients are reused. Most added lines are regression tests, including a
real local HTTP benchmark; deleting those would remove acceptance evidence.
Material positive line growth remains subject to the repository owner-exception
gate. Unrelated working-tree edits are excluded from the T14 scope. Changed
production files remain below the 10,000 code-line per-file cap. The canonical
whole-repository Tokei budget check remains a CI requirement.

Monitor aggregate concurrent workflows, analyzer capacity and graceful termination
duration after rollout. Roll back scan parallelism with `EVIDENCE_SCAN_WORKERS=1`;
revert only the T14 patch to roll back lifecycle changes. No data migration or
backfill is needed. Existing tenant-prefix selection and caller-thread persistence
are preserved; these tests do not establish database RLS correctness.

Pending release evidence: real deployment SIGTERM and AWS/Presidio workload
measurements, CI and component/risk-owner reviews
(`@KunalTF`, deputy `@VidhiTF`). No deployment, merge, human approval or live AWS
evidence is asserted here.
