# Agent quota core reuse and contract

Before implementation, inspected agent `main.py` rate limiting, startup validation,
`services/worker_throttle.py`, tenant plan resolution, and backend
`app/services/abuse_controls.py`. The backend demonstrates single-call Lua and
versioned hash-tag keys. Its single-counter increment charges denied requests and
cannot atomically admit three independent dimensions. Importing its application
package would couple deployables. A small agent-local core therefore follows its
Lua/TTL pattern with preflight of every counter before any mutation; worker
throttling tracks concurrent database jobs and cannot enforce request quotas.

Ingress charges tenant plus applicable authenticated human/service-principal user
and API key counters. Provider admission charges a separate aggregate tenant
expensive-model counter; every external resolved model is conservatively expensive,
so changing aliases, models, or providers cannot multiply available capacity.
The caller supplies verified identities; service principals without human users
must supply their stable verified principal ID or use their verified key dimension.

Counters use `authclaw:quota:v1:{sha256(tenant)}:<dimension>:<sha256(subject)>`.
The tenant hash tag colocates the atomic script's keys in Redis Cluster. Redis
server TTL supplies fixed 60-second windows beginning with first admission, avoiding
replica-clock boundary disagreement. All applicable counters must permit admission;
denial charges none. Invalid counter values/TTLs and uncertain responses fail closed.
Connection and socket timeouts are 250 ms, with zero automatic retries, including
ambiguous writes. An ambiguous execution may consume quota without executing work.

These keys are new and cannot preserve legacy per-process counters. Drain old
replicas, wait a full legacy window, then enable the new fleet together; mixed
fleets are unsupported. Rollback must retain fail-closed enforcement. The memory
backend is thread-safe and requires explicit isolated-development opt-in. Process
metrics do not call the database or Redis, and expose no subject identifiers.

## Local verification, 2026-09-17

Ran `services/agent/smoke_tests/test_quota_service.py`: 11 unit tests passed.
Ran `test_quota_redis.py` against isolated Redis 7.4.7: five integration tests
passed, covering separate clients, exact concurrent admission, each dimension,
denied-request noncharging, expiry, corrupted counters/TTLs, and a real write
followed by an injected lost response (one attempt, no downstream admission),
and an actual blackhole TCP connection timeout before execution with recovery.

Ran `quota_load.py` with `QUOTA_TEST_REDIS_URL=redis://127.0.0.1:16379/0`.
Three worker processes each offered 100 calls per dimension against real Redis.
With the selected dimension limited to 17, tenant/user/key stages each admitted
17 ingress and 17 provider invocations, rejecting 283; expensive-model stage
admitted 300 ingress and 17 provider invocations, rejecting 283. No availability
failures occurred. Measured p95 total admission latency in milliseconds was
34.643 tenant, 24.648 user, 28.309 key, 43.324 expensive-model. Cold maximums
were 638–812 ms including first dependency import; these are observations, not
latency SLO evidence. Refused Redis connection injection yielded ten unavailable
decisions and zero provider calls; restoration yielded ten successful provider calls.

The load provider is a deterministic Python callable and replicas are independent
core worker processes. This does not claim deployed HTTP gateway/agent replica
load evidence or production alert notification delivery; those release acceptance
obligations require their own controlled rehearsal.

### HTTP fixture replica load

`quota_load.py --http` starts three distinct uvicorn processes on ephemeral local
ports, extracting the production `main.py` middleware with the existing HTTP
boundary test helper. Authentication and plan lookup are verified-context fixtures;
the downstream handler runs the real provider quota before its deterministic stub.
Six concurrent HTTP clients offered 300 requests per dimension, quota 17:

| Dimension | HTTP 200 | HTTP 429 | HTTP 503 | Provider calls | p95 ms |
|---|---:|---:|---:|---:|---:|
| Tenant | 17 | 201 | 82 | 17 | 279.643 |
| User | 12 | 10 | 278 | 12 | 488.407 |
| Key | 17 | 124 | 159 | 17 | 529.031 |
| Expensive model | 17 | 250 | 33 | 17 | 563.699 |

This shared development host experienced frequent real 250 ms Redis timeouts.
Ambiguous writes can consume quota without invoking the provider, explaining fewer
than 17 successful user requests. These availability failures are measured release
risks, not successful-capacity evidence. No stage exceeded its provider quota;
ingress-limited stages executed downstream only 17/12/17 times respectively.
Explicit refused-socket outage traffic returned 30 HTTP 503 with zero downstream
or provider invocations. Restoration returned 17 HTTP 200, 13 HTTP 429, and
17 downstream/provider invocations. Separate process IDs were captured by the
harness for each stage. Full database-backed deployable and staging SLO evidence
are still required. An integration-suite rerun overlapping this HTTP load failed
on real Redis socket timeouts; it must run independently on a healthy dependency.
The final separate run passed all five integration tests in 1.699 seconds.
Test setup/inspection uses a two-second administrative timeout, while the
production admission implementation retains 250 ms connect/operation timeouts.
The after-write injection uses the setup connection to guarantee an actual write
before deliberately losing its response; the blackhole test exercises the
production connection timeout itself.

## Monitoring consumer correction

Review found `sync_sources` swallowed the newly propagated quota exceptions and
manual sync then reported success. Its background thread also lacks a verified
tenant and its document SQL was unscoped. Modify that existing consumer to require
the current verified tenant before work, bind existing document queries/writes and
pipeline/audit calls to it, and propagate quota failures. No new tenant resolver or
default owner is introduced. Unbound background monitoring is deferred until a
reviewed source-to-tenant binding exists. Global connector credential ownership
remains outside this quota change; this is not a complete connector authorization
or database RLS review.

`test_monitoring_quotas.py`: four runtime seam tests passed (0.100 seconds),
covering quota propagation, verified tenant propagation/scoped query parameters,
and unbound background refusal before I/O. Existing migration 1112 supplies the
document-findings tenant column; migration 1483 enables its RLS. These tests
validate application arguments, not PostgreSQL RLS behavior.

The current combined workspace passed `scripts/check_line_budget.py` using
Tokei 12.1.2 in a read-only container, with the release archive SHA-256 verified
against the checked-in CI pin. Highest covered file: console settings page,
2,124 code lines; highest gateway file: `redact.go`, 1,795 code lines.
