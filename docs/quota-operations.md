# Quota operations and release evidence

Reuse decisions (recorded before implementation): gateway/rate_limit.go owns edge
abuse windows, gateway/atomic_rate_limit.go owns the Redis script and failure
counters, gateway/auth.go supplies verified identities and environment validation,
and gateway/main.go owns exact health routes. Extend these seams; do not import
Python agent application packages into the Go gateway. Existing
infra/observability/acl21-alerts.yml establishes Prometheus rule conventions.
Existing scripts/gateway_latency_benchmark.py measures HTTP latency but does not
assert independent quota accounting, provider invocation counts, or replica
sharing; it cannot substitute for the required quota load rehearsal.

The gateway's existing v2 per-key edge abuse windows remain distinct from the
agent ingress and provider quota ledgers. Existing edge denial attempts increment
windows sequentially; preserving those counters avoids resetting deployment
windows. Do not describe those legacy counters as atomic multidimension quotas.

Operational acceptance requires real Redis replica load, outage and recovery plus
alert firing/resolution and delivery to an approved test receiver. The isolated
local receiver chosen under user authorization received both alerts firing and
resolved; see [quota-alert-evidence.md](quota-alert-evidence.md). This controlled
metric rehearsal does not establish production notification delivery.

Roll out during a controlled drain. Mixed old/new agent replicas are not safe:
old code can bypass admission, and new key formats start fresh quota windows.
Drain protected traffic, deploy all enforcement replicas with reviewed limits,
verify readiness, then gradually restore traffic. Rollback must keep enforcement
and fail-closed dependency handling; drain or serve controlled 503 responses if a
known-good enforced version is unavailable. Never disable limiting to recover.

During Redis failure, keep exact GET /health liveness available; readiness must
return 503 and protected work must not execute. Clients should respect Retry-After
and use bounded exponential backoff with jitter; avoid immediate retry storms.

Release evidence must include current-head component/security/consumer approvals,
T01 verifier output, production line growth and owner exception where applicable,
and the existing PR template. Local tests and AI review do not replace approval.

Gateway quota domains: `authclaw:gateway-quota:v1` independently governs HTTP
requests admitted at the authenticated Go boundary. Agent workflow ingress uses
`authclaw:quota:v1`. These are distinct quotas, including when an agent calls the
gateway. Actual provider attempts share the `authclaw:quota:v1` expensive_model
bucket only when the verified tenant identifiers are identical. A mapping between
external tenant IDs and internal agent tenant IDs is not assumed. All provider
models, including unknown aliases, are conservatively considered expensive.
GatewayProvider must leave provider admission to Go; locally resolved fallback
providers must be admitted in the agent before each provider attempt.

New gateway multidimension quotas use tenant SHA256 Redis Cluster hash tags;
all tenant/user/key counters are checked before any are incremented. Rejected
admissions do not charge this ledger. Counters expire 60 seconds after first
admission, rather than at wall-clock minute boundaries. Service principals share
the tenant service-user dimension and must retain a verified key. Egress admission is independent
of ingress consumption and happens immediately before proxy execution.

The gateway additionally exposes process-local Prometheus counters at
GET /health?metrics=true; this scrape performs no database or Redis request.
The availability gauge starts at zero and changes on admission/readiness probes.
Scrape /ready independently to refresh health during idle periods. There is no
new unauthenticated /metrics or internal operational exemption.

The trusted agent provider-ledger mapping resolves internal tenant IDs to
control_plane_id from the tenant database. This matches the Go authenticated
external tenant ID for shared provider accounting. Unmapped standalone agent
tenants use agent:<internal-id>; client identity headers do not establish mapping.

New production-line justification: gateway/quota_admission.go cannot reuse the
single-counter increment script as atomic independent admission; the existing
script charges before checking and cannot avoid partial charging across counters.
The new script mirrors the standalone cross-language quota contract without an
application-package dependency. Existing v2 edge windows remain intact for
rollout compatibility. gateway/proxy_test.go now characterizes RouteRequest
selection without executing unauthenticated upstream calls. The Redis quota test
uses a local HTTP provider stub and asserts exactly one invocation for one
admission followed by rejection. This does not claim coverage of the complete
PostgreSQL-backed credential, policy, audit, and proxy integration.
