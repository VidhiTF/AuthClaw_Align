# Fail closed on quota admission across agent and model gateway

Prepared with `.github/pull_request_template.md` for independent review.
Deployment and human approval remain pending.

## Jira

Issue: N/A; the request supplied an implementation plan without a Jira identifier.
Source: user-provided six-step quota enforcement plan. Classification: confirmed
security defect plus associated operational debt. Baseline execution reproduced
two handler invocations after a downstream exception and a successful handler
invocation after a Redis timeout.

## Engineering rules and prerequisite

T01 is active. The authenticated activation verifier confirmed PR 52, final
reviewed head `b8b23993a7a467396598eefdd23b97da83d47042`, merged commit
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, UTC effective date
`2026-09-16T12:57:25Z`, active ruleset 21141288, and zero bypass actors.
See [work record](quota-enforcement-evidence.md).

## Scope

Canonical agent ingress now admits verified tenant/user/key dimensions before
downstream execution. Go gateway enforces separate edge dimensions and actual
provider attempts. External models are conservatively expensive, including
aliases and fallback models. Provider retries require fresh provider admission.
401/403 remain authentication/authorization failures; quota exhaustion is 429;
unavailable or indeterminate admission is 503. No gateway marker or internal
prefix bypasses enforcement. Documentation, configuration, tests, and monitoring
changes support this single contract.
Regional Terraform installs the rules in Amazon Managed Prometheus, runs a
private ECS scraper for every agent/gateway replica, and routes managed
Alertmanager notifications only to approved regional SNS topics.

## Customer impact

Redis outages stop protected requests. Invalid plans and missing configuration
no longer receive enterprise defaults or memory fallback. Previously unbounded
users, keys, model calls and document paths can now receive 429. A background
watcher without verified tenant ownership cannot perform remote model work.
Local development must explicitly opt into memory limiting.

## Release notes

Release note: protected traffic now fails closed during quota dependency outages;
configure positive quotas and distributed Redis before deployment, honor
Retry-After, and use dependency readiness to gate traffic. Quota ledgers use new
keys and require a drained rollout; all external models share the expensive-call
budget. Independent human release acceptance is still required.

## Schema and rolling-deployment compatibility

The startup migration removes legacy enterprise defaults from all tenant plan
columns. It reconciles valid conflicting values to the least privileged plan and
revokes untracked all-enterprise values that cannot prove an entitlement. New
registrations explicitly receive the free plan. Operators must re-authorize
revoked enterprise tenants through the audited plan update before reopening
traffic. Reuse the existing tenant `control_plane_id` binding to share the
provider ledger across agent and Go. Unmapped agent-local tenants use `agent:<id>`
to prevent identifier collisions. New multi-counter Redis keys use a SHA256
tenant hash tag and expire 60 seconds after first admission. Denials do not
increment the new ledger. Legacy Go edge attempt counters remain separate and
retain their original denied-attempt accounting.

Drain protected traffic, replace all old replicas, verify readiness, wait out
the former window, then reopen gradually. Mixed versions can bypass or disagree
about limits and must not serve concurrently. Gateway ALB health checks use
`/ready`; liveness remains `/health`. No data backfill is required.

## Existing-code reuse

Reused agent authentication/tenant context, plan constants, provider HTTP call
sites, worker executor, startup validation, health/metrics endpoints, and Go
Redis atomic-script patterns. Modified existing middleware rather than adding a
second ingress limiter. Removed permissive exception/fallback paths and the old
agent INCR/EXPIRE limiter. Existing gateway edge counters remain intact.
See [core notes](quota-core-notes.md), [egress notes](quota-egress-notes.md), and
[operations](quota-operations.md) for searches and decisions.

## New-line justification

Necessity was recorded before implementation in the work record and component
notes. A single-counter script cannot implement all-or-none independent
tenant/user/key admission. Separate deployables require their own language
implementations; importing another deployable's application package is avoided.
Additional call-site guards prevent document, embedding, retry, and direct-Go
bypasses. Tests exercise actual Redis and handler/provider side effects.
Final per-file growth and checksum-verified Tokei evidence are retained in
`evidence/quota/line-growth.json` and `evidence/quota/tokei-result.txt`; the
repository line-budget check passed.
No semantic duplicate removal is performed; its merge protocol is inapplicable.

## Security and compliance

Quota subjects come from verified JWT, signed control-plane authentication or
verified API keys, never client identity headers. Agent API keys have no human
owner column and share a tenant service-principal bucket plus independent key
buckets. Database tenant binding is scoped to the authenticated tenant.
Shared environments require distributed limiting, valid positive limits and
Redis TLS except loopback sidecars; memory fallback is explicit isolated use.
250 ms socket/connect limits and disabled Redis retries bound ambiguous writes.
Metrics have no tenant, user, key, or model labels and health scrapes do not
access the database or Redis. Quota telemetry moved off public health routes to
an exact internal endpoint authenticated with a dedicated KMS-protected scrape
credential.

## Material line-growth exception

This change exceeds 100 positive added lines across production, tests and tooling.
The final worktree has 982 production lines added and 258 removed. Positive
non-prose growth is 3,532 lines including tests, configuration, tooling and raw
evidence; deletions in other files do not offset this policy measure.
Atomic admission, independent failure tests, and operational rehearsal require
growth; unrelated deletion cannot offset it. Final per-file counts are recorded
with integrated evidence. Independent current-head owners must approve the exact
marker from `scripts/repository_policy.py --pr-evidence <PR-number>` after the PR
exists. No marker or approval is fabricated for an uncommitted worktree.

## Tenant isolation evidence

Redis hash tags scope every subject to its verified tenant. Tests exercise
multiple users, multiple keys, distinct tenants, and each independently exhausted
dimension. The provider ledger uses an existing database tenant binding, not a
request header. Monitoring queries and pipeline calls preserve verified tenant
scope. Existing database RLS and transaction context remain the database control.
Physical PostgreSQL role/RLS cross-tenant reads, inserts, updates, exports and
similarity-search regression are not demonstrated by these isolated quota tests;
they remain required before release. Redis tests do not claim database isolation.

## Test evidence

See the [work record](quota-enforcement-evidence.md) and component evidence for
commands, results, and limitations. The original HEAD middleware was executed
with injected downstream and Redis failures to characterize the bypass. New
ASGI tests execute the actual selected production boundary definitions with
authentication/database seams isolated; 48 focused agent quota tests pass.
Provider tests assert zero calls on
denial and one on success. Real Redis tests cover atomicity, expiry, corrupt
state, timeouts, recovery, and concurrent independent clients.

Three HTTP fixture replicas shared real Redis under above-limit offered load.
They preserved quota bounds but the busy local Docker host caused substantial
503s at the deliberate 250 ms timeout. This is not a production latency/SLO pass.
Full deployed database-backed gateway/agent load and final CI remain required.
The alert rehearsal uses unchanged Prometheus rules and an approved local
receiver; final firing/resolution evidence is retained separately.
Terraform validation, all 20 native tests, and a complete synthetic deployment
plan verify the managed workspace, scrape discovery, rule installation,
remote-write IAM, Alertmanager, exact-workspace role trust, authenticated
scrape-secret isolation, and concrete SNS route. No shared AWS apply or production
SNS delivery is claimed.

## Risk

Quota dependency outages deliberately become protected-request outages. Measured
local contention caused significant 503s and requires capacity/timeout validation
on deployment hardware. Ambiguous writes may consume a slot without execution.
New windows, service-principal treatment, unknown-plan rejection, conservative
model classification, and background tenant requirements change behavior.
Readiness probe settings and client backoff must avoid restart/retry storms.

## Rollback

Drain protected traffic first. Recover Redis or deploy a reviewed version that
retains atomic admission and fail-closed errors. Preserve the new namespace and
configuration; if a key format changes, drain for a full window before reopening.
Never roll back to the old bypass, disable limiting, or enable memory mode in a
shared environment. Keep traffic closed if no safe version is available.

## Reviewer sign-off

Implementer: Codex acting for the requesting engineer; GitHub author: KunalTF.
Review requested from VidhiTF and RaviiTF. Required independent humans: agent owner/deputy,
gateway/platform-security owner/deputy, affected consumer owner, and governance
custodians for CI changes. CODEOWNERS assigns VidhiTF/KunalTF to agent,
KunalTF/VidhiTF to gateway/platform, and RaviiTF/VidhiTF to consumer/governance.
The author cannot satisfy their own review role. Reviewed commit, approval links,
line-growth exception, final acceptance, and merge evidence remain pending.

## T01 completion record (T01 only; otherwise N/A)

N/A: this is downstream quota implementation. T01 activation evidence is retained
above; it does not constitute approval of this implementation.
