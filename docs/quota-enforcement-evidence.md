# Quota enforcement work record

## Engineering rules and prerequisite

T01 activation verified with the bundled Python runtime running
`scripts/repository_policy.py --verify-github` on 2026-09-17. Authenticated
GitHub evidence: PR 52, reviewed commit
`b8b23993a7a467396598eefdd23b97da83d47042`, merged commit
`1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
`2026-09-16T12:57:25Z`; active ruleset 21141288, zero bypass actors.

## Scope

Confirmed security risk by direct source inspection: agent main middleware
catches downstream exceptions and executes the handler again; limiter failures
fall through; unknown/failed plan lookup selects enterprise; Redis INCR and
expiry are separate. Runtime reproduction and acceptance tests are recorded
below when executed. No claim of human acceptance is made.

## Existing-code reuse

Searched agent main middleware, tenant authentication/context, tenant plan
service, provider router/providers, document processing, startup validation,
gateway atomic_rate_limit.go/rate_limit.go, and existing observability rules.
Reuse verified tenant boundary, SQL tenant scoping, existing plan constants,
provider HTTP seams, environment validation entry point, and Redis Lua atomic
pattern. Do not import backend application code into agent or gateway.

## New-line justification

Before implementation: modify existing ingress/auth/startup/health seams and
remove the permissive limiter. A small agent-local quota module is necessary:
the existing Go single-counter script cannot be imported into Python, nor can
separate INCR operations enforce independently atomic tenant/user/key admission.
Provider call sites require admission at each actual external attempt, separate
from ingress. Tests and operational evidence require independent failure seams.
This is not semantic-duplicate consolidation.

## Enforcement contract

Agent tenant authentication is the canonical ingress boundary for all protected
routes, including aliases and internal routes. Existing public/authentication
endpoints retain their access contract; exact existing liveness remains public.
No gateway marker or private network address grants quota exemption.
JWT/signed principal user identities are verified. API keys have no human-owner
column and are service credentials: their verified key hash identifies the key,
and all tenant service keys share a service-principal user bucket. JWT sessions
have user and tenant buckets; no synthetic per-token key bucket is introduced.
Every subject is tenant-scoped. Actual external provider attempts consume a
separate aggregate tenant expensive-model bucket; all external models are
conservatively expensive, so aliases/fallback cannot avoid classification.
Gateway counters remain separate edge-abuse controls, not canonical ingress.

## Schema and rolling-deployment compatibility

No database schema changes. Atomic multidimension admission requires a new
Redis tenant hash tag and key namespace; old tenant counters lack a Cluster hash
tag and cannot safely join the script. Drain protected traffic, replace all old
replicas, verify readiness, wait at least the old quota window before reopening.
Do not run a mixed fleet or claim preserved windows. Quota outages return 503;
clients should use bounded exponential backoff with jitter and Retry-After.

## Risk

Redis outages deliberately stop protected work. First-admission fixed windows
and new keys change boundary behavior. Strict configuration can prevent startup.
Conservative model classification may reject previously admitted cheap models.

## Rollback

Drain traffic and keep it closed while recovering Redis or deploying a reviewed
fail-closed patch. Never restore the old permissive middleware. Reuse the new
namespace and configuration; if keys change, drain for a full window again.

## Reviewer sign-off

Pending independent human agent owner, gateway/platform-security owner and
affected consumer review under CODEOWNERS. AI assistance is not approval.

## Test evidence

Baseline characterization executed the actual `HEAD` enterprise middleware with
I/O seams: a downstream exception produced HTTP 200 and two downstream calls;
a Redis timeout produced HTTP 200 and one downstream call. The current HTTP
boundary tests assert one call on success/handler failure and zero calls after
denied or indeterminate admission. Main application imports/database boot were
isolated, so this is precise boundary evidence rather than full application boot.

The combined agent regression command is:

```powershell
$env:PYTHONPATH='services/agent'
$env:QUOTA_TEST_REDIS_URL='redis://127.0.0.1:16379/0'
.quota-venv/Scripts/python.exe -m unittest discover -s services/agent/smoke_tests -p 'test*quota*.py' -v
```

The retained [agent test output](../evidence/quota/agent-tests.txt) passed 46 tests.
It includes real Redis 7.4.7,
atomic multidimension admission, concurrent clients, corrupt/invalid Redis state,
expiry, socket timeout before execution, dropped response after execution,
recovery, actual ASGI boundary functions, provider zero/one invocation assertions,
tenant binding, and monitoring failure propagation. Six existing provider
compatibility/logging tests passed separately. Python compilation succeeded for
changed agent paths. The 52 repository-policy, delivery-control, and Compose
contract tests passed; Compose configuration and changed YAML parse checks passed.
The final [Go command](../evidence/quota/gateway-command.txt) and
[output](../evidence/quota/gateway-tests.txt) passed 43 top-level tests and 41
subtests, with zero failures or skips. This covers actual Redis concurrency,
independent dimensions, provider invocation counts, five authenticated protocol
contracts, streaming recovery, routing, readiness and strict configuration.
Authentication/credential/policy/audit database calls use existing test seams.
Initial fixture failures exposed JSON-key ordering and streamed delta framing
from existing authenticated response protection; final assertions compare full
JSON values and reconstructed stream content while retaining exact provider
request and invocation checks. Go formatting and diff checks passed.
After the combined agent run, stricter allowed-response remaining validation and
its regression case passed all 12 core tests again; see
[final core output](../evidence/quota/core-final-tests.txt).

[Core load](../evidence/quota/core-load.json) offered 300 requests per dimension
to three processes sharing Redis with quota 17: each dimension admitted exactly
17 provider calls and rejected 283, with zero unavailable decisions. Expensive
model testing admitted all ingress before independently limiting provider calls.
Refused Redis yielded zero provider invocations and recovered successfully.

[HTTP replica load](../evidence/quota/http-load.json) used three real uvicorn
processes running the actual extracted ingress boundary with verified-auth/plan
fixtures and a deterministic provider. All quota bounds held. Local Docker
contention produced substantial 503 responses at the real 250 ms timeout:
tenant/user/key/model stages had 82/278/159/33 unavailable responses out of 300.
This is an explicit capacity risk, not a latency/SLO pass. Outage traffic had
zero downstream/provider invocations; recovery restored admitted execution.
Full database-backed deployable load and production capacity validation remain
unverified. Earlier overlapping integration runs failed under this contention;
the final isolated combined run passed.

[Alert evidence](../infra/observability/quota-rehearsal-evidence.json) records
successful promtool tests and actual Prometheus/Alertmanager delivery of both
firing and resolved alerts to `approved-local-quota-test`. The user authorized
choosing the receiver; it was isolated on a private Docker network. Root verified
the checked-in rule hash, receiver identity and both resolutions after deliberate
recovery at `2026-09-17T06:03:35.638Z`. No production paging was triggered.
Earlier scrape-drop resolutions are excluded from accepted recovery evidence.
See [alert run record](quota-alert-evidence.md) for details and limitations.

Review follow-up added the production deployment path. Terraform validation and
an applyable synthetic plan proved regional managed Prometheus, private DNS
scraping of every agent/gateway replica, checked-in rule installation, SigV4
remote write, least-privilege Alertmanager SNS routing, and resolved delivery
configuration. CI now inspects its own plan for this complete chain. The retained
[plan summary](../evidence/quota/terraform-observability-plan.json) is deployment
configuration evidence, not an AWS apply or production notification claim.

The formal security diff scan completed with full scoped coverage and identified
one low-severity wildcard AMP workspace trust in the new Alertmanager role. The
trust now references the exact quota workspace ARN, and the Terraform plan
assertion rejects a return to wildcard workspace trust. The sealed pre-fix scan
is retained outside the repository as scan `06154c51-356c-4064-91fa-ca47c419d691`.

Legacy burst/minute/day 429 responses now increment the shared quota rejection
and decision counters before returning. A real-Redis middleware test verifies one
downstream call followed by a legacy denial and the exported alert numerator.
Scheduled document monitoring is disabled by default and cannot start without an
explicit positive tenant ID; enabled polls restore required tenant context,
retry quota failures, and export status/failure/last-success metrics.

Checksum-verified Tokei 12.1.2 produced the full
[line report](../evidence/quota/tokei.json); the root reran the repository checker
against it and received `Line budget OK`. Counts use Tokei code lines per file,
matching repository enforcement, not a sum across each directory.
Final per-file additions/deletions are retained in
[line-growth evidence](../evidence/quota/line-growth.json). The material-growth
exception still requires independent current-head owner approval.

## Remaining release gates

Independent current-head human component/security/consumer/governance approvals,
the required line-growth marker, final PR CI/merge evidence, physical PostgreSQL
RLS regression, and full deployed capacity/rollout testing remain pending. Local
fixtures and AI review cannot establish those facts. The change is not deployed.
