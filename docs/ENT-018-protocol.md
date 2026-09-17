# ENT-018: service request HMAC v2

Reuse: extend control_plane_auth, agentFetch, existing Redis and managed ECS secret
injection. New lines are necessary for content binding, key scope and replay
enforcement; header-only v1 cannot enforce those invariants. No new dependencies.

HMAC-SHA256 signs the UTF-8 newline-joined sequence (no trailing newline):
`authclaw:service-request:v2`, timestamp, nonce, service, audience, key ID, method,
raw URL-encoded path, canonical query, hex SHA-256 of body bytes, Content-Type,
tenant ID, actor ID, role. Control characters are forbidden in signed fields.
Role spelling is authenticated before normalization. Empty body hashes empty bytes.

X-AuthClaw headers: Version=2, Timestamp (10 decimal Unix-second digits), Nonce
(32 lowercase random hex characters), Service=console, Audience=agent, Key-ID,
Tenant-ID, User-ID, Role, Signature (64 lowercase hex characters). Duplicates fail.
Query components are strict UTF-8 form-decoded (+ means space), RFC3986-encoded,
and sorted by encoded name; duplicate-name value order is preserved. Empty values
remain explicit. Invalid percent escapes/UTF-8 and empty query pairs fail closed.
The receiver never normalizes or decodes the signed path.

AUTHCLAW_INTERNAL_SERVICE_SECRET becomes a JSON ring: `active_key_id`, `keys`.
Each key entry has `secret` (minimum 32 UTF-8 bytes), `service`, `audience` and
`endpoints` (exact method/raw-path strings, e.g. `GET /remediation/findings`).
Values are managed in Secrets Manager and injected only into console and agent;
never put real key values in Terraform state. Request inputs cannot select scope.

Timestamp skew is at most 60 seconds against both the receiver and Redis clock.
Redis rechecks the timestamp atomically so differences between receiver clocks
cannot extend acceptance beyond nonce retention. Atomic nonce consumption retains
each service/audience nonce for 121 seconds after acceptance, covering the entire
120-second earliest-to-latest timestamp window including its boundary. Key ID is
not part of nonce uniqueness. Replay-store outages fail closed; no memory fallback.

Rotation: provision old+new keys with old active; roll all receivers; switch active
ID and roll senders; drain old senders and wait at least 121 seconds; remove old
key and roll receivers. Rollback during overlap switches active ID back. Never
reuse an ID for different material. ECS secrets refresh on task replacement,
not automatically on secret edits. No v1 fallback: initial upgrade requires
coordinated cutover or isolated v2 capacity before routing v2 traffic.

Local rotation/interoperability tests are not live AWS deployment evidence.

Redis must use noeviction. On a new Redis process/replication generation (including
re-promotion of the same process), authentication returns 503 for 122 seconds after first use,
waiting out signatures whose nonce history may be missing. Do not delete nonce
keys or restore partial cache snapshots on a running node. Resource exhaustion
and Redis errors fail closed. Deployment smoke must verify this recovery window;
availability during cache recovery is deliberately secondary to replay safety.
Redis clocks must be synchronized without backward time steps during service.

Local compose requires an explicit JSON ring in AUTHCLAW_INTERNAL_SERVICE_SECRET;
there is no default signing credential. Current console endpoints are
`GET /api/v1/agent/health/ready`, `GET /remediation/connectors`, and
`GET /remediation/findings`. Additional method/path pairs require explicit key
policy approval. Do not place production secrets in shell history or docs.

## Verification record — 2026-09-17

Implemented from master `45976f00fd04170f926e570a9ac99fc6574da931` on
`feat/ent-018-hmac-v2`. Local verification, not deployed acceptance:

- Agent smoke suite: 44 passed. Set PYTHONPATH=services/agent and
  ENT018_REDIS_URL to a dedicated disposable localhost Redis, then run
  `python -m unittest discover -s services/agent/smoke_tests -q`.
  A psycopg database URL selects the installed driver; no live database needed.
- Seven protocol tests include body/query/path/method/tenant/actor/role tampering,
  service/key/endpoint scope, malformed and duplicate headers, oversized bodies,
  TLS defaults, timestamp boundaries, replay and cache-outage rejection.
- Real Redis rehearsal: startup denies access; after the simulated recovery
  interval, exactly one of 16 concurrent nonce claims succeeds; replay fails and
  TTL covers the full acceptance window. Redis uses noeviction.
- Real Node signer/Python verifier rehearsal: four request vectors each under
  old, new, then old active keys (12 acceptances), including Unicode bodies and
  duplicate query parameters. Separate retirement rejects old keys; nonce reuse
  across key IDs fails. This rehearses the protocol, not ECS rolling deployment.
- Existing evidence-access tests: 17 passed. CI-plan, direct-AWS contract and
  repository-policy unit suites: 53 passed. Terraform validate and all 20 mock
  tests passed; no infrastructure was applied.
- Exact agent CI pytest selection: 29 passed plus 20 subtests, with Redis
  enabled. Initial local attempts lacked psycopg2 or waited on the deliberately
  unavailable database; selecting installed psycopg and `connect_timeout=2`
  resolved those test-environment issues. The existing Starlette/httpx
  deprecation warning remains; no dependency changes were needed.
- Console unit suite: 45 passed; TypeScript checking, targeted signer/client
  lint and production build passed. Agent CI now provisions Redis and Node;
  console signing changes also select the agent interoperability suite.

Reuse/simplification removed repeated verification from main.py (net -17 lines)
and shortened agentFetch (net -4 lines). Net overall growth is necessary for
the protocol, replay boundary and negative-case evidence; no new dependencies.
Initial application-code diff: 225 added / 83 deleted lines (+142), counting Git's
normalized numstat for the three modified runtime files plus the new 42-line
signer, before the review corrections below. Infrastructure, CI and tests are additional. Changed console source
files have 42 and 302 physical lines, conservative upper bounds below the
10,000-code-line per-file budget; the authoritative Tokei CI gate remains pending.
Material-growth and component/security/governance owner approval remain required.
Tenant identity comes from the validated backend session and authenticated tenant
header; existing transaction tenant context/database enforcement is unchanged.

Before deployment: generate independent high-entropy keys (at least 32 random
bytes), provision the JSON ring in the existing managed secret, review the Redis
7.1/noeviction plan, coordinate the v1-to-v2 cutover, and rehearse rotation and
Redis failover on AWS. No live secret was changed. Roll back a rotation using the
overlapping old key; rolling back the protocol requires coordinated sender and
receiver deployment, never an unauthenticated fallback. TLS is required for the
replay store unless local/development/test is explicitly selected.

## Adversarial review corrections

Reproduced and fixed valid signed requests returning 500 because RBAC ran before
authentication. The existing tenant middleware now authenticates, resolves tenant,
and enforces existing RBAC rules in order with one error boundary; invalid roles
return 403 rather than unhandled 500. Removed the separate RBAC middleware and
redundant public-path check. Tenant lookup runs off the async event loop.

Real Redis demotion/re-promotion reproduced reuse of an already-aged recovery gate;
the gate now binds process and replication generation. A receiver-clock-skew test
also reproduced acceptance outside the shared window; Redis now enforces timestamp
acceptance inside the atomic nonce script. Both tests failed before their fixes.
Source-extracted middleware tests exercise actual declaration order, valid signed
access, one-time authentication, tampering, denied role, and off-loop DB resolution.
These fixes reuse the existing middleware, RBAC policy, threadpool and Redis script;
no new production helper, dependency, or alternate authentication path was added.

Final review verification: 45 agent smoke tests, 30 exact-CI agent tests plus
20 subtests, 17 evidence-access tests, 53 deployment/policy tests, 45 console
tests, and 20 Terraform mock tests passed. TypeScript, targeted ESLint, production
console build, Python compilation/formatting and diff whitespace checks passed.
An independent read-only adversarial reviewer repeated the actual middleware test
and found no additional material defect after corrections. This is not a human
owner approval or live AWS verification.

Final application-code diff: 238 added / 106 deleted lines (+132 versus master),
10 fewer production lines than the pre-review implementation despite the added
replay safeguards. Extra regression-test lines are intentional. Infrastructure
and CI growth still require the existing material-growth review gate.

## Integration with master 0103304 (quota enforcement)

Merged the updated master without dropping its fail-closed tenant/user/key quota
admission. Authentication and RBAC precede quota admission; a missing tenant is
401, exhausted quota is 429, and unavailable authentication/quota state is 503.
The existing signed-request regression now also exercises quota denial and outage.
CI reuses one disposable Redis service for both suites and retains Node setup.

Fresh integrated checks: 93 agent smoke tests; 78 exact Agent CI tests plus 48
subtests; 41 focused signing/quota/evidence tests plus 13 subtests; 78 policy tests;
45 console tests and TypeScript checking; 20 Terraform tests all passed. An initial
Agent CI invocation from the repository root failed two policy tests because
policies.yaml is relative to services/agent; rerunning from CI's working directory
passed. This was an invocation error, not a product change. Prior line counts and
baseline references above describe the initial implementation; the PR growth map
is regenerated against the updated master for current-head owner approval.
