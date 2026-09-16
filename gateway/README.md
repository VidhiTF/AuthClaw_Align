# AuthClaw Gateway Service 🚪

The AuthClaw Gateway is a high-performance Go-based reverse proxy that intercepts and routes requests to LLM providers (OpenAI, Anthropic, Cohere, Azure OpenAI) under strict multi-tenant isolation, logging audit events for security and compliance.

## 🏗️ Architecture

- **Auth Middleware**: Extracts API keys from the `Authorization: Bearer <key>` header, hashes it with SHA-256, validates it against the control plane PostgreSQL database, and injects the resolved `tenant_id` into the request context.
- **Payload Normalization**: The adapter layer parses and normalizes provider-specific payloads (like OpenAI chat completions or Anthropic messages) into a generic structure to prepare for security audits and redactions.
- **Dynamic Routing**: Re-writes request headers and URLs to proxy the requests transparently to downstream endpoints.
- **Audit Logging**: Emits tenant-keyed traffic events with stable event IDs to Kafka (`gateway.traffic`) and falls back to stdout when Kafka is disabled.

## Sensitive-data policy enforcement

ACL-17 enforces tenant policy before model-provider egress. Supported actions are
`block`, `warn`, `redact`, and `require_approval`. A warning remains observable through
response headers and safe telemetry, but matching content is redacted before it is sent
to the provider. Normalization, analysis, tokenization, and request-rebuild failures are
fail-closed so the original request is never used as a fallback.

Gateway logs and audit traces contain identifiers, entity types, counts, actions, and
match fingerprints only; they do not contain raw prompts or matched sensitive values.
The metrics endpoint exposes policy block, warn, redact, and fail-closed counters. See
[`ADR-0008`](../docs/adr/0008-acl-17-gateway-policy-redaction.md) for the processing
order and rollback decision.

## Provider Compatibility

| Provider | Gateway route | Upstream auth injection | Streaming format |
| --- | --- | --- | --- |
| OpenAI | `/v1/chat/completions` | `Authorization: Bearer <provider key>` | OpenAI `data:` chat deltas |
| Anthropic | `/v1/messages` | `x-api-key` plus `anthropic-version` | Anthropic `content_block_delta` events |
| Cohere | `/v2/chat` | `Authorization: Bearer <provider key>` | Cohere `content-delta` events |
| Azure OpenAI | `/v1/chat/completions` with `X-Provider: azure_openai`, backed by a deployment-scoped endpoint, or direct `/openai/deployments/.../chat/completions` | `api-key` plus `api-version` query | OpenAI-compatible chat deltas |
| Gemini | `/v1/models/{model}:generateContent` | `x-goog-api-key` | Gemini candidate part deltas |
| AWS Bedrock (feature-gated) | `/bedrock/model/{model}/invoke` | AWS SigV4 | Model-specific invoke response |

For Azure OpenAI, save the provider credential endpoint as the deployment-scoped URL, for example
`https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions`.
Set `AZURE_OPENAI_API_VERSION` to override the default `2024-10-21` query parameter.
Bedrock uses only the `/bedrock/model/.../invoke` public form and remains disabled unless
the Bedrock feature flags, explicit tenant/model budgets, and AWS runtime credentials are configured.
See [Bedrock authorization and reservations](../docs/security/BEDROCK_VALIDATION.md).

---

## 🚀 Running Locally

### 1. Prerequisites
- Go 1.21+
- PostgreSQL database (running from root `docker-compose.yml`)

### 2. Start the Gateway
Ensure the database is running (`docker-compose up -d` in the project root). Then, start the gateway:

```bash
cd gateway
go run .
```

The gateway will start and listen on `http://localhost:8080`.

---

## 🧪 Testing

Run the full Go suite, which includes unit tests for health checks, payload extraction/re-serialization, database authentication checks, dynamic proxy routing, and payload fidelity contract checks:

```bash
cd gateway
go test -v
```

---

## 📡 Local curl Verification

To test the gateway locally:

### 1. Create a Test API Key (via Database)
Ensure you have created a tenant, a user, and a valid API key in PostgreSQL. You can verify this by running:
```sql
SELECT key_hash FROM api_keys;
```

### 2. Make a request
Run a curl command pointing to the local gateway (which will authenticate and proxy requests to target providers):

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <your_authclaw_api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Hello, gateway!"}
    ]
  }'
```

### 4. Run latency/load benchmarks

After the full stack is running and seeded, run the gateway latency benchmark
from the repository root:

```bash
python scripts/gateway_latency_benchmark.py --ci --provider-baseline-url http://localhost:19090 --require-provider-baseline
```

The benchmark is intended for `docker-compose.full.yml`, including Kafka,
ClickHouse, and the CI mock provider profile. It reports total p50/p95/p99 latency, p95 time-to-first-byte,
throughput, status-code counts, p50/p95/p99 provider-baseline overhead,
streaming first-byte overhead, SSE frame integrity, and threshold failures for
the default safe scenarios. The `--ci` profile keeps request volume below the
gateway's default rate limits; raise `GATEWAY_RATE_LIMIT_*` before using
larger request counts for heavier load tests.

Official local NFR thresholds are p95 <= 800ms, p99 <= 1000ms, and p50/p95/p99
gateway overhead <= 50ms for provider-pass-through scenarios at concurrency 5
against the local mock provider. Redaction transform scenarios and streaming
scenarios are recorded separately with explicit transform/stream thresholds
because they include PII analysis or SSE protection work, not only proxy
overhead. The CI/release gate sets
`REDACTION_LOCAL_ANALYZER_ONLY=true`, `AUTHCLAW_LITE_POLICY_REQUESTS_PER_MINUTE=0`,
`GATEWAY_RATE_LIMIT_ENABLED=false`, `GATEWAY_HTTP_LOGGER_ENABLED=false`,
`GATEWAY_AUTH_LAST_USED_ENABLED=false`, `GATEWAY_AUTH_CACHE_TTL_MS=60000`,
`PROVIDER_CREDENTIAL_CACHE_TTL_MS=60000`, and
`GATEWAY_POLICY_LOCAL_FAST_PATH=true`, `GATEWAY_POLICY_DECISION_CACHE_TTL_MS=60000`,
and `REDACTION_RUNTIME_CONFIG_CACHE_TTL_MS=60000`
to isolate gateway/proxy overhead
from access-log I/O, auth metadata writes, external analyzer, rate-limit store,
and repeated credential/policy lookup latency.
Gateway redaction uses `PRESIDIO_ANALYZE_TIMEOUT_MS=750` by default, then falls
back to local regex analysis with structured `[REDACTION]` fallback logs when
Presidio is slow or unavailable.
For redaction stress evidence, the benchmark also supports a concurrency-10
profile with 1200ms p95 and 1500ms p99 thresholds after raising gateway and
policy rate limits.

- `allow`: normal allowed request
- `redact`: request containing PII that should be redacted
- `block`: request matching the starter policy's SSN block rule

Useful variants:

```bash
# Include streaming latency and SSE no-fragmentation proof.
python scripts/gateway_latency_benchmark.py --scenarios allow,redact,block,stream --provider-baseline-url http://localhost:19090 --require-provider-baseline

# Write machine-readable results for CI/release evidence.
python scripts/gateway_latency_benchmark.py --ci --json-output gateway-benchmark.json --provider-baseline-url http://localhost:19090 --require-provider-baseline

# Heavier local NFR evidence profile after raising gateway and policy rate limits.
python scripts/gateway_latency_benchmark.py --scenarios allow,redact,block,stream --requests 100 --concurrency 5 --warmup 5 --json-output gateway-benchmark-heavy.json --provider-baseline-url http://localhost:19090 --require-provider-baseline

# Redaction/concurrency stress evidence profile after raising gateway and policy rate limits.
python scripts/gateway_latency_benchmark.py --scenarios allow,redact,block,stream --requests 100 --concurrency 10 --warmup 5 --json-output gateway-benchmark-concurrency10.json --p95-threshold-ms 1200 --p99-threshold-ms 1500

# HITL is intentionally opt-in because the SRS timeout is 30 minutes.
python scripts/gateway_latency_benchmark.py --scenarios hitl --allow-hitl --timeout-seconds 1900
```
