# AuthClaw Redaction Engine Runbook

## Scope

The gateway redaction engine protects PII/PHI before provider egress and reverses AuthClaw-issued tokens in provider responses when safe to do so. It supports:

- `mask` tokens, for example `[REDACTED_EMAIL_ADDRESS_ab12cd34]`
- tenant-salted hash tokens, for example `[HASH_US_SSN_2b91c0e712aa]`
- synthetic replacement values
- reversible tokenization through tenant-scoped `redaction_tokens`
- custom NER recognizers in addition to Presidio defaults
- local fallback detection when Presidio is slow or unavailable

## Custom NER

Configure custom recognizers with either:

- `REDACTION_CUSTOM_RECOGNIZERS_JSON`
- `REDACTION_CUSTOM_RECOGNIZERS_FILE`

Example:

```json
[
  {
    "name": "MedicalRecordNumber",
    "entity_type": "MEDICAL_RECORD_NUMBER",
    "patterns": ["\\bMRN-[0-9]{6}\\b"],
    "context_keywords": ["patient", "clinic"],
    "score": 0.96
  }
]
```

The gateway sends these recognizers to Presidio as ad-hoc recognizers and also applies them in the local fallback pipeline.

## Concurrency And Fallback

Production knobs:

- `PRESIDIO_ANALYZE_TIMEOUT_MS`, default `750`
- `PRESIDIO_ACQUIRE_TIMEOUT_MS`, default `100`
- `PRESIDIO_MAX_CONCURRENCY`, default `10`
- `PRESIDIO_SLOW_LOG_MS`, default `500`

If Presidio is unavailable, over the concurrency cap, or times out, the gateway falls back to built-in regex/custom recognizer detection and increments metrics.

## Hash Salt

Set `REDACTION_HASH_SALT` in production. Hash tokens include tenant ID, original value, and this salt so the same value does not produce the same token across tenants.

## Token Retention

Each gateway route has `redaction_token_retention_days`, default `90`. New token mappings receive `expires_at` based on this value. The gateway purges expired mappings for the tenant before creating or reusing tokens. Admins can also call:

```text
POST /v1/redaction/{tenant_id}/purge-expired
```

## Metrics

The gateway `/metrics` endpoint exposes:

- `authclaw_gateway_redaction_analyze_requests_total`
- `authclaw_gateway_redaction_presidio_success_total`
- `authclaw_gateway_redaction_presidio_fallback_total`
- `authclaw_gateway_redaction_presidio_timeout_total`
- `authclaw_gateway_redaction_presidio_slow_total`
- `authclaw_gateway_redaction_entities_total`
- `authclaw_gateway_redaction_tokens_created_total`
- `authclaw_gateway_redaction_tokens_reused_total`
- `authclaw_gateway_redaction_tokens_purged_total`

Alert when fallback or timeout counters spike above normal baseline, then check Presidio health, latency, CPU/memory pressure, and custom recognizer regex complexity.
