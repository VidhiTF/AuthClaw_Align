# Bedrock authorization and budgets

Bedrock stays disabled by default. Enabling AWS/Bedrock flags alone grants no tenant
access. `BEDROCK_TENANTS_JSON` is an operator-managed map keyed by the authenticated
tenant UUID, then exact model ID. Tenant API keys cannot edit this configuration.
Missing, malformed, revoked, or incomplete entries deny egress. No saved provider
endpoint can redirect Bedrock signing away from the regional AWS HTTPS endpoint.

## Configuration shape

This schema example uses synthetic prices, not deployable pricing. Replace every
tenant/model/price/ceiling with verified values before enabling a staging tenant.
Empty `{}` is the safe default.

```json
{
  "TENANT_UUID": {
    "models": {
      "EXACT_BEDROCK_MODEL_ID": {
        "max_input_tokens": 200000,
        "max_output_tokens": 4096,
        "input_usd_per_million": 1,
        "output_usd_per_million": 5
      }
    },
    "max_daily_requests": 10,
    "max_daily_tokens": 2500000,
    "max_daily_cost_usd": 10
  }
}
```

`max_input_tokens` MUST cover the model's full supported input-token ceiling,
including provider formatting overhead; it is not a client estimate or a smaller
desired limit. Prices must conservatively cover the model/region and invocation
mode, and be updated before a provider pricing change. Unsupported models have no
implicit price fallback. Request output caps cannot exceed the configured maximum.

Before egress, one transaction binds the authenticated tenant and reserves one
request, the full configured input ceiling plus requested output cap, and their
model-specific cost rounded upward to the database's four-decimal USD precision.
Concurrent requests cannot share remaining reservations. UTC rollover is part of
that atomic statement. Missing rows initialize under tenant RLS; storage, binding,
and commit failures deny egress.

Reservations are conservative: failed/signing-rejected requests retain allocation
until rollover, and unused tokens are not refunded. Existing `/aws/usage` counters
report RESERVED tokens/cost, not actual provider billing. The operator map is
authoritative for caps, including when reduced. Actual billing reconciliation
requires live operational evidence.

## Supported requests and credentials

Only text-only Claude Messages and Titan Text `/bedrock/model/{model}/invoke`
requests are supported. The route selects the model. System, message, input, and
stop-sequence text are inspected/rebuilt. Tools, media, unsupported families,
unknown fields and streaming invoke formats fail closed. Invocation uses standard
latency/default service tier; client query parameters and `x-amzn-*` overrides are
rejected, including paid priority/optimized modes and unconfigured guardrails. Claude requires
`max_tokens`; Titan requires `textGenerationConfig.maxTokenCount`.

The AWS SDK credential chain supports temporary session tokens and renewable
role credentials. Signing errors stop transport before egress. Client AWS signing
headers are removed. Only the regional HTTPS runtime host is signable:
`https://bedrock-runtime.<AWS_REGION>.amazonaws.com` (China suffix supported).

Baseline Terraform intentionally gives the gateway no application task role;
this patch does not broaden IAM access. Deployment enablement requires a reviewed
least-privilege credential source and explicit tenant budgets. Local validation
uses synthetic signer credentials and loopback PostgreSQL; no cloud calls occur.

## Verification and deployment

Gateway regression tests cover tenant/model denial, conservative reservations,
unsupported schemas, AWS session-token signing and rejected signing destinations.
`TestBedrockBudgetAuthenticatedPostgres` additionally requires a disposable,
loopback PostgreSQL database ending in `_test`, a migrated schema and restricted
runtime role. Supply the owner URL in `BEDROCK_TEST_OWNER_DATABASE_URL` and the
runtime URL in `DATABASE_URL`. It tests concurrent request/token/cost ceilings,
UTC rollover, and rejection without authenticated tenant context.

Staging still needs trusted PostgreSQL CA certificates, live provider postchecks,
operational price/ceiling verification, and release evidence.

Invocation header contract: [AWS InvokeModel](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html).
