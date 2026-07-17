# ADR-0008: ACL-17 gateway policy and sensitive-data redaction

| Metadata | Value |
|---|---|
| Owner | Vidhi Sharma |
| Collaborator | Kunal |
| Jira issue | ACL-17 |
| Branch | `feat/gateway/ACL-17-policy-redaction` |
| Date | 2026-07-17 |
| Status | Implemented; review and CI confirmation pending |

## Context

The gateway is AuthClaw's supported model-egress boundary. Sensitive information must
not reach a model provider unless the applicable tenant policy permits it and the
request has been transformed as required. The policy decision must also be observable
without copying raw sensitive values into logs or audit evidence.

## Decision

The gateway applies the following sequence before provider egress:

1. Authenticate the request and resolve its tenant.
2. Normalize the provider-specific request into prompts.
3. Load and validate the tenant policy.
4. Evaluate explicit `block` and `warn` rules.
5. Apply human-approval rules when configured.
6. Detect and tokenize sensitive values for `redact`, `warn`, and
   `require_approval` rules.
7. Rebuild the provider request exclusively from the transformed prompts.
8. Evaluate the remaining policy controls and proxy only an allowed request.

Policy actions have these meanings:

- `block`: return HTTP 403 before provider egress.
- `warn`: emit a safe warning signal, redact the matching value, and continue.
- `redact`: tokenize the matching value and continue.
- `require_approval`: complete the existing approval flow and redact before continuing.

Normalization, warning evaluation, sensitive-data analysis, tokenization, or request
rebuild failures are fail-closed. A failed protection step therefore cannot fall back
to sending the original request.

## Evidence and privacy constraints

Normal logs and audit events may contain request identifiers, tenant identifiers,
policy action, entity type, counts, duration, and a SHA-256 match fingerprint. They
must not contain the original prompt or the matched sensitive value. Enabling gateway
debug logging does not relax this rule.

The metrics endpoint publishes:

- `authclaw_gateway_policy_block_total`
- `authclaw_gateway_policy_warn_total`
- `authclaw_gateway_policy_redact_total`
- `authclaw_gateway_policy_fail_closed_total`

Warning responses also include `X-AuthClaw-Policy-Action: warn` and
`X-AuthClaw-Policy-Warning: true`.

## Consequences

Fail-closed behavior can reject a request when an analyzer or transformation component
is unavailable. This is intentional: availability must not bypass the model-egress
privacy boundary. Operators can use the safe counters and audit events to diagnose the
failure without exposing the affected data.

## Rollback

Revert the ACL-17 implementation commit to restore the previous gateway behavior.
Tenant-specific warning rules can be removed from policy configuration independently,
but raw-prompt logging must not be re-enabled. After rollback, run gateway policy and
redaction tests and review audit output before deployment.
