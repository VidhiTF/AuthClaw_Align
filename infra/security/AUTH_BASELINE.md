# AuthClaw Auth Baseline

This runbook covers the production authentication baseline for API keys, provider credentials, secret providers, and OIDC/SSO discovery.

## API Keys

- New API keys expire by default after 90 days.
- API-key creation and rotation allow `expires_in_days` from 1 to 365.
- Revoked, rotated, inactive, and expired keys are rejected by `resolve_api_key`.
- Backend and gateway both resolve keys through the same database function, so revocation and rotation propagate immediately on the next request.
- Sensitive lifecycle operations require both:
  - tenant role: `owner`
  - key scope: `admin`
- Last-used audit fields are recorded on every authenticated backend/gateway request:
  - `last_used`
  - `last_used_ip`
  - `last_used_user_agent`
  - `last_used_request_id`

Rotation procedure:

1. Call `POST /v1/api-keys/{id}/rotate`.
2. Store the returned `api_key` secret immediately; it is shown once.
3. Update dependent clients to the new secret.
4. The old key is marked inactive with `rotated_at` and stops resolving immediately.

## Provider Credentials

- Provider credentials are encrypted with the configured AuthClaw secret provider.
- Creating a new credential for a provider rotates any active credential for that provider.
- `POST /v1/provider-credentials/{id}/rotate` creates a new versioned active row and marks the old row `rotated`.
- `DELETE /v1/provider-credentials/{id}` marks a credential `revoked` with `revoked_at` and `revoked_by`.
- Gateway only loads credentials where `status = active` and `revoked_at IS NULL`, ordered by highest `version`.

## Secret Provider Production Choice

Set `AUTHCLAW_SECRET_PROVIDER` to one of:

- `env`: local/staging envelope key from environment. Requires a non-demo `ENVELOPE_KEY` or versioned `ENVELOPE_KEY_<VERSION>`.
- `vault`: HashiCorp Vault. Requires `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_SECRET_KEY_PATH`.
- `aws_kms`: AWS KMS envelope material. Requires `AWS_KMS_ENCRYPTED_DATA_KEY` or `KMS_ENCRYPTED_DATA_KEY`.

Production must set `AUTHCLAW_SECRET_KEY_VERSION`. Rotate secrets by adding a new versioned key, deploying with the new version, rotating provider credentials, and then retiring old material after all rows have moved.

## OIDC/SSO Hooks

OIDC discovery is exposed at:

- `GET /v1/auth/oidc/config`

Required environment for enabled OIDC discovery:

- `OIDC_ISSUER_URL`
- `OIDC_CLIENT_ID`
- `OIDC_REDIRECT_URI`

Optional overrides:

- `OIDC_AUTHORIZATION_ENDPOINT`
- `OIDC_TOKEN_ENDPOINT`
- `OIDC_JWKS_URI`
- `OIDC_SCOPES`

Production startup validation fails on partial OIDC configuration or non-HTTPS redirect URIs.
