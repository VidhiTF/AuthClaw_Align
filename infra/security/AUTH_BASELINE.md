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

## Platform Authorization

Platform roles are global and separate from tenant roles. Platform operations require
both the `ADMIN` platform role and the dedicated `platform.admin` API-key scope.
Platform roles are not exposed or assignable through tenant user APIs. Provisioning is
performed only through controlled operational procedures.
Platform-scoped API keys are likewise provisioned and managed only through controlled
operational procedures; tenant API-key endpoints cannot create, list, rotate or revoke
them.

Platform identities currently reuse authenticated user records and the existing API-key
authentication protocol. They may evolve into a dedicated platform identity model in a
future architecture change.
A tenant containing a PlatformAdmin identity cannot be deactivated, disabled, or
suspended until that identity is transferred or removed through the approved
operational procedure.

Bootstrap from the backend runtime with owner database credentials and the production
API-key hash secret:

```bash
PLATFORM_ADMIN_TENANT="Internal Operations" \
PLATFORM_ADMIN_EMAIL="operator@example.com" \
python scripts/bootstrap_platform_admin.py
```

Store the displayed key immediately; it is shown once. Verify with
`PLATFORM_ADMIN_ACTION=verify` and the same tenant/email variables. Roll back with
`PLATFORM_ADMIN_ACTION=rollback`; this revokes the identity's platform-scoped keys and
restores its platform role to `NONE`.

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

### Managed envelope model

- Backend and gateway field encryption uses randomized AES-256-GCM. The runtime
  envelope key is injected from AWS Secrets Manager; the Terraform stack encrypts
  that secret with the environment KMS key. The ciphertext records provider and key
  version so old material can remain available during rotation.
- Agent database fields can use per-record AWS KMS envelope encryption by setting
  `AUTHCLAW_ENVELOPE_PROVIDER=aws_kms` and `AUTHCLAW_AWS_KMS_KEY_ID`. Each write calls
  `GenerateDataKey`, stores only the wrapped data key, key identifier and AES-GCM
  ciphertext, and binds KMS operations to the `authclaw:purpose=database-field`
  encryption context.
- Selecting a managed envelope provider is fail-closed. KMS/Vault errors never fall
  back to local encryption, and provider error details are not returned to callers.

### Rotation and failure procedure

1. Preserve the previous version as `ENVELOPE_KEY_<OLD_VERSION>` for backend and
   gateway reads; never overwrite it in place.
2. Add the next managed secret and set `AUTHCLAW_SECRET_KEY_VERSION` plus
   `ENVELOPE_KEY_<NEW_VERSION>` for the deployment.
3. Re-save or rotate provider, connector and OIDC credentials so new ciphertext uses
   the new version/key identifier.
4. Prove both old and new rows decrypt, then remove the previous key only after no
   records reference it.
5. For per-record KMS envelopes, change `AUTHCLAW_AWS_KMS_KEY_ID` for new writes. Old
   ciphertext retains its original key identifier and remains decryptable while that
   KMS key is enabled.
6. A disabled key, wrong key identifier/context, malformed envelope or failed KMS call
   must fail the request. Do not retry with local keys.

Production service boundaries default to TLS enforcement. Backend requires HTTPS for
`GATEWAY_INTERNAL_URL`, `OPA_URL` and `PRESIDIO_URL`; gateway requires HTTPS for OPA and
Presidio. Staging can exercise the same guard with
`AUTHCLAW_REQUIRE_SERVICE_TLS=true`. Live certificates and TLS handshakes remain an AWS
acceptance-evidence step.

## OIDC/SSO Hooks

### Invitation role authority

- An invited user's tenant role is the role assigned by the authorized invitation.
- OIDC claims authenticate the identity; they do not silently override a verified
  invitation's role.
- Tenant invitation APIs cannot assign the tenant `owner` role or any platform role.
- Platform roles remain provisioned only through the controlled operational process
  documented above.
- A future change that allows IdP-managed role assignment requires a separate
  authority-model decision, conflict policy, and tenant-isolation regression suite.

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
