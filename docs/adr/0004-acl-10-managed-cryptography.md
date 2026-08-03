# ADR-0004: ACL-10 managed cryptography baseline

- Jira: ACL-10 / F05
- Status: Implemented for code and simulation; live AWS evidence pending
- Decision date: 2026-07-14
- Owner: Kunal
- Collaborator: Vidhi

## Context

ACL-10 requires TLS for production-like traffic, managed encryption for stored
sensitive values, field protection for credentials, and testable key rotation and
failure behavior. AWS credentials are not available for this change, so the repository
must distinguish executable local proof from claims that require a deployed KMS, ACM
certificate and service network.

Backend and gateway share the `authclaw-secret-v2` database format. Replacing it with a
backend-only KMS format would prevent the Go gateway from resolving provider
credentials. The agent already has a separate per-record KMS envelope implementation.

## Decision

1. Keep the shared backend/gateway format: randomized AES-256-GCM field encryption,
   explicit provider/key version and legacy read compatibility. In AWS, its runtime
   key comes from a KMS-encrypted Secrets Manager secret.
2. Harden the agent's existing per-record KMS path instead of adding another crypto
   implementation or a Go AWS SDK. Each write uses `GenerateDataKey`; the stored
   envelope contains only the wrapped key, key identifier, algorithm, encryption
   context and AES-GCM ciphertext.
3. Bind new AWS KMS envelopes to
   `authclaw:purpose=database-field`. Preserve reads for earlier envelopes that did not
   record an encryption context.
4. Managed-provider selection is fail-closed in every environment. Invalid key
   material, unavailable KMS, malformed metadata, wrong context and tampered
   ciphertext cannot downgrade to a local key.
5. Production startup rejects non-HTTPS backend-to-gateway/OPA/Presidio URLs. The Go
   gateway independently rejects non-HTTPS OPA and Presidio URLs. Staging enables the
   same check with `AUTHCLAW_REQUIRE_SERVICE_TLS=true`.
6. Non-sensitive health/readiness output may expose provider, key version/key
   identifier and managed/fail-closed state. It must never expose keys, wrapped key
   blobs, ciphertext or provider exception details.

No new dependency, service or database migration is introduced.

## Local and CI evidence

| Requirement | Evidence without AWS credentials | Status |
| --- | --- | --- |
| External TLS | Terraform declares HTTPS ALB listeners, ACM certificate input and the TLS 1.3/1.2 policy | Simulation proof |
| Service traffic TLS | Production/staging boundary guards reject plaintext internal URLs; RDS uses `sslmode=require`; Redis transit encryption is enabled | Code proof; live handshake pending |
| Encrypted storage | RDS, Redis, Secrets Manager and log/storage resources use the environment KMS key | Terraform/static proof |
| Field-level credential protection | Provider, connector and OIDC secrets use randomized AES-GCM; gateway compatibility remains covered | Local test proof |
| KMS envelope encryption | Mock KMS proves `GenerateDataKey`, decrypt, key binding, encryption context and randomized ciphertext | Simulation proof |
| Rotation | Local tests prove versioned backend/gateway keys and per-envelope KMS key identifiers preserve old/new reads | Simulation proof |
| Failure behavior | Tests prove KMS denial, malformed envelopes, wrongCom service scheme and ciphertext tampering fail closed | Local test proof |
| CI | Backend, agent, gateway, IaC, secret/dependency and evidence gates execute these checks | Required before review |

Commands:

```text
pytest backend/tests/test_secret_crypto.py -q
cd services/agent && python -m unittest discover -s smoke_tests -v
go -C gateway test ./...
python -m unittest scripts/test_acl10_cryptography_controls.py scripts/test_no_credential_proof.py
terraform -chdir=infra/terraform validate
```

## Telemetry and operational signals

- Backend `/health` includes `secret_management` with provider, key version,
  non-sensitive key identifier, managed state and configuration state.
- Agent production readiness includes selected secret backend, envelope provider,
  fail-closed selection and whether a customer-managed key identifier is configured.
- Secret rotation/store events record a hashed secret reference, backend and version;
  values are excluded.
- KMS failures return only the operation and exception class. Provider messages are
  retained only as chained causes for trusted server-side debugging.

## Rollback

1. Keep the previous field key/version and KMS key enabled throughout rollout.
2. Roll back application images without changing ciphertext or KMS aliases.
3. Continue reads using the key identifier/version embedded in each envelope.
4. If new writes fail, stop writes, restore the previous configuration and image, then
   verify old/new sample ciphertext before resuming.
5. Never delete or schedule deletion of the previous KMS key until inventory proves no
   stored envelope references it.

## Credential-required acceptance evidence

The following remain intentionally incomplete until an AWS sandbox is authorized:

- apply the Terraform stack and capture the actual KMS key/alias and IAM policy;
- prove successful and denied KMS calls with the ECS task role;
- validate ACM certificates and external TLS negotiation;
- enable the service TLS guard in the controlled-beta environment and capture real
  backend, gateway, OPA and Presidio TLS handshakes;
- perform a live key rotation, failure drill and rollback, then attach redacted logs and
  key identifiers to ACL-10.

ACL-10 must remain In Progress/In Review, not Done, until those live items and the final
approved pull request are attached in Jira.
