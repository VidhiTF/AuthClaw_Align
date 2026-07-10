# AuthClaw

AuthClaw is a compliance and security platform for AI applications. It sits between users and AI providers, protects sensitive data, enforces guardrail policies, records tamper-evident audit trails, and helps teams map evidence to SOC 2, GDPR, and HIPAA controls.

## What AuthClaw Does

AuthClaw provides:

- Multi-provider AI gateway for OpenAI, Anthropic, Cohere, Azure OpenAI, Gemini, and compatible routes
- Real-time PII/PHI redaction with mask, hash, and synthetic replacement strategies
- YAML/OPA policy enforcement for model allowlists, blocklists, regex rules, topics, and rate limits
- Human-in-the-loop approval workflows for risky or destructive actions
- MFA-gated remediation approvals
- Compliance agent and remediation workflow orchestration
- Evidence and findings tracking
- SOC 2, GDPR, and HIPAA readiness scoring
- Signed audit exports with hash-chain verification
- Tenant isolation with PostgreSQL RLS
- Tier-based usage limits and worker throttling
- Red-team simulation and policy failure tracking
- Terraform-based AWS deployment with multi-region/failover scaffolding

## Main Product Areas

### Gateway

The gateway proxies AI requests to supported model providers while applying AuthClaw controls.

It handles:

- Provider routing
- Request/response normalization
- PII/PHI detection and redaction
- Streaming response protection
- Policy evaluation
- Rate limiting
- Audit event emission

### Policies & Guardrails

Policies are written in YAML and evaluated through the gateway and OPA path.

Supported controls include:

- Allowed and blocked models
- Regex-based redaction, blocking, or approval
- Topic-based restrictions
- Per-tenant and per-route rate limits
- Human approval triggers

### Agent & Remediation

The Agent & Remediation area is for compliance workflows.

It can:

- Run framework scans
- Explain control gaps
- Retrieve grounded regulatory context through RAG
- Create remediation plans
- Route risky actions through approval
- Execute approved remediation through controlled worker paths
- Record evidence, findings, and audit logs

Destructive remediation is designed to require approval and MFA before execution.

### Risk & Red Teaming

Risk & Red Teaming checks whether AI controls can be bypassed.

It supports:

- Prompt-injection probes
- Sensitive-data leakage checks
- Harmful-content probes
- Go/no-go posture
- Findings creation for failed probes

Simulation mode is non-destructive by default.

### Findings

Findings are tracked issues discovered by scans, red-team runs, manual review, or audit checks.

Findings include:

- Severity
- Status
- Framework
- Risk score
- Evidence link
- Owner
- Remediation summary

### Frameworks

Framework scoring maps evidence, findings, audit logs, redaction activity, approvals, and policy signals to:

- SOC 2
- GDPR
- HIPAA

Each framework includes control-level scoring, gaps, evidence links, and traceability.

### Audit & Trust Center

AuthClaw creates tamper-evident audit records and signed audit exports.

The audit system supports:

- Hash-chain verification
- Signed JSON export
- Offline verification
- Trust Center sharing
- Framework-scoped exports
- Public auditor share links

## Architecture

AuthClaw is made of several services:

- `backend`: FastAPI control plane, workflows, evidence, findings, auth, compliance scoring
- `gateway`: Go AI gateway and enforcement layer
- `console`: Next.js web console
- `audit_consumer`: Kafka/ClickHouse audit ingestion worker
- `postgres`: primary transactional database
- `redis`: rate limiting and cache support
- `opa`: policy evaluation
- `presidio`: PII/PHI analysis
- `clickhouse`: audit analytics storage
- `kafka/redpanda`: audit and gateway event backbone

## Local Development With Docker

Start the full local stack:

```bash
docker compose -f docker-compose.full.yml up --build
```

Seed the local demo tenant:

```bash
docker compose -f docker-compose.full.yml exec backend sh -lc 'DATABASE_URL="$APP_DATABASE_URL" python scripts/seed_authclaw_lite.py'
```

Open the console:

```text
http://localhost:3001
```

Default local demo login depends on the seeded environment values. Check `.env.full.example` or the seed script for the current demo credentials.

## Common Docker Commands

Start full stack:

```bash
docker compose -f docker-compose.full.yml up --build
```

Start in background:

```bash
docker compose -f docker-compose.full.yml up -d --build
```

Stop stack:

```bash
docker compose -f docker-compose.full.yml down
```

View backend logs:

```bash
docker compose -f docker-compose.full.yml logs -f backend
```

View gateway logs:

```bash
docker compose -f docker-compose.full.yml logs -f gateway
```

Run backend tests:

```bash
docker compose -f docker-compose.full.yml exec backend pytest
```

Run migrations manually:

```bash
docker compose -f docker-compose.full.yml exec backend sh -lc 'DATABASE_URL="$OWNER_DATABASE_URL" alembic upgrade head'
```

## Production Deployment

Production infrastructure is defined under:

```text
infra/terraform
```

The Terraform stack supports:

- Primary AWS region
- Optional secondary failover region
- ECS/Fargate services
- ALB ingress
- RDS PostgreSQL
- RDS cross-region read replica
- ElastiCache Redis
- KMS
- Secrets Manager
- CloudWatch logs
- Optional Route53 failover records
- Optional Kafka/ClickHouse audit integration

Example Terraform flow:

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

## Security Model

AuthClaw uses:

- Tenant isolation through PostgreSQL row-level security
- Scoped API keys
- Role-based access control
- OIDC/SSO support
- Encrypted provider credentials
- Short-lived worker tokens
- Deny-by-default worker permission boundaries
- MFA approval for sensitive workflows
- Immutable audit records
- Signed audit exports
- CI security gates

## Evidence And Proofing

Local proofing exists for:

- Tier-based limits
- Gateway policy rate limits
- Worker throttling
- Tenant isolation
- Cryptographic audit export verification
- Red-team pass/fail thresholds
- Compliance evidence manifest validation
- HA/failover evidence validation
- Cloud connector contract tests
- Remediation workflow simulation

Some production claims require real external proof:

- Live 99.99% availability evidence
- Real Route53 failover timing
- Real cloud remediation with sandbox credentials
- External penetration test
- SOC 2 auditor evidence
- True active-active data writes, if required by the final SRS

## Useful Validation Commands

Run backend and script tests:

```bash
python -m pytest backend/tests scripts
```

Run gateway tests:

```bash
cd gateway
go test ./...
```

Run console lint:

```bash
cd console
npm run lint
```

Run console build:

```bash
cd console
npm run build
```

Validate no-credential proof artifact:

```bash
python scripts/no_credential_proof.py infra/security/no_credential_proof.local.json --repo-root .
```

Validate HA evidence artifact:

```bash
python scripts/ha_failover_evidence.py infra/terraform/ha_failover_evidence.example.json
```

Validate compliance hardening evidence:

```bash
python scripts/compliance_hardening_evidence.py infra/security/compliance_hardening_evidence.example.json
```

## Current Completion Status

AuthClaw is largely complete from a local code and product-build perspective.

Estimated status:

- Local/code completion: about 90-93%
- Strict production/SRS completion: about 78-82%

The remaining gap is mostly real-world proof, not ordinary feature code:

- External pentest
- SOC 2 auditor evidence
- Live cloud failover proof
- Real provider/sandbox remediation proof
- Production availability data

## Repository Structure

```text
backend/          FastAPI backend, workflows, services, migrations, tests
gateway/          Go gateway, provider adapters, policy/redaction enforcement
console/          Next.js web console
audit_consumer/   Kafka to ClickHouse audit consumer
infra/            Terraform, OPA, SQL, security evidence, runbooks
scripts/          Proof validators, benchmarks, smoke tests
sdk/              Client SDK examples
.github/          CI/CD hard gates
```

## License

Private project.
