# AuthClaw

AuthClaw is the consolidated product repository owned by **AgentsArchitects**.
It combines the strongest production-oriented parts of the three source repositories:

- **Kunal / `authclaw-lite`** — canonical gateway, FastAPI control plane, audit pipeline,
  Terraform, Docker Compose, and CI security gates.
- **Vidhi / `AuthClaw`** — LangGraph agent, regulatory RAG corpus, document processing,
  HITL, redaction, risk, and provider-routing logic in `services/agent`.
- **Ravi / `authclaw-mvp`** — Next.js/Shadcn console shell, RBAC views, API-key
  management, and compliance dashboards in `console`.

## Repository map

| Path | Owner | Purpose |
|---|---|---|
| `gateway/` | Kunal | Go provider gateway and enforcement path |
| `backend/` | Kunal | FastAPI control plane, tenant RBAC, API keys, SSO and compliance APIs |
| `audit_consumer/` | Kunal | Kafka/Redpanda to ClickHouse audit pipeline |
| `infra/` | Kunal | Terraform, OPA, PostgreSQL and ClickHouse infrastructure |
| `services/agent/` | Vidhi | LangGraph, RAG, document intelligence, HITL, redaction and risk |
| `console/` | Ravi | Next.js/Shadcn operator console |
| `sdk/python/` | AgentsArchitects | Install-free Python client for the provider gateway |

## Local start

Copy `.env.full.example` to `.env.full`, replace every `change-me` value, then run the
canonical full-stack command:

```bash
docker compose --env-file .env.full -f docker-compose.full.yml up -d --build --wait
```

Local endpoints:

- Console: `http://localhost:3001`
- Control-plane API: `http://localhost:8000`
- Agent API: `http://localhost:8001`
- Provider gateway: `http://localhost:8080`

The checked-in defaults are for local development only. Production startup is designed
to fail closed when required encryption, signing, SSO, or secret-manager settings are
missing.

CI validates this Compose model and starts the same full stack before running
`scripts/smoke_test.py`. See `startup_guide.md` for verification and shutdown commands.

## Python dependency locks

Python 3.14.3 dependencies are declared in each `requirements.in` file and compiled into
hash-locked `requirements.txt` files. Install and run the pinned compiler inside the
Linux production base image:

```bash
python -m pip install --require-hashes -r requirements-tooling.txt
pip-compile --generate-hashes --allow-unsafe --strip-extras --resolver=backtracking requirements.in
```

Run the second command from `backend`, `audit_consumer`, or `services/agent`; compile
each `requirements-test.in` the same way. Commit both the edited input and generated
lock. CI rejects stale locks, and production installs reject packages whose hashes do
not match.

## Delivery and controlled beta

CI exposes `ACL-14 Required Checks`, one aggregate status that succeeds only after the
build, test, secret, dependency, compliance, integration, benchmark, and image-scan jobs
pass. A successful hard-gate run on `master` triggers the controlled-beta workflow, but
its deployment job runs only when the `controlled-beta` environment variable
`CONTROLLED_BETA_ENABLED` is `true` and every required AWS/DNS input exists.

Enabled releases use GitHub OIDC for short-lived AWS access, promote tested images to
KMS-encrypted ECR repositories, deploy containers by digest, use encrypted Terraform
state and managed runtime secrets, verify ECS health and CloudWatch alarms, and restore
the previous task definitions if verification fails. A skipped workflow is not live
deployment evidence.

See `docs/adr/0006-acl-14-controlled-beta-delivery.md` for the decision and
`infra/terraform/BETA_DEPLOYMENT.md` for enablement, branch protection, and rollback.
The supported launch configuration, known limitations, and acceptance-evidence index are
published in `infra/security/AUDIT_READY_RELEASE_CHECKLIST.md`.

## Compliance positioning

The product includes technical controls and evidence generation for GDPR and SOC 2,
plus material suitable for a SOC 3 report. This is **audit readiness**, not a claim that
AuthClaw has completed a SOC 2 Type II examination or received a SOC 3 report. Those
reports require an independent licensed CPA firm and, for Type II, an observation period.

See `docs/COMPLIANCE_BOUNDARY.md`, `docs/ARCHITECTURE.md`, and
`docs/BRANCH_GOVERNANCE.md` before deployment. Console integration status is tracked in
`docs/CONSOLE_API_COMPATIBILITY.md`.

## Branch workflow

- `master` — release integration branch; required protection is defined in
  `.github/branch-protection-master.json`.
- `dev/kunal` — gateway, backend, audit, infrastructure and CI work.
- `dev/vidhi` — `services/agent/**` work.
- `dev/ravi` — `console/**` and console contract-adapter work.

Changes reach `master` through pull requests, passing required CI checks and owner
review. Feature branches use `feat|fix|chore/<area>/<JIRA-KEY>-slug`, for example
`feat/infra/ACL-14-encrypted-beta`. The repository owner must apply the checked-in
protection payload after `ACL-14 Required Checks` has run on `master`; `CODEOWNERS` alone
does not enforce these rules.

## Provenance

The source archive hashes and extraction decisions are recorded in
`docs/provenance/SOURCE_MANIFEST.md`. Original repository READMEs are retained in
`docs/provenance/` for traceability.
