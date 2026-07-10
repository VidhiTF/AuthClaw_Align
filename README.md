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

## Local start

Copy `.env.full.example` to `.env.full`, replace every `change-me` value, then run:

```bash
docker compose --env-file .env.full -f docker-compose.full.yml up --build
```

Local endpoints:

- Console: `http://localhost:3001`
- Control-plane API: `http://localhost:8000`
- Agent API: `http://localhost:8001`
- Provider gateway: `http://localhost:8080`

The checked-in defaults are for local development only. Production startup is designed
to fail closed when required encryption, signing, SSO, or secret-manager settings are
missing.

## Compliance positioning

The product includes technical controls and evidence generation for GDPR and SOC 2,
plus material suitable for a SOC 3 report. This is **audit readiness**, not a claim that
AuthClaw has completed a SOC 2 Type II examination or received a SOC 3 report. Those
reports require an independent licensed CPA firm and, for Type II, an observation period.

See `docs/COMPLIANCE_BOUNDARY.md`, `docs/ARCHITECTURE.md`, and
`docs/BRANCH_GOVERNANCE.md` before deployment. Console integration status is tracked in
`docs/CONSOLE_API_COMPATIBILITY.md`.

## Branch workflow

- `master` — protected release branch; only the repository owner can merge.
- `dev/kunal` — gateway, backend, audit, infrastructure and CI work.
- `dev/vidhi` — `services/agent/**` work.
- `dev/ravi` — `console/**` and console contract-adapter work.

All changes reach `master` through pull requests, passing required CI checks and owner
review. Jira issue keys use the `ACL-` prefix and should appear in branch names and PRs.

## Provenance

The source archive hashes and extraction decisions are recorded in
`docs/provenance/SOURCE_MANIFEST.md`. Original repository READMEs are retained in
`docs/provenance/` for traceability.
