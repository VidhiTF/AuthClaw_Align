# AuthClaw

Enterprise AI governance gateway for routing LLM traffic through tenant-aware security, policy, audit, redaction, approval, observability, and provider-control layers.

[![AuthClaw CI](https://github.com/Vidhi-sharma-kvs/AuthClaw/actions/workflows/ci.yml/badge.svg)](https://github.com/Vidhi-sharma-kvs/AuthClaw/actions/workflows/ci.yml)

## What AuthClaw Does

AuthClaw sits between customer applications and LLM providers:

```text
Client App
  -> Dedicated Go Gateway
  -> Python Governance Backend
  -> Tenant Resolution
  -> Policy Engine
  -> Provider Router
  -> LLM Provider
  -> Streaming Redaction
  -> Audit Engine
  -> Client App
```

The dashboard is an administration surface for API keys, provider credentials, policies, approvals, requests, audit logs, and document intelligence. The gateway is the primary product.

## Repository Map

| Path | Purpose |
| --- | --- |
| `apps/` | GitHub-facing application index for backend, web console, and Go gateway |
| `gateway-go/` | Dedicated Go gateway and streaming redaction runtime |
| `routers/` | FastAPI route modules |
| `services/` | Backend business services, policy, auth, metrics, secrets |
| `database/` | Database setup, migrations, and tenant/RLS helpers |
| `document_processing/` | Document extraction, OCR, redaction, storage |
| `frontend/` | React/Vite administration UI |
| `infrastructure/` | GitHub-facing infrastructure index |
| `deployment/` | Docker, Terraform, EC2, and production deployment assets |
| `docs/` | Architecture, phase notes, runtime, and cleanup documentation |
| `sdk/python/` | Python SDK package placeholder and customer integration example |
| `tests/` | Backend and integration test suites |
| `tools/` | Local verification and diagnostic utilities |

More detail: [docs/REPOSITORY_STRUCTURE.md](docs/REPOSITORY_STRUCTURE.md).

## Local Development

```powershell
.\scripts\start-local.ps1
```

Expected local endpoints:

| Service | URL |
| --- | --- |
| Frontend | `http://127.0.0.1:5175` |
| Go Gateway | `http://127.0.0.1:9000` |
| Python API | `http://127.0.0.1:8000` |
| Gateway Health | `http://127.0.0.1:9000/health/ready` |

## Verification

```powershell
python -m pytest -q
cd gateway-go
go test ./...
cd ..\frontend
npm run lint
npm run build
```

CI also validates Docker builds, Terraform formatting/validation, backend tests, frontend quality, and security scanning.

## Security Notes

Never commit `.env`, PEM files, provider API keys, SMTP credentials, JWT secrets, generated deployment env files, or local caches. The repository intentionally ignores these files.

Report security issues using [SECURITY.md](SECURITY.md).
