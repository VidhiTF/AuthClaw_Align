# AuthClaw

AuthClaw is an open-source, enterprise-grade AI Gateway and Authorization engine. It proxies your AI traffic to providers like OpenAI and Anthropic, enforcing security policies, detecting PII, standardizing access control, and generating compliance scores.

## Features

- **AI Gateway**: Unified proxy to OpenAI, Anthropic, and Azure OpenAI.
- **Policy Engine**: Inspect requests and responses. Block, warn, or redact PII.
- **Role-Based Access Control (RBAC)**: Manage users, roles, and granular permissions.
- **API Keys**: Authenticate your internal apps to the gateway securely.
- **Immutable Audit Logs**: Tamper-proof, append-only PostgreSQL trails for all events.
- **Compliance Dashboard**: Real-time scoring against SOC2, GDPR, and HIPAA rules.

## Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy, PostgreSQL, Redis
- **Frontend**: Next.js 15, React Query, Zustand, Tailwind CSS, Shadcn UI
- **Infrastructure**: Docker, Docker Compose

## Quickstart

Run the full stack locally with Docker Compose:

```bash
docker-compose up --build
```

Access the applications:
- **Web Dashboard**: http://localhost:3000
- **API Server**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## Local Development

### 1. Database & Redis

Start the dependencies using the provided docker-compose or run them locally:

```bash
docker-compose up db redis -d
```

### 2. Backend API

```bash
cd apps/api
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Run migrations and seed database
alembic upgrade head
python scripts/seed.py

# Start server
uvicorn app.main:app --reload
```

### 3. Frontend Web

```bash
cd apps/web
npm install
npm run dev
```

## Security

AuthClaw implements defense-in-depth:
1. **Audit Logs**: PostgreSQL trigger-based immutability prevents row deletion.
2. **Secrets**: API Keys are hashed before storage.
3. **Data Loss Prevention**: Built-in PII detection engine catches sensitive data before it leaves your network.

## Testing

Backend:
```bash
cd apps/api
pytest tests/
```

Frontend:
```bash
cd apps/web
npx playwright test
```
