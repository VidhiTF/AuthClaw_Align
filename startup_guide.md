# AuthClaw local startup

Docker Desktop and Docker Compose are the only host prerequisites for the full local
stack. From the repository root, copy the environment template once, replace every
`change-me` value, and start the product with the canonical command:

```powershell
Copy-Item .env.full.example .env.full
docker compose --env-file .env.full -f docker-compose.full.yml up -d --build --wait
```

The Compose project starts the console, control plane, agent, gateway, PostgreSQL,
Redis, OPA, Presidio, Kafka, ClickHouse, and the audit consumer. Do not start those
services separately; doing so bypasses the dependency and health ordering proven by CI.

Local endpoints:

- Console: `http://localhost:3001`
- Control-plane API: `http://localhost:8000`
- Agent API: `http://localhost:8001`
- Provider gateway: `http://localhost:8080`

Local invitations use the development email outbox by default. After approving an
access request with an invitation, its History shows the invitation link and
verification code (`Delivery local_outbox`). No email is sent to the recipient's
inbox. Failed attempts already recorded in History remain as historical evidence;
new invitations use the corrected configuration after the backend restarts.

For real email delivery, set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`,
`SMTP_FROM`, and `SMTP_TLS` in `.env.full`, then recreate the backend with that same
`--env-file`. Supply a verified sender and provider credentials. Compose's explicit
SMTP environment entries override values from the service's optional `.env.local`.
Incomplete SMTP authentication is rejected
at startup; shared and production environments cannot use the local email outbox.

Verify the running stack with:

```powershell
python scripts/smoke_test.py
```

Stop it without deleting local data:

```powershell
docker compose --env-file .env.full -f docker-compose.full.yml down
```

Add `-v` only when you intentionally want to delete the local databases and queues.
