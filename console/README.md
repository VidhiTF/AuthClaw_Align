# AuthClaw console

The customer-facing AuthClaw console is the canonical Next.js application in this
directory. It uses the App Router and a server-side access shell; browser pages call
same-origin route handlers, which authenticate requests to the canonical control plane
and agent service.

## Controlled-beta navigation

The primary customer surfaces are:

- `/gateway` - provider gateway configuration and status (owner/admin)
- `/compliance` - compliance readiness, evidence traceability, and trust sharing
- `/approvals` - tenant-scoped human-in-the-loop gateway decisions
- `/audit` - audit events, exports, and integrity verification

The historical `/frameworks` link redirects inside this application to `/compliance`.
No authenticated route redirects to or depends on a separate legacy console.

## Local development

From this directory:

```bash
npm ci
npm run dev
```

The console listens on `http://localhost:3001`. The full monorepo stack is normally
started from the repository root:

```bash
docker compose --env-file .env.full -f docker-compose.full.yml up -d --build
```

## Validation

```bash
npm run lint
npx tsc --noEmit --pretty false
npm run test:unit
npm run build
npx playwright test
```

Playwright requires the seeded full stack described by the repository CI workflow.

## Enterprise OIDC identity context

An enabled tenant OIDC configuration requires an immutable external tenant identifier.
The verified ID-token `tenant_id` claim must match that value. MFA context is required
by default through `amr=mfa` or a tenant-configured accepted `acr`, with `auth_time`
limited to 43,200 seconds. These values can be changed per tenant in Settings without
changing the existing application TOTP policy for sensitive actions.

### OIDC audit events

OIDC backend decisions reuse the existing `audit.events` pipeline and structured
application logs. Pre-authentication state rejection and console session expiry use
the existing structured application logs because those decisions occur before a
trusted backend principal exists. Categorical events cover successful login and
rejected token, issuer, audience, signature, nonce, redirect URI, tenant, MFA, state,
and expired-session decisions. Events contain tenant and validated actor identifiers,
the action, categorical reason, result status, and request correlation identifier
only. Authorization codes, tokens, nonce, state, client secrets, cookies, and raw
claims are never included.

## Deployment and rollback

`console/Dockerfile.demo` is built by the root Compose definitions and by the required
CI console job. To roll back F07 without restoring a legacy deployment, redeploy the
previous monorepo image. Existing `/frameworks` bookmarks remain safe through the local
compatibility redirect. Database or backend API rollback is not required because F07
does not change either contract.

To roll back ACL-13, deploy the prior application image first, then downgrade migration
`026` to `025`. Existing tenant OIDC configuration remains disabled after rollback until
its prior policy is explicitly re-enabled.

For existing active OIDC configurations, set `AUTHCLAW_OIDC_TENANT_MAPPINGS` to a JSON
object mapping internal tenant UUIDs to immutable external tenant IDs. Migration `026`
backfills those values transactionally and stops before schema changes if any mapping is missing.
