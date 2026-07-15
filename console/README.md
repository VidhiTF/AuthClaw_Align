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

## Deployment and rollback

`console/Dockerfile.demo` is built by the root Compose definitions and by the required
CI console job. To roll back F07 without restoring a legacy deployment, redeploy the
previous monorepo image. Existing `/frameworks` bookmarks remain safe through the local
compatibility redirect. Database or backend API rollback is not required because F07
does not change either contract.
