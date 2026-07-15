# Console API compatibility

The console under `console/` is the single canonical customer UI while the backend remains
the canonical control plane. Server route handlers and `console/src/lib/api-client.ts`
cover launch-critical contract differences without creating a second identity or data
model.

The console remains a presentation and server-side adapter for that canonical backend. It
does not own users, tenants, policy, audit, evidence or workflow records.

## Controlled-beta route boundary

- `/gateway`, `/compliance`, `/approvals`, and `/audit` are first-class routes in the
  canonical Next.js access shell.
- `/frameworks` is an internal compatibility redirect to `/compliance`; it never leaves
  the canonical application.
- Approval decisions reuse the canonical workflow approval endpoints and retain backend
  scope and MFA enforcement.
- The static files under `console/public/` are public marketing content, not a second
  authenticated application.

## Runtime boundary

- `backend/` authenticates users and remains the identity, tenant and authorization
  authority. Console login delegates to `/v1/auth/login`.
- `console/src/app/api/**` is a browser-facing BFF. Authenticated handlers use
  `console/src/lib/api-client.ts` to forward the backend-issued API key to canonical
  `/v1/**` routes.
- `console/src/lib/session-store.ts` stores the short-lived backend credential server-side
  with AES-256-GCM encryption. The browser receives only an HTTP-only session cookie.
- Agent requests are server-to-server, HMAC-signed and scoped to the authenticated backend
  tenant, user and role. Unsigned, expired or cross-tenant requests are rejected.
- The ACL-29 public route `/trust/shared/:token` is preserved by a same-origin rewrite to
  the replacement page at `/trust-center/:token`; both use the canonical backend Trust
  Center API.

## Wired contracts

- Login, logout, session lookup, OIDC administration and password reset.
- Signup OTP request/resend/verification and tenant onboarding status.
- Tenant-scoped users, invites, MFA, API keys and provider credentials.
- Gateway routes and gateway connectivity tests.
- Policies, simulation, activation, rollback, approvals and remediation workflows.
- Dashboard, compliance scores, audit, signed audit export/verification, evidence and
  findings.
- Trust Center shares, public reports, signed exports and verification.
- Agent session creation, history and chat through the authenticated agent boundary.
- AWS status/usage/S3 and ephemeral cloud-connector operations through backend routes.

## Verification evidence

- [Pull request #16](https://github.com/AgentsArchitects/AuthClaw/pull/16) passed console
  lint, TypeScript, unit tests and the production build.
- The full-stack CI gate started `docker-compose.full.yml`, checked all service health
  endpoints, logged in through the console, verified backend session/tenant context,
  opened audit data and completed an agent chat against the real services.
- Agent smoke tests cover signature scope and expiry. Console unit tests cover encrypted
  session credentials and plaintext-session migration.
- Production console images are built from the pinned standalone `console/Dockerfile`;
  the demo image remains isolated in `console/Dockerfile.demo`.

## Remaining production evidence

The adapters are wired, but production release still requires environment-owned proof:

- SendGrid sender verification and live OTP/password-reset delivery.
- Live provider credentials and provider-specific error/rotation behavior.
- AWS connector, S3, KMS, CloudFront/WAF and origin-denial evidence owned by ACL-14,
  ACL-29, ACL-30 and ACL-37.
- Expanded end-to-end coverage for destructive administration, SSO and cloud mutations.

These are deployment and acceptance gates, not alternate API contracts. Pages must keep
using the BFF and canonical backend/agent authorities while that evidence is collected.
