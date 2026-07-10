# Console API compatibility

Ravi's console is retained as the UI shell while Kunal's backend is the canonical control
plane. The adapter in `console/src/lib/api-contract.ts` covers launch-critical contract
differences without creating a second identity or data model.

## Adapted now

- Password login using Kunal's short-lived bearer API key and `/auth/me` principal lookup.
- Tenant-scoped API-key list/create/revoke.
- Gateway route list/create/update/delete.
- Provider credential list/create/delete and path translation.
- Policy list/create/validate.
- Approval list/approve/reject.
- Audit list and client-side integrity summary shape.
- Compliance score/dashboard reads and score recalculation.
- `/api/v1` compatibility alias for the imported console and existing clients.

## Must be completed before enabling the affected page in production

- Provider credential edit semantics (rotation is supported; generic patch is not).
- Tenant profile edit and rate-tier screens.
- User role update semantics and invite/OTP UX.
- The signup verification screen for Kunal's two-step email OTP onboarding.
- Rich assessment, mapping, report, remediation, risk and trust-report endpoints that exist
  in Ravi's original API but not in Kunal's control plane under the same contract.
- End-to-end tests proving every enabled route against the consolidated backend.

Pages without a verified contract should be feature-flagged or hidden at launch. A page
rendering successfully is not proof that its mutations are connected safely. The imported
agent/remediation, risk/red-team and integrations navigation entries are hidden by default;
set `NEXT_PUBLIC_ENABLE_EXPERIMENTAL_SURFACES=true` only in a non-production validation
environment until their contracts pass end-to-end tests.
