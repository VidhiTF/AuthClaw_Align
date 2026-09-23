## Jira

User-reported invitation delivery failure (2026-09-18); no Jira ID supplied.
Confirmed configuration defect: the local backend was launched from
`.env.full.example` with `SMTP_HOST=smtp.sendgrid.net`, an SMTP username, and an
empty password. The screenshot matches `create_access_request_invitation`'s
`EmailDeliveryError` history path. No provider credentials were printed.

## Engineering rules and prerequisite

Fresh `scripts/repository_policy.py --verify-github` passed before implementation:
T01 PR 52, reviewed b8b23993a7a467396598eefdd23b97da83d47042, merged
1e40bdb5c8fd6b4e28c827035ab7d06645530ccb, effective 2026-09-16T12:57:25Z.
Ruleset 21141288 is active with zero bypass actors; record owner KunalTF.

## Scope

Follow-up: the user's screenshot and authenticated browser verification show that
the review page has no retry action and still shows only the original failed
history. Reuse its existing status PATCH, busy state, refresh, invitation service,
and history rendering. Permit an explicit same-status invitation retry only for
APPROVED/INVITED requests, reuse the tenant ID from trusted prior history, append
a fresh delivery result, and expose a Resend invitation button. This needs no new
route, schema, or delivery implementation. Preserve old events.

Live retry then exposed the pre-existing PostgreSQL update-branch defect:
`resend_count = COALESCE(resend_count, 0)` is ambiguous with the function's OUT
parameter. Add migration 053 using the existing guarded function-replacement
pattern; qualify the already-locked `v_invite.resend_count`. Keep the function's
signature, ACL, owner, and security context unchanged. Advance the existing
backend/gateway/Compose/Terraform revision gates to the bounded 052/053 window.
The effective SQL correction is one expression; the migration ensures existing
installations receive it on upgrade without editing historical migration 043.

Use the existing local outbox, as explicitly selected by the user. Fresh local
invitations must retain their link and verification code. Detect incomplete SMTP
authentication at startup and at delivery, before connecting to a provider.
Do not allow local outbox delivery in shared or production environments.
Historical failed-delivery events remain truthful; no history backfill is needed.

## Customer impact

Local setup works without external email credentials. Real email delivery still
requires working SMTP credentials and a verified sender. Invalid SMTP configuration
will fail startup with a configuration error rather than fail after invitation creation.

## Release notes

Local invitation delivery uses the existing development outbox by default;
incomplete SMTP credentials are rejected before attempting delivery. Approved and
invited requests can be retried from the review page, which shows a fresh local
verification code and explicitly says no email was sent. Migration 053 repairs
the existing database function's resend branch.

## Schema and rolling-deployment compatibility

No API, table, or event schema changes. Existing SMTP and local_outbox delivery
values remain unchanged. Migration 053 changes one expression in the existing
function body; signature, ownership, grants, and security context are unchanged.
For rolling deployment, deploy the updated backend/gateway with the explicit
052,053 compatibility window, apply 053 through the ownership-prepared migration
pipeline, then tighten to 053. Operators enabling SMTP must supply complete
credentials. No live 053 migration or deployment is claimed; those remain release
evidence. Terraform formatting, initialization, validation, and the CI plan were
checked with the repository's cached container.

## Existing-code reuse

Searched `email_service.py`, `startup_checks.py`, `access_requests.py`, onboarding
and user invitation endpoints, console history, Compose configuration, auth tests,
access-request tests, and existing TLS tests. Reuse the outbox writer, invitation
metadata/code display, SMTP transport, startup validator, and Compose contract test.
No new delivery provider, queue, endpoint, or client state is needed. The new retry
button uses the existing transition handler and the same delivery/history path.

Recovery verification exposed a second confirmed defect: the existing resend API
committed a fresh code and then returned HTTP 500 (`InvalidRequestError: Could not
refresh instance`). Its transaction-local tenant context ends at commit. Before
editing that path, reuse `_invitation_audit_snapshot` and materialize the existing
response while authorized; audit only the snapshot after commit/rollback. This
avoids any new authorization bypass or broader database access.

## New-line justification

Before implementation: a small shared SMTP configuration check is necessary because
startup currently checks only SMTP host/sender in production, and delivery attempts
authentication even with an empty password. Reuse that check at both boundaries;
keep the existing transport and outbox. Regression tests exercise the failure
and intended local behavior. Original delivery recovery adds 20 net production
Python lines. The review retry adds 13 net service lines and 8 net UI lines;
migration 053 adds 28 lines, while revision-gate replacements add no net lines.
Counts include whitespace. Affected files contain 162 physical lines (email
service), 300 (startup checks), 712 (onboarding), 371 (access requests), and 345
(review client), each
below the 10,000-code-line ceiling even counting all physical lines. Tokei is not
installed locally; the full repository Tokei CI gate is not claimed as executed.
Semantic duplicate consolidation is not part of this change.

## Security and compliance

No credentials, user email addresses, or invitation tokens belong in this evidence.
Negative tests must prove invalid authentication never contacts SMTP and shared
environments never write verification codes to a local outbox. Provider outages
must continue to report failure. No weakening of transport security is planned.

## Material line-growth exception

This patch adds 268 positive net non-prose lines: template 2, SMTP service 16,
startup checks 3, onboarding 1, access-request service 13, review client 8,
migration 28, auth tests 36, access-request tests 102, migration/deployment tests
40, Terraform CI plan fixture 17, and Compose contract
2. Counts are against current `align/master` and exclude unrelated working-tree
changes.
Most growth is regression coverage; existing production paths were reused. Removing
these boundary checks would lose evidence for incomplete credentials, forbidden
outbox fallback, usable invitations, and expired ORM access after commit/rollback.
Material-growth owner approval is required before merge and remains pending.

## Tenant isolation evidence

No database role, authorization, or RLS policy changes. The public resend's trusted
tenant_id comes from the existing authn.prepare_onboarding_invite_resend path,
which establishes transaction-local RLS context for the invitation. Resend now
materializes its response and audit snapshot before that context ends. Live checks
after recovery confirmed an unscoped runtime session cannot read the invitation
and current_user has neither superuser nor BYPASSRLS. The platform review retry
uses the prior server-written delivery history's tenant_id, scoped to the locked
access request, rather than looking up or creating another tenant by company name.
Parameterized APPROVED/INVITED regressions verify preservation of that tenant ID
and reject same-status requests without the explicit invitation flag. No new negative insert,
update, export, or similarity tests were run; those operations were not changed.

## Test evidence

Baseline commit: 064189454d42de79341b68d8a89490d6042c0943, with pre-existing user changes.
Runtime inspection confirmed the backend's Compose environment file is
`D:\AUTHCLAW-NEW\.env.full.example`, environment `local`, and SMTP password empty.
Fresh verification on 2026-09-18 (repository Python 3.14 virtual environment):

- Before the SMTP fix: 17 targeted regressions failed, 2 passed; the Compose
  contract failed on the enabled SMTP host. Both expected defects were demonstrated.
- Before the resend fix: both success/failure transaction-expiration regressions
  failed on post-transaction ORM reloads.
- `pytest -p no:cacheprovider -q --disable-warnings tests/test_auth_baseline.py
  tests/test_secret_crypto.py`: 102 passed, exit 0 (20 existing deprecation warnings).
- `pytest -p no:cacheprovider -q --disable-warnings tests/test_access_requests.py
  -k 'test_email or test_best_effort or test_status_transition or test_local_invitation
  or test_service_persists or test_invitation_resend_does_not_reload'`: 10 passed,
  exit 0 (27 deselected, 21 existing warnings).
- `python -m unittest scripts.test_internal_tls.SMTPChecks`: 2 passed, exit 0;
  real SMTP acceptance with trusted TLS, invalid-CA/plaintext rejection, and no
  production outbox fallback.
- `python scripts/test_compose_contract.py` and scoped `git diff --check`: exit 0.
- Rebuilt/recreated only the backend using the observed Compose environment file;
  backend health passed. Synthetic live outbox delivery preserved its link and code.
- The actual screenshot invitation's first recovery request demonstrated HTTP 500
  after delivery. After the resend patch/rebuild, recovery returned HTTP 200 with
  `delivery=local_outbox`. No recipient, invite token, or verification code is saved
  in this document. The old failure history is retained; resend updates the invite.

Follow-up verification on the same date:

- Both new platform retry regressions failed before the service change with
  `Invalid access request transition`, then passed after it.
- Targeted migration/revision-gate and access-request tests: 19 passed,
  23 deselected, exit 0 (22 deprecation warnings), using the closed dummy database.
- Gateway `go test ./... -run '^TestCompatibleDatabaseRevisions$' -count=1`:
  passed, exit 0; a dummy `_test` database URL satisfied the fixture safety guard.
- Scoped review-client ESLint passed. The console image build passed Next.js
  compilation, TypeScript checks, and generation of 59 static pages.
- Backend, console, and gateway images rebuilt. Recreated consumers are healthy.
  Compose contract and scoped whitespace checks passed again.
- First live review retry exposed the existing ambiguous PostgreSQL resend
  counter. A pre-rebase prototype used revision 050 and proved the guarded SQL
  replacement while preserving owner, SECURITY DEFINER, search_path, and execute
  ACL. Current master subsequently assigned revisions 050-052, so this branch
  carries the same correction as 053 with `down_revision = "052"`.
- Authenticated in-app browser: `/developer/access-requests` -> APPROVED ->
  Resend invitation. The exact affected request now shows INVITATION READY at
  12:39 PM IST, "Local invite ready — no email sent", the same invitation link,
  and a fresh verification code. Refresh retained that result above the original
  failed event. Desktop screenshot visually confirmed both entries and the code.
  Page identity was AuthClaw at the intended localhost:3001 route, meaningful
  content rendered without a framework overlay, and captured warn/error logs
  were empty. Browser verification caught the database error that unit tests
  alone did not; it was repeated after migration/rebuild to prove recovery.

Fresh rebase verification on 2026-09-23 against `align/master`:

- SMTP/local-outbox regressions: **20 passed**, 53 deselected.
- Exact database-free access-request/invitation regressions: **12 passed**,
  27 deselected. A broader `-k email` attempt also selected two FastAPI lifespan
  tests and failed only because the deliberately closed PostgreSQL endpoint was
  unavailable; those tests are not counted as passing.
- Migration chain, 053 SQL replacement, and deployment-default regressions:
  **5 passed**.
- Compose contract, Python compilation, gateway 052/053 compatibility test,
  `go vet ./...`, and `go build ./...`: passed.
- Scoped review-client ESLint and a full no-emit TypeScript check: passed.
- Terraform recursive format, initialization, validation, and full CI plan passed
  in an ephemeral cached 1.15.7 container. Independent review found the old CI
  fixture's stale revision, plaintext placeholder, missing alarm targets, and
  incomplete audit-consumer inputs; regression assertions now keep that fixture
  aligned with the fail-closed module contract.
  A live 053 migration, production SMTP, deployment, and full database-backed
  integration remain release-stage evidence.

Test settings used dummy PostgreSQL URLs on 127.0.0.1:1, REDIS_URL on the same closed
port, and PGCONNECT_TIMEOUT=2 for authentication tests' best-effort audit paths.
Broad attempts including every access-request HTTP test were interrupted: those
tests require a migrated PostgreSQL fixture and failed/stalled on the deliberately
unavailable database. They are not passing integration evidence. No destructive
database suite was run on the user's live local database. Browser QA used the
available in-app controls at the default 1265x712 desktop viewport; no external
Playwright fallback or new browser dependency was needed. Mobile and other
browsers, full HTTP integration suites, and production SMTP were not tested.

## Risk

Misconfigured SMTP deployments will fail early. Local delivery is a development
outbox, not real email. SMTP outages and invalid provider credentials remain external
failure modes; this fix cannot guarantee provider availability.

## Rollback

Revert only the relevant application/UI hunks and rebuild affected images;
preserve pre-existing edits. Keep migration 053 and its compatible revision gate
when rolling back application behavior: the downgrade intentionally refuses to
restore the broken resend expression. Older 052-only consumers cannot start
against 053 without the compatibility patch. Do not restore incomplete SMTP
configuration, change database ownership/grants, or remove database volumes.

## Reviewer sign-off

Implementation: Codex. Backend/gateway/infra/security owner KunalTF (deputy
VidhiTF); console owner RaviiTF (deputy VidhiTF); root configuration/documentation
governance owners RaviiTF and VidhiTF. Independent
human approvals, current-head review links, and merge remain pending.

## T01 completion record (T01 only; otherwise N/A)

N/A: downstream invitation fix; fresh activation evidence is recorded above.
