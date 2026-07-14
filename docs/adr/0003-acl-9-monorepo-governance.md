# ADR-0003: ACL-9 monorepo governance and verification

- Jira: ACL-9 / F04
- Status: Implemented -- pending pull-request approval
- Decision date: 2026-07-14
- Owner: Kunal
- Review owner: Binod / AgentsArchitects

## Context

AuthClaw already exists as the consolidated repository selected by ACL-6. ACL-9 makes
that repository usable as the governed delivery baseline: a clean checkout must build,
feature work must return through protected contributor branches, ownership must route
reviews, and required checks must be capable of blocking a broken merge.

The first ACL-9 pull-request run exposed three baseline failures: CodeQL could not read
workflow metadata, Gitleaks could not read pull-request commits and used an unsupported
action input, and the full-stack job referenced a missing backend Dockerfile. Local
full-stack verification then exposed invalid development encryption defaults and two
console-to-backend URL/preflight defects.

## Decision and completed work

1. `master` remains release integration and contributors work through `dev/*` branches
   using `feat|fix|chore/<area>/<JIRA-KEY>-slug` branches.
2. `CODEOWNERS`, the pull-request template and `docs/BRANCH_GOVERNANCE.md` define review
   routing, required evidence and rollback expectations. GitHub branch rules remain the
   enforcement authority.
3. CI now runs for pull requests to `dev/**`, grants the least additional read access
   required by CodeQL and Gitleaks, uses supported Gitleaks environment settings, and
   keeps scanning independent of optional SARIF storage. CodeQL analysis runs locally
   in the job without uploading until repository code scanning is enabled by an admin.
4. Full and demo Compose builds use the existing backend `Dockerfile.demo` and valid
   development-only JWT and Fernet defaults. Production still fails closed without
   managed secrets.
5. The console preserves `/api/v1` when joining canonical API paths, server-side shared
   Trust Center requests use the private backend URL, and authenticated CORS preflight
   requests reach the CORS middleware. Playwright runs only browser specifications,
   targets the already-started Compose console in CI, and its mocks follow canonical
   backend routes.

No new dependency, service, data model or database migration was added.

## Acceptance evidence

| ACL-9 criterion | Evidence |
| --- | --- |
| Canonical repository builds from a clean checkout | All application images build; the full Compose stack starts from fresh volumes; backend, agent, gateway and console health checks return HTTP 200 |
| Main blocks direct pushes and requires green checks plus review | Required GitHub rule set is documented in `docs/BRANCH_GOVERNANCE.md`; `CODEOWNERS` routes final review to AgentsArchitects; CI runs on `dev/**`, `main` and `master` pull requests |
| CODEOWNERS and PR template cover platform, agent/compliance and console/access | `.github/CODEOWNERS` covers gateway/backend/audit/infra, agent and console; `.github/pull_request_template.md` requires scope, security, tests, migration/rollback and evidence |

Local verification completed before review:

- full Compose build, startup, seed and smoke checks;
- live browser login and authenticated System Overview;
- console production build, lint, four API-contract tests and 34 Playwright tests
  (eight explicitly opt-in real-stack scenarios remain skipped by CI);
- Gitleaks with no findings, `pip-audit` with no known vulnerabilities,
  `govulncheck ./...` with no vulnerabilities, and `npm audit --audit-level=high`
  with no high-severity failure;
- gateway latency benchmark within configured thresholds;
- both Compose files render successfully and `git diff --check` passes.

The pull request's GitHub checks are the final acceptance evidence for CodeQL, security
scanning and the clean full-stack gate.

## Telemetry and rollback

Runtime verification uses the existing health endpoints, container logs and GitHub job
logs. Gateway benchmark evidence is retained in the job summary so the gate does not
depend on optional artifact storage. No additional telemetry pipeline is required for
repository governance.

Rollback is a normal revert of the ACL-9 commit. The change has no schema migration and
does not alter production data. Local disposable state can be removed with:

```bash
docker compose --profile ci -f docker-compose.full.yml down -v
```

Production secrets must never be replaced with the documented local defaults.

## Consequences

- Broken security, build or full-stack checks block merge once the documented GitHub
  rules are enabled.
- Console, backend and Compose share one tested local baseline instead of relying on
  legacy paths or missing build files.
- ACL-6 and ACL-29 remain independent review records and are not modified by ACL-9.
