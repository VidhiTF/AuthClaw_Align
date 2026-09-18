# T10 implementation evidence and PR handoff

Baseline: `5ff6f4b9235c02705695e9821985bba13d2f29ae`. The user authorized committing and publishing T10 for review. No human approval, merge, deployment or release completion is claimed. This handoff follows the repository PR template; the PR records the published head and requests the required independent reviews.

## Jira

T10/P1, source Claims 5 and 12. No Jira identifier was provided. Corrected disposition: confirmed product/compliance semantics risk and ownership configuration debt. The user authorized implementation with B2B governance and security prioritized. The attached action-plan document was source material, not authorization to implement unrelated tasks.

## Engineering rules and prerequisite

CONTRIBUTING.md and AGENTS.md were read before edits. The fresh activation verifier passed on 2026-09-18 using `.quota-venv/Scripts/python.exe scripts/repository_policy.py --verify-github`: T01 PR 52, reviewed head `b8b23993a7a467396598eefdd23b97da83d47042`, merged SHA `1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, UTC effective date `2026-09-16T12:57:25Z`; live ruleset 21141288 active, zero bypass actors. The manifest and authenticated GitHub evidence establish T01 activation, not T10 approval.

## Scope

Canonical scores measure weighted qualified evidence coverage. A fully qualified, implemented control without blocking findings earns 100; otherwise it earns zero. Activity counts contribute only to separate non-authoritative diagnostics. Exact reviewed evidence, configured environment, integrity, freshness and disposition checks determine qualification. Consumers expose gaps/version and preserve backend readiness decisions. Evidence and T10 reviews are immutable; history retains method boundaries. The separate agent engine is explicitly diagnostic/unassessed.

VidhiTF requested changes on `588e179`: P2 correctly identified that the previous 84.9 cap still awarded canonical activity points; P3 identified successful TOTP replay across approvals. Both defects were reproduced before correction. Claim 12 passed and its owner configuration remains intact. See [review corrections](T10_REVIEW_CORRECTIONS.md) for decisions and new regression evidence. This revision does not claim reviewer acceptance.

Baseline regressions reproduced CC7.2 `100/compliant` from counts and absence of an aggregate readiness guard: 2 failures, 21 passes before the fix. Backend scorer, API, public package, console and agent paths were inspected. This coherent T10 change addresses the confirmed behavior; it introduces no certification claim. Cross-owner approval remains pending.

## Customer impact

Existing customers may see lower scores, missing-assessment gaps and legacy history labels. Review requires two distinct tenant administrators and fresh MFA. Internal owner names are configurable; public shares use neutral labels. The legacy tenantless agent snapshot/alert hook is disabled while stored history is retained. Agent reports no longer invent 100% compliance for empty/error states. Assessment administration uses APIs; no new management UI is included.

## Release notes

Compliance readiness now requires scoped, current, integrity-verified evidence independently reviewed with MFA. Scores show evidence gaps and calculation version; history separates methods. Activity volume and agent diagnostics cannot establish compliance. See [operations](T10_OPERATIONS.md) for configuration, intake and deliberately unsupported/incomplete controls.

## Schema and rolling-deployment compatibility

Migration 050 adds calculation version and assessment metadata to existing snapshots, changes uniqueness to tenant/framework/day/version, and protects T10 approval audits against update/delete. It preserves forced RLS. Old rows become `legacy_unversioned`; no historical evidence is backfilled as qualified.

Migration 051 adds a nullable per-user consumed TOTP timestep. Consumption is durable and serialized with the protected action, independent of approval IDs. Drain old backend snapshot and MFA writers before migration. New backend requires 051; gateway accepts 050/051. Deploy backend then consumers/agent; old writers must not overlap the cutover. New response fields are additive, and versionless UI data is explicitly labeled. The corrected scoring method uses `evidence-v3-`; historical assessments remain available but need fresh review to qualify under this method. Rollout and recovery steps are in the operations guide.

## Existing-code reuse

Searches found and reused the canonical scorer, APIs, snapshot model, public projection, Settings, evidence integrity writer, PendingApproval/ApprovalAudit, existing MFA, tenant session dependencies and transactional notifications. Console consumers were updated in place. Control weights remain; activity counts are diagnostics only and text traceability is display-only. Qualification gathers inputs in bulk. Unsafe agent tenantless scoring/fallback branches were removed; separate tenant models were not merged.

## New-line justification

These reuse decisions were documented before production edits: counts and text matches cannot supply exact reviewed assessments; existing gateway/remediation approvals cannot authorize arbitrary control claims. A narrow typed service is necessary for proposal binding, independent MFA review, immutable provenance and qualification. It reuses tables, cryptography and principals instead of adding a service, identity system or assessment store. Versioned metadata and serialized transactional upserts are necessary for history and alerts. Owner display uses existing Settings instead of a personnel directory.

The compact policy fingerprint binds executable decision definitions and integrity rules without duplicating thresholds. A scoring dependency sets isolation before authentication and uses one connection. Public access logging revalidates in a fresh transaction and increments atomically. Independent review identified these concurrency/security requirements.

The review correction reuses the existing User row and MFA verifier. Operation-specific Redis failure counters and per-approval timestamps cannot enforce global successful-proof consumption; one durable timestep column and migration are necessary. Backup codes are consumed under the same row lock and flushed before ORM refresh. Assessment principals lock in deterministic UUID order before MFA to avoid cross-over review deadlocks.

Final counts are recorded below. Tokei 12.1.2 and `scripts/check_line_budget.py` enforce per-file code budgets. Semantic duplicate merging is N/A: no logical duplicate cluster is relocated or merged.

## Security and compliance

No production credentials are added to tracked source/evidence. Disposable database credentials remain in ignored runtime files; test fixtures use clearly synthetic secrets. Intake requires actual user sessions, same-tenant active owner/admin principals, separate actors, fresh MFA, unchanged hashes and unexpired one-use approval. Source hashes, environment, exact requirements and finding disposition snapshots are bound into immutable audit/evidence. Removing or corrupting latest evidence cannot revive an older pass.

Missing configuration, unsupported producer/version, wrong scope, failed/stale/corrupt evidence, open/accepted risks, unreviewed terminal findings and incomplete implementation block qualification and canonical points. Activity gaps are diagnostic only. Read failures do not persist affirmative fallback scores. Public packages remove provenance IDs and traceability and never expose configured personnel. MFA rejects previously consumed and older timesteps across operations; consumption commits with the protected action, while unsuccessful transaction rollback permits retry. Existing secrets/TLS/debug/service policies remain in force; no external production dependency is added.

## Material line-growth exception

This change exceeds 100 positive net non-prose lines per file. Deletion elsewhere cannot offset growth. The necessary increase is typed review/qualification, versioned persistence and executable negative/concurrency evidence. Reusing counts, generic approval actions or text traceability was rejected because those do not establish the trust contract. Existing stores/infrastructure are reused and obsolete agent branches removed.

Actual counts follow below. Required independent owner approval markers from `scripts/repository_policy.py --pr-evidence <PR-number>` remain pending; this document cannot grant the exception.

## Tenant isolation evidence

Trusted tenant UUID comes from vetted credentials through authenticated database binding; assessment intake additionally rejects API keys. Sources, principals, findings, approvals, audits and snapshots are explicitly scoped. Forced RLS uses `authn.current_tenant_id()` with USING/WITH CHECK under restricted roles. Public shares bind their tenant and share/auditor access is revalidated after the consistent scoring read.

Application tests deny cross-tenant sources and assessment reads/reviews and verify public scope/provenance redaction. Actual PostgreSQL tests use a restricted non-superuser/non-bypass role for request paths; privileged setup is separate. They deny cross-tenant snapshot reads/inserts/updates, approval/audit reads, and history access. Similarity-search tests are N/A because T10 neither changes nor calls such a path.

## Test evidence

These local results cover the corrected working tree over `588e179`; the published PR records the final commit. The previously green CI on `588e179` is not evidence for this revision. Required fresh CI and reviewer acceptance remain pending.

| Acceptance | Executed evidence |
| --- | --- |
| Counts-only canonical zero; qualified controls independent of activity; qualification, source integrity, API/public/history contracts; durable MFA and baseline authentication | Integrated suite: 223 passed, four Redis-dependent tests skipped, 17.88s; includes all 19 new MFA unit cases and three public-safe Trust Summary metadata cases |
| Same-tenant session/role/scope; MFA requirement; self-review/replay/revocation; rollback; public projection | Real FastAPI and SQLite tests with explicit upstream identity/MFA fixtures |
| Real writer → scoped evidence → independent review → compliant CC7.2 | PostgreSQL tests parameterize minimal/high activity: counts alone produce 0/insufficient_evidence; reviewed CC7.2 earns 100 and SOC2 coverage 12.5 in either case |
| Migration 049→050→051, legacy retention, forced RLS, immutable audit, restricted roles | PostgreSQL suite: 18 required tests plus opt-in measurement passed (19 total, 35.72s) on local PostgreSQL 16.15; upgrades/downgrade use the restricted migrator, bootstrap uses owner, request paths use restricted runtime |
| Single connection/RR read → READ COMMITTED writes; concurrent upserts; one alert; atomic rollback; version history; downgrade refusal; concurrent public views | Same PostgreSQL suite; actual database concurrency and OTP validation |
| TOTP and backup single-use across approvals, concurrency and tenant boundaries | Real verifier through assessment endpoint; same code concurrent approvals yield exactly one success; next timestep succeeds; cross-over reviewers avoid deadlock; tenant state and downgrade protection enforced |
| Separate agent diagnostics, empty/error/report/history behavior | Original T10 verification: 22 tests passed in 2.78s on `588e179`; agent implementation is unchanged in this correction |
| Console qualification/version/history/error presentation | Fresh 49 units; TypeScript; public-claim checks; production build passed; 11 production-build browser scenarios passed with diagnostic 100 versus canonical 0; targeted lint passed with four existing navigation warnings |
| Schema cutover gate | Gateway `TestCompatibleDatabaseRevisions` passed, including six subcases |
| Line budgets | Tokei 12.1.2 and repository checker passed; final count snapshot below |

Backend reproduction: set DATABASE_URL and OWNER_DATABASE_URL to explicit disposable `_test` URLs, then run `.quota-venv/Scripts/python.exe -m pytest backend/tests/test_compliance_scoring.py backend/tests/test_control_assessments.py backend/tests/test_compliance_policy.py backend/tests/test_t10_api_contract.py backend/tests/test_trust_center.py backend/tests/test_migration_chain.py backend/tests/test_migration_038.py backend/tests/test_authorization_matrix.py backend/tests/test_mfa_replay.py backend/tests/test_auth_baseline.py backend/tests/test_release4_abuse_controls.py -q -p no:cacheprovider --disable-warnings`.

The local combined run explicitly set Python's `os.environ["REDIS_URL"] = ""` before `pytest.main` to skip four live-Redis checks because no local Redis was available, and used loopback port 1 with `connect_timeout=1` for optional audit writes outside the dedicated PostgreSQL suite. These four skips are not passes; required CI supplies Redis. An initial run waited on inherited Redis configuration and was stopped. The next run exposed two fixture setup errors from constructing an unused Redis client; the ORM fixture now isolates that client while exercising the real MFA verifier, and the final combined run passed. No production Redis fallback was introduced.

PostgreSQL reproduction uses the existing CI bootstrap environment and runs `pytest -q -p no:cacheprovider tests/test_t10_postgres.py` from backend. Local runner/output are retained in ignored `.quota-venv/t10-postgres/run-tests.ps1` and `results.txt`; credentials in the runner are disposable and must not be published. The suite creates and removes an isolated database. Docker engine startup failed; an official portable PostgreSQL server bound only to loopback supplied real testing without installing a system service.

Agent command from services/agent: `../../.quota-venv/Scripts/python.exe -m pytest --noconftest -p no:cacheprovider smoke_tests/test_compliance_diagnostics.py tests/test_audit_transport_contract.py -q`.

Console fixture browser tests validate rendering and request contracts against the production build, not live backend integration. Ignored reproduction helpers remain under console/.authclaw. Local Python is 3.12.14 versus repository 3.14.3; locked dependencies were installed with a Windows tzdata addition in the ignored venv. Locks are unchanged. Initial Windows resource/access errors occurred before collection; successful runs supersede those attempts, not the required CI run. The first corrected PostgreSQL run failed because a new legacy-user fixture omitted required platform_role; the fixture was corrected and all 19 tests passed.

Required backend/unit/PostgreSQL and agent CI selections now include these tests. PR CI, post-merge smoke, full regression and deployment validation remain separate gates.

Fresh synthetic measurement: 600 source records, 100 approved assessments, 200 review audits (700 evidence rows). Existing activity metrics took 22.56ms/17 SELECTs; the full framework without display traceability took 69.97ms/22 SELECTs with a 10,960-byte JSON payload. Qualification alone used five SELECTs and 2,091,714 peak Python bytes; its instrumented 211.77ms includes tracemalloc overhead and is not directly comparable to the uninstrumented time. This loopback Windows observation is neither a previous-release benchmark nor a production SLO result. Set `T10_POSTGRES_MEASURE=1` to repeat it; CI runs the 18 required tests and skips only this optional measurement. Disposable databases were removed and the portable server was stopped after verification.

Final non-prose size snapshot, 2026-09-18 07:49 UTC, against PR base `5ff6f4b`: production source **+1,324/−346**, tests **+2,149/−63**, configuration/tooling **+14/−4**. Positive growth summed per file is **3,173** (1,070 source, 2,093 tests, 10 configuration). User DOCX and documentation prose are excluded. Required material-growth owner approval is pending. Exact per-file counts and the tool hash are retained in ignored `.authclaw/t10-tooling/size-summary.json`; raw Tokei output is adjacent in `tokei.json`. Reproduce with Tokei 12.1.2 `--files backend/app gateway audit_consumer console/src --output json` piped to `scripts/check_line_budget.py`.

| Budget scope | Files counted | Largest file code lines | Per-file limit |
| --- | ---: | ---: | ---: |
| backend/app | 82 | 904 | 10,000 |
| gateway | 60 | 1,795 | 10,000 |
| audit_consumer | 19 | 695 | 10,000 |
| console/src | 126 | 2,124 | 10,000 |

All line budgets and `git diff --check` pass. New qualification service: 334 code lines; policy fingerprint: 68; modified scorer: 718. No dependency manifest/lock was changed. Local test outputs do not replace current-head CI or human review.

## Risk

Scores may decrease. Policy code changes change calculation identity and require new reviews; retain the deployed source/image with evidence. GDPR/HIPAA remain unsupported and partial SOC2 mappings remain blockers. Framework-wide finding scope is deliberately conservative until a trustworthy narrower mapping exists.

Repeatable reads extend transaction duration; qualification reads history in bulk. Synthetic performance observations are not production capacity approval. Staging latency/memory/payload, representative workload and agreed SLO acceptance remain required. Immutable audits affect retention/deletion and must not be removed to bypass downgrade guards.

## Rollback

Stop assessment/snapshot/MFA writers and disable affected surfaces on failed rollout. Preserve evidence, audits, versioned snapshots and consumed-proof state. Prefer a forward fix preserving qualification and replay prevention. Downgrade 051 refuses if any TOTP watermark exists; downgrade 050 refuses if T10 audits/versioned snapshots exist. Before any such state exists only, downgrade during a drained maintenance window. Do not restore count-only claims or disable replay protection, RLS or triggers. Follow the operations guide and established backup/restore procedure.

## Reviewer sign-off

Independent AI source review identified and drove fixes for finding-status bypass, pool exhaustion, incomplete version fingerprints, stale cached principals and public-view concurrency. It does not substitute for human approval.

Required owners per CODEOWNERS: platform/security KunalTF (deputy VidhiTF), agent VidhiTF (deputy KunalTF), console/API consumer RaviiTF (deputy VidhiTF), governance/CI RaviiTF/VidhiTF. Publication is authorized as KunalTF, so independent review is requested from VidhiTF and RaviiTF. Two current-head human approvals, applicable growth markers, PR CI, staging acceptance and merge evidence remain pending. Deployment and merge are not authorized by the publication request.

## T01 completion record (T01 only; otherwise N/A)

N/A: this is T10. T01 activation was verified above; this change does not alter the activation record.
