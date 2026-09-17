# T07 — Gateway database TLS: plan and acceptance evidence

Status: implementation and local acceptance complete on the working tree; live deployment, canary evidence, and required human review remain pending.

Reviewed baseline: `01033048797de4d449fb945e1794b1d857866888`.
Source: user-supplied Claim 11 and T07 screenshot. The attachment is reference material, not independent authorization to change or deploy code.

## Corrected disposition

The quoted string-append implementation is absent from this baseline. `gateway/db.go:133` parses configuration using `pq.NewConfig`; shared environments default an omitted SSL mode to `verify-full` and reject other effective modes. The original production plaintext-default mechanism is therefore historical at this baseline, not a freshly confirmed High vulnerability. Deployment state has not been verified.

The confirmed T07 gap was that shared/production startup accepted an omitted SSL mode by silently supplying `verify-full`, contrary to the explicit-configuration acceptance criterion. The working-tree implementation now rejects omission before connecting or listening while preserving explicit local-development behavior.

Target interpretation: shared/production DATABASE_URL must explicitly select `sslmode=verify-full`. Missing, empty, ambiguous, or weaker settings are rejected before connection attempts. An inherited PGSSLMODE alone does not satisfy the explicit URL/DSN requirement. Preserve supported keyword DSNs with equivalent explicit validation.

`require` is insufficient for this target: it does not guarantee hostname verification. Reference: https://www.postgresql.org/docs/18/libpq-ssl.html. The pinned local `github.com/lib/pq@v1.12.3/ssl.go` also distinguishes encryption-only, CA-only, and full hostname verification.

## Architecture and reuse findings

- `gateway/main.go` validates environment configuration, calls `InitDB`, and only then starts the HTTP listener.
- `gateway/db.go` owns config parsing, connector creation, initial ping, migration/RLS validation, and pool setup. Change the existing configuration boundary rather than adding a second database client.
- `gateway/redact.go:isSharedEnv` recognizes ci, shared-test, staging, stage, production, and prod. Reuse it; verify the startup environment validator rejects unknown names.
- `gateway/db_test.go:TestDatabaseConfigTLS` is the existing focused configuration test seam. Extend it and change omission expectations deliberately.
- The pinned driver reads PostgreSQL environment variables during `NewConfig`. Explicit-source validation must precede trusting the effective mode. Characterize URL/keyword parsing, duplicate options, service-file behavior, and environment precedence before selecting the smallest implementation.
- `ValidateDatabaseSecurity` validates migration and database authorization state; it does not prove TLS. Preserve it and avoid confusing a schema/RLS failure with a successful TLS rejection.
- `scripts/test_internal_tls.py` and `scripts/test_internal_tls_containers.py` offer synthetic-certificate/container patterns but do not constitute PostgreSQL gateway TLS evidence.
- Terraform injects DATABASE_URL from Secrets Manager. The reviewed code does not establish the contents of live secrets or mounted CA bundles.
- Gateway guidance, ADR-0004, the credential inventory, and required CI now use the explicit verified-TLS contract.

## Intended contract

1. Shared/production configuration requires an explicit unambiguous verify-full mode, a TCP hostname, and a usable trust source. Reject Unix-socket forms for this TLS contract and verify every host in supported multi-host configurations.
2. Reject disable, allow, prefer, require, verify-ca, unsupported/custom modes, missing/empty mode, malformed DSNs, and conflicting repeated TLS options. Credentials containing the text `sslmode` must have no effect.
3. A trusted CA and matching, valid server certificate permit connection. Missing/unreadable trust material, an untrusted issuer, expired certificate, hostname mismatch, or a server refusing TLS prevents startup. System trust is acceptable when deliberately configured and proven; do not assume every deployment needs a custom CA file.
4. No retry or fallback may reconnect without verification. Validate reconnects as well as the initial connection.
5. Explicit local development retains its documented exception. Shared-like aliases cannot acquire that exception through misspelling or whitespace/case handling.
6. Logs identify the failing configuration/handshake category without exposing passwords, full DSNs, private keys, or secret contents.

## Dependency-ordered implementation plan

1. **Activate the engineering gate.** COMPLETE for this baseline. The version-controlled verifier confirmed the two required reviews, merge ancestry, active live protections with zero bypass actors, and effective date. Retain the output below with implementation evidence and rerun it against the implementation head.
2. **Characterize current behavior. COMPLETE.** The new regression cases failed on the omission, inherited-mode, duplicate-mode, empty-mode, and socket cases before the production edit.
3. **Tighten the existing boundary. COMPLETE.** `databaseConfig` now requires exactly one explicit `verify-full` value in shared environments, checks the driver's effective mode, and rejects socket hosts. URL parsing uses `net/url`; a narrow keyword scanner follows libpq quoting/escaping and retains duplicates that `pq.Config` collapses.
4. **Prove process behavior. COMPLETE LOCALLY.** Disposable PostgreSQL containers exercised valid, expired, untrusted, hostname-mismatched, missing-CA, plaintext-only, reconnect, and certificate-replacement cases. The actual gateway reached HTTP health only with verified TLS and a non-superuser role that passed migration/security validation.
5. **Align delivery configuration and documentation. COMPLETE FOR VERSIONED FILES.** Required CI runs the new unit/process tests and uses an explicit gateway test DSN. Gateway guidance and security documents require `verify-full`. Live secret values and CA mounts remain an operator preflight because they are deliberately external to version control.
6. **Review and release. PENDING EXTERNAL ACTION.** Use the repository PR template, attach this evidence, obtain the required current-head component/security/governance approvals and material-growth marker, inspect live secret/CA configuration, and canary before production rollout.

New-line justification before implementation: modify existing functions/tests first. Any new production lines must enforce explicit provenance or reject ambiguous configuration that the current effective-mode check cannot distinguish. New test/harness lines are justified only by missing configuration/startup/handshake evidence. No semantic-duplicate consolidation is proposed.

## Acceptance-evidence matrix

Expected outcomes are not recorded as passes. The statuses below describe fresh working-tree evidence.

| ID | Scenario | Status | Observed evidence |
| --- | --- | --- | --- |
| T07-01 | Production/shared URL or keyword DSN omits sslmode, including existing query parameters | **PASS** | Unit and subprocess tests reject; the actual gateway exited 1 with the controlled configuration error, did not expose the password marker, and never listened on port 18081 |
| T07-02 | Missing/empty mode with PGSSLMODE=verify-full or other inherited settings | **PASS** | URL and keyword cases reject inherited or empty modes |
| T07-03 | disable/allow/prefer/require/verify-ca/custom or malformed mode | **PASS** | Focused cases reject every supported weak mode and malformed input in shared environments |
| T07-04 | Duplicate/conflicting modes, sslmode text in password, malformed URL, socket and multi-host variants | **PASS** | Duplicate/conflicting and socket cases reject; credential text is ignored; explicit multi-host verify-full remains accepted |
| T07-05 | verify-full + trusted CA + matching valid certificate | **PASS (local synthetic)** | `pg_stat_ssl` reported `ssl=true`, `TLSv1.3`, `TLS_AES_256_GCM_SHA384`; full `InitDB` validation passed and the actual gateway health endpoint returned 200 |
| T07-06 | Unknown CA, wrong hostname, expired certificate, missing/unreadable specified CA | **PASS (local synthetic)** | Each real handshake failed for its expected certificate/trust reason |
| T07-07 | PostgreSQL refuses TLS | **PASS (local synthetic)** | Driver returned `pq: SSL is not enabled on the server`; no plaintext fallback occurred |
| T07-08 | Reconnect after pool connection closes; certificate replacement | **PASS (local synthetic)** | Forced new pooled connection succeeded with the valid certificate; replacing the certificate on the same endpoint with an expired one caused rejection |
| T07-09 | Explicit local development exception and invalid environment names | **PASS** | Local omission remains disabled-TLS development behavior; shared aliases reject omission; environment-validation regression passes |
| T07-10 | Sanitized diagnostics and unchanged DB authorization validation | **PASS (local synthetic)** | Password marker absent from rejection output; non-superuser full `InitDB` passed revision 049 and database security checks over verified TLS |

`pg_stat_ssl` proves encryption of that connection; it does not prove client hostname verification. T07-06 negative handshakes provide the complementary verification evidence. Static tests, unrelated TLS tests, or another client's successful psql session cannot replace gateway handshake evidence.

## Evidence captured during this review

- Pre-change focused evidence confirmed omission, inherited settings, duplicate settings, and socket cases violated the intended contract. Post-change focused evidence passes every table case plus service-file provenance rejection.
- `gh auth status`: exit 0; active authenticated account `KunalTF`, HTTPS Git operations. Token value was redacted by the CLI/tool output.
- T01 verifier: exit 0. PR 52 reviewed commit `b8b23993a7a467396598eefdd23b97da83d47042`, merged commit `1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective `2026-09-16T12:57:25Z`, active ruleset `21141288`, zero bypass actors. Record owner: KunalTF.
- Installed official Go 1.26.5 Windows amd64 archive under the per-user Programs directory. Observed `go version go1.26.5 windows/amd64`; archive SHA-256 `97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38` matches the publisher value. Its `bin` directory was added to the user PATH.
- Focused configuration/startup tests: `go test -count=1 -run '^(TestDatabaseConfigTLS|TestInitDBRejectsUnsafeSharedDatabaseURL)$' -v .`: exit 0.
- Real TLS and security-validation tests: `go test -count=1 -run '^(TestDatabaseTLSIntegration|TestInitDBAcceptsVerifiedTLS)$' -v .`: exit 0 against isolated PostgreSQL 16 containers. Positive transport was TLS 1.3/AES-256-GCM; all five negative handshake cases passed.
- Actual gateway executable: verified configuration logged successful database initialization and served `GET /health` with HTTP 200. The omission run exited 1 with the controlled error and left the port closed.
- Required gateway CI selection, including the new T07 unit/process cases, passed against isolated Redis 7: `ok gateway`, exit 0.
- `go vet ./...`: exit 0. `python -m unittest scripts.test_repository_policy`: 27 tests passed. Tokei 12.1.2 line-budget gate: `Line budget OK`. `git diff --check`: exit 0.
- Docker evidence used official `postgres:16-alpine` digest `sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685` and synthetic credentials/certificates only.
- No live secret inspection, packet capture, deployment, or canary was performed. Those actions require release authorization and owner participation.

Future evidence bundle must retain exact command, UTC timestamp, tested commit/image digest, tool versions, synthetic topology, environment names, case IDs, expected/observed status, process exit codes, sanitized stdout/stderr, server connection evidence, and artifact hashes. Record skipped/failed cases explicitly. The package-level `TestMain` requires an explicitly named `_test` DATABASE_URL even for configuration-only tests; continue using an unreachable synthetic URL for unit-only commands and real isolated services for integration evidence.

## Consequences, rollback, and ownership

- Strict omission rejection can stop otherwise securely connected deployments that currently rely on automatic verify-full. Update URL/DSN configuration and trust provisioning before deploying the stricter binary.
- Hostname verification can reject IP endpoints, aliases absent from certificate SANs, and incorrect proxy endpoints. Validate the certificate presented at the actual PostgreSQL connection endpoint.
- CA rotation, unreadable mounts, and connection timeouts affect availability. Use valid overlapping trust during rotation and exercise reconnect behavior. Inspect timeout behavior before adding a bounded startup deadline; do not broaden this task into pool tuning.
- No database schema, tenant-key, API, or data migration is planned. Existing tenant authorization/RLS is retained. Cross-tenant CRUD evidence is N/A for a transport-only change unless implementation expands into authorization or queries.
- Rollback: restore the last verified TLS-capable binary/configuration and valid CA/hostname setup; do not restore plaintext or require-only operation. The present baseline's automatic verify-full may serve as a temporary operational rollback, but that would no longer satisfy strict T07 omission rejection.
- Gateway/infra security review: primary KunalTF, deputy VidhiTF per CODEOWNERS; two independent human approvals are required, with no self-approval. Governance review additionally applies if CI/policy paths change. Reviewers must inspect the final commit and raw negative/positive evidence.
- Production change in `gateway/db.go`: 126 added and 4 deleted lines (net +122 by `git diff --numstat`). Tests add 184 and delete 19 lines (net +165). Material non-prose growth exceeds 100 lines and requires the repository-policy marker in a current-head owner approval. Tokei confirms all hard path budgets remain within limits.
- Existing code was modified at the established database-config seam; no new production file, dependency, service, schema, or migration was introduced. The added keyword scanner is necessary because `pq.Config` intentionally collapses duplicates and does not expose whether `sslmode` came from the DSN, environment, or service file.
- Semantic-duplicate protocol: N/A. This change does not merge or remove logical duplicates.
