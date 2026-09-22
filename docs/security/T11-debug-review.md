# T11 debug and SQL logging review

Date: 2026-09-22

## Corrected disposition

Current `align/master` already defaults `Settings.DEBUG` to `False`. The confirmed
defects were narrower than the original report:

- deployment configuration exported `API_DEBUG`, which the settings model ignored;
- an operator could explicitly set `DEBUG=true` in a production-like or unknown
  environment, enabling SQL statement logging.

The fix was recreated from current `align/master`. It preserves the merged ENT-019
compliance settings and ownership validation, database revision `052`, connector
tenant configuration, ClickHouse configuration, and the existing CI test selection.

## Implemented contract

- `DEBUG` remains disabled by default.
- Docker Compose and environment examples use the settings field name `DEBUG`.
- Debug mode requires an explicit `AUTHCLAW_ENV` of `local`, `development`, `dev`,
  or `test`; shared, production-like, unknown, and unspecified environments reject
  `DEBUG=true` during settings initialization.
- SQLAlchemy continues to derive `engine.echo` from `settings.DEBUG` and keeps
  `hide_parameters=True` when local debug logging is enabled.
- The obsolete `API_DEBUG` variable is ignored and cannot enable debug logging.

## Fresh evidence

- `backend/tests/test_debug_settings.py`: 7 passed, 18 subtests passed.
- Adjacent backend regression suite: 162 passed, 1 skipped, 18 subtests passed.
  This included logging, startup security, migration-chain, compliance/ENT-019,
  T10 API contract, and audit-metrics coverage.
- `scripts/test_compose_contract.py`: passed for local, production, and obsolete
  `API_DEBUG=true` rendering cases.
- Live production-like rehearsal: a disposable PostgreSQL 16.10 database migrated
  to revision `052`; the restricted runtime role passed backend startup security
  validation; `/health` returned HTTP 200; and a real query reported
  `engine.echo=false` with `hide_parameters=true`. No SQL trace was emitted.
- `git diff --check`: passed.

No database writes, migrations, authorization changes, tenant-data operations, or
concurrency-sensitive code are part of this change. The skipped adjacent test is an
existing environment-dependent case and is unrelated to T11.
All rehearsal containers and their disposable database data were removed.

## Risk and rollback

The intentional behavior change is fail-closed startup when debug is enabled without
an explicitly local environment. Operators must set both `DEBUG=true` and an allowed
local `AUTHCLAW_ENV` for development diagnostics. Rollback consists of reverting the
settings validator and deployment variable rename together; partial rollback would
restore the naming mismatch or permit production SQL logging.

This evidence supports code review only. It does not claim required human approvals,
branch protection checks, deployment validation, or merge authorization.
