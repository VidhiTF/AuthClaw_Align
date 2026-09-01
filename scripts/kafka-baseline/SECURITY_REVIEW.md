# Security review checklist for Kafka baseline tooling

## Pre-flight checks

- Verify all commands are read-only:
  - No `alter`, `delete`, `truncate`, `drop`, `set`, `reset`, `update`, `producer`/`consumer` offset rewinds.
- Verify no credential-bearing environment variable is exported to outputs:
  - Exclude `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL` password segments, SMTP/LLM keys, and secrets.
- Verify command logs are file-redirected to dedicated evidence paths with filesystem permission
  constraints in the execution environment.
- Verify runbook marks whether this was executed in staging/production and whether
  representative load was active.

## During run

- Use read-only roles for DB and Kafka observability actions.
- For AWS CLI use a role that cannot mutate cluster or create endpoints.
- Restrict output files to approved evidence bucket/path.

## Post-run

- Confirm any temporary token/env injection files are removed.
- Confirm output directory is added to evidence evidence with least privileges.
- Confirm no raw payload dumps were created.

