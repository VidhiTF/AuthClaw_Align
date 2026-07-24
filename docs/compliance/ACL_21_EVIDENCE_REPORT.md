# ACL-21 implementation evidence report

- Branch: `feat/audit/ACL-21-immutable-evidence`
- CI disposition: project waiver; local focused validation is authoritative for
  this change.
- Python baseline: 3.14.3

## Evidence checklist

- [x] Migration 028 applied to a disposable PostgreSQL database.
- [x] 100 concurrent same-tenant appends produced contiguous sequences.
- [x] Concurrent multi-tenant append test passed for four tenants.
- [x] Duplicate replay returned the original row.
- [x] Idempotency collision with changed content failed.
- [x] Audit `UPDATE` and `DELETE` were rejected.
- [x] Kafka failure retained unpublished outbox rows in focused tests.
- [x] ClickHouse outage/gap left the event retryable in focused tests.
- [x] PostgreSQL replay reconstructed ClickHouse rows in focused tests.
- [x] Export v2 verified with a pinned key and offline command.
- [x] Wrong/revoked/unknown keys and attacker re-signing failed.
- [x] First/middle/last deletion, reorder, duplication, cross-tenant injection,
  payload, manifest, and signature tampering failed.
- [x] Filtered export retained intermediate proof records.
- [x] Additive rollback was verified by migration review: downgrade removes only
  the append function and retains immutable rows, columns, trigger, and outbox.

## Attachments for Jira

Attach the focused test transcript, a redacted sample signed artifact, its
SHA-256 checksum, the trusted-key registry containing public data only, tamper
test transcript, ClickHouse reconstruction report, and rollback proof. Never
attach signing private keys or production event payloads.

Local command results and artifact hashes are recorded in
`docs/compliance/evidence/acl21-local-test-results.md`.
