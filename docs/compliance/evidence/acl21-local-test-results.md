# ACL-21 local validation — 2026-07-20

Runtime: Python 3.14.3, Go 1.26.4.

| Validation | Result |
| --- | --- |
| Backend ACL-18/auth/audit/export/privacy/worker/trust-center tests | 74 passed |
| Audit consumer mirror/hash/backbone tests | 25 passed |
| Focused Gateway audit/Kafka/outbox tests | passed (6.396s) |
| Python canonical append against PostgreSQL | 1 passed |
| PostgreSQL 100-writer same-tenant test | passed |
| PostgreSQL four-tenant concurrent test | passed |
| Alembic ACL-18 027 to ACL-21 028 upgrade | passed; single head 028 |
| Offline sample export verification | verified |

The PostgreSQL tests also assert exact replay, changed-content idempotency
collision, contiguous tenant sequences, canonical SHA-256 values, one outbox row
per append, and rejection of audit-row `UPDATE` and `DELETE`.

Fault-injection tests assert ClickHouse query/insert retry behavior, sequence-gap
retry, exact duplicate replay after a process boundary, Kafka publish failure
propagation, proof tampering, cross-tenant injection, and signing-key failures.

The full Gateway package run reached the ACL-21 tests but later failed in the
unrelated baseline `TestGetOrCreateRedactionTokenIsIdempotentUnderConcurrency`
when the local PostgreSQL connection was forcibly closed. The focused ACL-21
Gateway selection passed on the same database.

## Master compatibility

ACL-21 was rebased onto master commit `2234128`. Master added ACL-18 migration
027, so the ACL-21 migration is now 028 and follows 027.

A migration run against an empty database exposed an upstream master baseline:
ACL-18 migration 027 alters `approval_audit`, but no earlier migration creates
that table. After supplying the pre-existing `approval_audit` table represented
by the master ORM model in the disposable database, the real 026 -> 027 -> 028
upgrade completed and reported a single head at 028. ACL-21 does not hide or
work around that unrelated bootstrap defect.

## Synthetic review artifacts

- `acl21-sample-export.json`
  SHA-256 `d4e9811cb46f7f8b284126c368f8cf6bc45132a96442356f7090a10997a7480c`
- `acl21-sample-trusted-keys.json`
  SHA-256 `d969b608dfd180b5e40a0777dce17e42199f0cb1445c952ab186eafbbd4eb447`

The sample uses a public, non-production deterministic seed and contains only
synthetic tenant/event data.
