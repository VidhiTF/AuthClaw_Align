# Kafka-to-SQS audit transport readiness matrix

Scope: PR #19 local production-readiness review through Task 14C.

Source requirements: architecture plan section 3.2 and `docs/adr/0011-audit-transport-selection.md`.

Status labels:

- `LOCAL-PASS`: verified by repository code, local tests, local Compose contract or speculative Terraform plan.
- `LIVE-EVIDENCE-PENDING`: requires deployed AWS/account evidence or approved canary data.
- `BLOCKED`: known code-level or local-readiness blocker.

| Requirement | Status | Commands / evidence |
| --- | --- | --- |
| Kafka remains default and complete rollback path | LOCAL-PASS | `AUDIT_STREAM_TRANSPORT` defaults to `kafka` in gateway, backend and audit consumer; `AGENT_AUDIT_STREAM_TRANSPORT` defaults to `kafka`; Terraform variable defaults to `kafka`; Kafka plan assertion passes with no SQS audit resources. |
| SQS activates only through explicit configuration | LOCAL-PASS | `AUDIT_STREAM_TRANSPORT=sqs_fifo`; `scripts/assert_audit_transport_plan.py kafka infra/terraform/kafka-plan.json`; `scripts/assert_audit_transport_plan.py sqs_fifo infra/terraform/sqs-plan.json`. |
| Producers use canonical audit-record UUIDs | LOCAL-PASS | Backend direct-SQS and gateway-to-isolated-producer contract tests require canonical UUIDs. Legacy agent events are explicitly kept on Kafka until the agent emits ACL-21 canonical committed audit records. |
| Tenant ordering, deduplication and prior-hash behavior are equivalent | LOCAL-PASS | `audit_consumer/local_e2e.py --real-adapters` traverses backend producers, Redpanda/LocalStack consumers and ClickHouse; the common deterministic workload produces identical durable IDs, tenant sequences and chain heads before the separate SQS retry event. |
| Acknowledgement happens only after durable commit | LOCAL-PASS | Real-local adapter evidence records Kafka commits and SQS deletes only after ClickHouse inserts; the focused consumer suite also covers failure paths. |
| Retry, visibility renewal and DLQ behavior fail safely | LOCAL-PASS | `audit_consumer/tests/test_transport_sqs_fifo.py`; real-local LocalStack evidence separately verifies transient ClickHouse failure redelivery, durable commit before ack, and poison redrive to the FIFO DLQ. |
| No static AWS credentials, secrets, account IDs or payloads are committed | LOCAL-PASS | Local scan/review found no committed real credentials in the audit transport phase; CI Terraform uses placeholder env vars only with provider AWS validation skipped. |
| Task-role IAM permissions are separated and least privilege | LOCAL-PASS | Speculative SQS plan includes producer-only send/metadata roles for backend and the isolated `audit_producer`, plus a consumer-only receive/delete/visibility/metadata role. The co-located gateway/OPA/Presidio task has no task role, and the agent receives no canonical SQS producer role. Live IAM simulation remains deployment-only. |
| KMS, TLS-only policies, alarms, redrive and private endpoint configuration are coherent | LOCAL-PASS | Terraform fmt/init/validate and both mode plans pass; production-like SQS plan requires non-empty alarm actions. SQS plan includes encrypted FIFO queue/DLQ, TLS-only policies, redrive, alarms and private SQS endpoint. |
| Primary and secondary Terraform stacks behave correctly | LOCAL-PASS | Speculative plans run with secondary disabled for CI; conditional module wiring keeps Kafka mode free of SQS resources. Full secondary live-region behavior remains AWS-only. |
| CI change detection runs required audit gates | LOCAL-PASS | `.github/workflows/ci.yml` detects audit transport paths and gates backend, agent, gateway, audit-consumer E2E, Terraform plans and readiness pending evidence. |
| Local evidence is labelled `LOCAL-SIMULATION` | LOCAL-PASS | `infra/security/audit-transport-local-real-e2e.md`, `infra/security/audit-transport-local-e2e.md` and `infra/security/audit-transport-local-benchmark.md`. |
| AWS evidence remains `LIVE-EVIDENCE-PENDING` | LOCAL-PASS | `scripts/sqs_audit_deployment_readiness.py --output-json infra/security/sqs-audit-ci-pending.local.json --output-md infra/security/sqs-audit-ci-pending.local.md`. |
| LocalStack/Redpanda evidence does not claim AWS performance or final transport selection | LOCAL-PASS | `infra/security/audit-transport-local-benchmark.md` explicitly states local results cannot determine AWS cost, production capacity or final transport decision. |
| No Kinesis implementation is added while ADR condition remains unmet | LOCAL-PASS | Repository search found Kinesis references only in ADR/baseline comparison material, not runtime transport implementation. |
| Generated evidence is not committed or regenerated unnecessarily by CI | LOCAL-PASS | Benchmark evidence is committed once as local simulation; CI runs the functional harness and readiness pending script without committing generated artifacts. |
| Deployed queue attributes, alarms, IAM simulation, endpoint coverage, ECS task roles and canary audit chain | LIVE-EVIDENCE-PENDING | Read-only deployment collector returns pending evidence without AWS: `scripts/sqs_audit_deployment_readiness.py`; production verification requires `--live` with approved read-only AWS access and optional explicit `--run-canary`. |

The preceding evidence predates audit origin and transport hardening. Secure release
readiness remains LIVE-EVIDENCE-PENDING until the following checks are collected.

Shared workers require `CLICKHOUSE_SECURE=true`, `AUDIT_POSTGRES_URL` with
`sslmode=verify-full`, and (for Kafka) `KAFKA_SECURITY_PROTOCOL=SASL_SSL` with
`KAFKA_SASL_USERNAME` and `KAFKA_SASL_PASSWORD`. System certificate trust is the
default; optional `CLICKHOUSE_CA_CERT` and `KAFKA_SSL_CAFILE` paths must exist in
the worker image. Supply primary credentials through `audit_consumer_secret_arns`,
separate secondary-region credentials through `secondary_audit_consumer_secret_arns`,
and TLS options through `audit_consumer_environment`. Set `clickhouse_port=8443`.
Local Compose explicitly defaults to local/plaintext and no PostgreSQL verifier;
it is not a shared deployment. Origin verification does not change canonical v2
hashes. Exact authenticated replay is deduplicated; mismatched evidence is rejected,
and PostgreSQL unavailability leaves transport positions unacknowledged.

Configure servers and clients in the same rollout, without applying these changes
to running services from this task:

- Mount `infra/clickhouse/tls.xml` as `/etc/clickhouse-server/config.d/audit-tls.xml`
  and provision the referenced certificate/key with the server DNS name in its SAN.
  Move health checks, schema jobs and other ClickHouse HTTP clients to verified HTTPS.
  Disable or firewall plaintext native access as well. Give the mirror principal only
  `SELECT, INSERT ON authclaw.audit_events`; inspect `SHOW GRANTS` for inherited roles
  and verify UPDATE/DELETE/ALTER/TRUNCATE are denied.
- For Redpanda, merge the following into the existing broker configuration (preserve
  data directory, advertised DNS names, partitions, retention and offsets). Provision
  SCRAM users externally; enable authorization and remove anonymous publishing.
  Migrate all producers and topic-init jobs to authenticated TLS together. Existing
  local producers use plaintext and cannot be pointed at this listener unchanged.

```yaml
redpanda:
  kafka_api:
    - name: audit_secure
      address: 0.0.0.0
      port: 9093
      authentication_method: sasl
  kafka_api_tls:
    - name: audit_secure
      enabled: true
      require_client_auth: false
      cert_file: /etc/audit-tls/broker.crt
      key_file: /etc/audit-tls/broker.key
```

Listener configuration follows [Redpanda authentication documentation](https://docs.redpanda.com/streaming/current/manage/security/authentication/).
ClickHouse HTTPS configuration follows [ClickHouse TLS documentation](https://github.com/ClickHouse/clickhouse-docs/blob/main/docs/guides/sre/tls/configuring-tls.md).

- Broker ACLs: trusted producers may WRITE only their audit topics; the mirror may
  READ those topics and its consumer group, and WRITE only `audit.deadletter`.
  Verify an unrelated principal cannot publish. Require replication and
  `min.insync.replicas` appropriate to the deployment; DLQ clients use `acks=all`.
- Provision a dedicated PostgreSQL LOGIN that inherits only the NOLOGIN
  `authclaw_audit_verifier` capability role. It needs database CONNECT but no direct
  table privileges, writer-role membership, mutation privileges or superuser rights.
  Verify it can execute `public.verify_audit_origin` and that unrelated roles cannot.
  Do not reuse a producer or database-owner credential.
- In staging, prove trusted TLS connections succeed and expired/untrusted/wrong-host
  certificates and missing SASL credentials fail. Verify forged/rehashed, tampered,
  cross-tenant and replayed events against PostgreSQL, Kafka DLQ outages and retries,
  SQS visibility/redrive, tenant ordering and mirror continuity. Record effective
  grants, ACLs and immutable evidence before release.
- Retain the previous worker image/task definition, database volumes, broker offsets,
  queue evidence and certificate configuration. Do not reset offsets or delete data
  during rollout or rollback; stop the worker and restore the recorded compatible
  image/configuration if verification fails. Rollback must preserve origin checks
  and secure transport in shared environments.
