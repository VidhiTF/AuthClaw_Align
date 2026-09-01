# Kafka-to-SQS audit transport readiness matrix

Scope: local production-readiness review for commits `ec2cc26` through `dfb36cf`.

Source requirements: architecture plan section 3.2 and `docs/adr/0011-audit-transport-selection.md`.

Status labels:

- `LOCAL-PASS`: verified by repository code, local tests, local Compose contract or speculative Terraform plan.
- `LIVE-EVIDENCE-PENDING`: requires deployed AWS/account evidence or approved canary data.
- `BLOCKED`: known code-level or local-readiness blocker.

| Requirement | Status | Commands / evidence |
| --- | --- | --- |
| Kafka remains default and complete rollback path | LOCAL-PASS | `AUDIT_STREAM_TRANSPORT` defaults to `kafka` in gateway, backend, agent and audit consumer; Terraform variable defaults to `kafka`; Kafka plan assertion passes with no SQS audit resources. |
| SQS activates only through explicit configuration | LOCAL-PASS | `AUDIT_STREAM_TRANSPORT=sqs_fifo`; `scripts/assert_audit_transport_plan.py kafka infra/terraform/kafka-plan.json`; `scripts/assert_audit_transport_plan.py sqs_fifo infra/terraform/sqs-plan.json`. |
| Producers use canonical audit-record UUIDs | LOCAL-PASS | Backend: `uv run --directory backend --with-requirements requirements-test.txt pytest -p no:cacheprovider tests/test_audit_transport_contract.py -q`; agent equivalent contract tests; gateway SQS FIFO Go tests. |
| Tenant ordering, deduplication and prior-hash behavior are equivalent | LOCAL-PASS | `uv run --directory audit_consumer --with boto3 --with clickhouse-connect --with python-dotenv python local_e2e.py --transport both --evidence ../infra/security/audit-transport-ci-e2e.md`; committed local evidence: `infra/security/audit-transport-local-e2e.md`. |
| Acknowledgement happens only after durable commit | LOCAL-PASS | `audit_consumer` focused suite: `31 passed`; consumer calls `ack()` only after `_process_message()` returns successfully. |
| Retry, visibility renewal and DLQ behavior fail safely | LOCAL-PASS | `audit_consumer/tests/test_transport_sqs_fifo.py`; E2E harness verifies retry, simulated DLQ and tenant isolation. |
| No static AWS credentials, secrets, account IDs or payloads are committed | LOCAL-PASS | Local scan/review found no committed real credentials in the audit transport phase; CI Terraform uses placeholder env vars only with provider AWS validation skipped. |
| Task-role IAM permissions are separated and least privilege | LOCAL-PASS | Speculative SQS plan includes producer-only send/metadata role and consumer-only receive/delete/visibility/metadata role; live IAM simulation remains deployment-only. |
| KMS, TLS-only policies, alarms, redrive and private endpoint configuration are coherent | LOCAL-PASS | Terraform fmt/init/validate and both mode plans pass; SQS plan includes encrypted FIFO queue/DLQ, TLS-only policies, redrive, alarms and private SQS endpoint. |
| Primary and secondary Terraform stacks behave correctly | LOCAL-PASS | Speculative plans run with secondary disabled for CI; conditional module wiring keeps Kafka mode free of SQS resources. Full secondary live-region behavior remains AWS-only. |
| CI change detection runs required audit gates | LOCAL-PASS | `.github/workflows/ci.yml` detects audit transport paths and gates backend, agent, gateway, audit-consumer E2E, Terraform plans and readiness pending evidence. |
| Local evidence is labelled `LOCAL-SIMULATION` | LOCAL-PASS | `infra/security/audit-transport-local-e2e.md` and `infra/security/audit-transport-local-benchmark.md`. |
| AWS evidence remains `LIVE-EVIDENCE-PENDING` | LOCAL-PASS | `scripts/sqs_audit_deployment_readiness.py --output-json infra/security/sqs-audit-ci-pending.local.json --output-md infra/security/sqs-audit-ci-pending.local.md`. |
| LocalStack/Redpanda evidence does not claim AWS performance or final transport selection | LOCAL-PASS | `infra/security/audit-transport-local-benchmark.md` explicitly states local results cannot determine AWS cost, production capacity or final transport decision. |
| No Kinesis implementation is added while ADR condition remains unmet | LOCAL-PASS | Repository search found Kinesis references only in ADR/baseline comparison material, not runtime transport implementation. |
| Generated evidence is not committed or regenerated unnecessarily by CI | LOCAL-PASS | Benchmark evidence is committed once as local simulation; CI runs the functional harness and readiness pending script without committing generated artifacts. |
| Deployed queue attributes, alarms, IAM simulation, endpoint coverage, ECS task roles and canary audit chain | LIVE-EVIDENCE-PENDING | Read-only deployment collector returns pending evidence without AWS: `scripts/sqs_audit_deployment_readiness.py`; production verification requires `--live` with approved read-only AWS access and optional explicit `--run-canary`. |

Final local verdict: `LOCAL-PASS` with AWS-only evidence pending. No code-level/local blockers are known.
