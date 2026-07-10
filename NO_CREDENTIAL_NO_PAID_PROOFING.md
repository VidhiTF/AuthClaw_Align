# No-Credential / No-Paid-Dependency Proofing Plan

This document separates what AuthClaw can honestly prove without cloud credentials,
paid services, external auditors, or real users from what can only be simulated or
left as an optional live-evidence path.

## Bottom Line

AuthClaw can make most of the remaining SRS gaps stronger without spending money:

- local and CI proof for tier limits, worker throttling, policy behavior, audit
  integrity, compliance evidence packaging, red-team thresholds, and release
  readiness;
- simulated failover and recovery evidence for HA workflows;
- mocked or local-provider cloud-remediation tests;
- audit-ready placeholders for evidence that must later come from cloud accounts,
  a pentest vendor, or a SOC 2 auditor.

AuthClaw cannot honestly claim live 99.99% availability, true multi-region
active-active writes, external penetration-test completion, or SOC 2 attestation
without external systems or third parties.

## Fully Doable Without Credentials Or Paid Dependencies

| Work item | What can be completed locally | Evidence artifact to produce |
| --- | --- | --- |
| Tier-based tenant limits | Add a deterministic tier-to-quota map for starter/pro/enterprise and enforce it in backend/gateway paths. | Unit tests plus CI gate proving tier decisions. |
| Gateway policy rate limits | Exercise per-tenant and per-route request limits with Redis/test Redis or in-memory test doubles. | Gateway tests and rate-limit report. |
| Background worker throttling | Add local throttles for scans, evidence jobs, red-team jobs, and remediation workers. | Worker throttle tests showing queue/backoff behavior. |
| SOC 2 evidence automation structure | Generate evidence manifests from local CI outputs, test reports, config snapshots, signed audit exports, and release metadata. | `compliance-evidence.json` and signed bundle. |
| Audit-ready release checklist | Add a checklist that gates release on tests, scans, migrations, rollback notes, DR notes, and signed audit export verification. | Machine-readable checklist plus markdown summary. |
| Red-team pass/fail thresholds | Define severity thresholds, probe categories, failure budgets, and CI pass/fail behavior. | Red-team test report with pass/fail result. |
| Security runbooks | Document incident response, secret rotation, audit export verification, DR simulation, and release rollback. | Runbook markdown files. |
| Control evidence pipeline | Validate required evidence files exist and contain expected fields. | CI job output from local fixture evidence. |
| Cloud connector contract tests | Mock AWS/GCP/GitHub APIs and prove request construction, permission boundaries, rollback behavior, and audit logging. | Contract tests with no real cloud calls. |
| Remediation workflow proof | Seed local findings, run simulated remediation, require HITL/MFA where destructive, and verify rollback path. | Local remediation proof report. |
| Route53 failover simulation | Validate Terraform intent and simulate health-check state changes in fixture data. | Simulated failover evidence JSON. |
| RTO/RPO calculation logic | Prove that scripts reject missing/invalid recovery metrics and accept compliant fixture metrics. | HA evidence validator tests. |
| Latency proof harness | Run benchmark locally/CI against local gateway and fail if threshold is exceeded. | Benchmark JSON and CI summary. |
| Tenant isolation proof | Use local database/RLS tests with synthetic tenants. | Tenant isolation test report. |
| Cryptographic audit export proof | Generate signed exports locally and verify tamper detection. | Signed export fixture and verification report. |

## Doable Only As Simulation Without Credentials

| Work item | Honest local version | What it does not prove |
| --- | --- | --- |
| Route53 failover | Terraform validation plus simulated failover evidence. | Real DNS failover timing or AWS health-check behavior. |
| Multi-region service recovery | Validate Terraform, run local restart/failover scripts, and check synthetic RTO/RPO fields. | Real regional outage recovery. |
| Database promotion workflow | Document and test command sequencing with fixture metadata. | Actual replica promotion, replication lag, or data correctness after cloud failover. |
| Cloud remediation | Mock AWS/GCP/GitHub APIs and validate permissions, payloads, approvals, audit events, and rollback. | Real provider-side changes. |
| KMS/Vault envelope encryption | Test AES-GCM and provider adapter validation with fake/local keys. | Real AWS KMS/Vault availability, IAM, key policy, or rotation. |
| LLM red-team evaluation | Test deterministic probes against local/mocked model responses. | Behavior of real OpenAI/Anthropic/Cohere/Azure models. |

## Not Honestly Finishable Without External Dependencies

| SRS claim | Why it needs external proof |
| --- | --- |
| Demonstrated 99.99% availability | Requires running deployed infrastructure over time or controlled production-like failover tests. |
| True active-active data writes | Requires a real multi-region write-capable datastore strategy and conflict/consistency validation. |
| Route53 failover proof | Requires AWS credentials, hosted zone setup, health checks, and live DNS observations. |
| External penetration test | Must be performed by an independent external party. Internal scans are not an external pentest. |
| SOC 2 attestation | Requires an auditor. AuthClaw can automate evidence, but cannot self-attest SOC 2. |
| Live AWS/GCP/GitHub remediation proof | Requires provider credentials and sandbox resources. |

## Recommended No-Paid Path

1. Implement all local-only controls first: tier quotas, worker throttles, release
   checklist, evidence manifest generation, red-team thresholds, and contract tests.
2. Add a clear evidence label to every generated artifact:
   - `local-proof`: fully proven without external systems.
   - `simulation-proof`: behavior validated with fixtures or mocks.
   - `credential-required`: live proof requires cloud or SaaS credentials.
   - `third-party-required`: proof requires an external pentester or auditor.
3. Keep optional live-proof scripts, but make them skip cleanly when credentials
   are absent.
4. Avoid claiming production HA, active-active writes, external pentest completion,
   or SOC 2 completion until real evidence exists.

## Local Proof Gate Added

The no-credential path is now machine-checkable:

```bash
python scripts/no_credential_proof.py infra/security/no_credential_proof.local.json
```

Artifacts:

- `infra/security/no_credential_proof.local.json` maps every local/simulation work item to concrete evidence and tests.
- `infra/security/compliance-evidence.local.json` is the local SOC 2/control evidence manifest structure.
- `infra/security/audit-ready-release-checklist.local.json` and `infra/security/AUDIT_READY_RELEASE_CHECKLIST.md` define the local release checklist.
- `backend/app/services/tier_limits.py` defines deterministic starter/pro/enterprise quotas.
- `backend/app/services/worker_throttle.py` enforces local scan/evidence/red-team/remediation throttling.

## Practical Completion Target Without Credentials

Without credentials or paid dependencies, AuthClaw can reasonably reach:

- **95-100%** completion for tier limits, throttling, local compliance automation,
  red-team thresholds, release checklist, signed audit exports, tenant isolation,
  and policy enforcement.
- **70-80%** completion for HA/failover, because only simulation and Terraform
  validation are possible.
- **60-75%** completion for cloud remediation, because provider APIs can be mocked
  but live side effects cannot be proven.
- **0% live completion** for external pentest and SOC 2 attestation, while still
  reaching **80-90% readiness** for the evidence package those parties would review.
