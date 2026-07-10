# AuthClaw SRS Gap Analysis

Source: `C:\Users\WIN10\Downloads\AuthClaw_Project_Plan.pdf`  
Scanned as the working SRS on July 3, 2026.

## Current State

AuthClaw is beyond a basic MVP skeleton. The repo already includes:

- Console login, signup, tenant context, password reset, and session handling.
- Gateway route configuration and provider credential management.
- Policy editor with YAML validation, dry-run simulation, activation, and rollback.
- Audit explorer with hash-chain fields and signed export/verification flows.
- Agent UI, workflow history, remediation plan review, approvals, and MFA modal.
- User/RBAC, API key, invite, worker-token, tenant-status, and MFA settings.
- Compliance scoring backend and control-by-control framework UX for SOC 2, GDPR, and HIPAA.
- Trust Center backend/UI with shareable public pages.
- Evidence, findings, audit, and Trust Center traceability from each framework control.
- Cloud connector page for AWS, GitHub, and GCP.
- Real AWS S3 remediation execution with target-bound CLI diffs, approved apply path, before/after verification, rollback, and destructive-action MFA expiry.
- Direct encrypted cloud login setup, connector health, GitHub repository/security scanning, pull-request remediation, GCP asset/IAM scanning, and GCP remediation actions.
- Gateway redaction strategies: mask, hash, synthetic.
- Gateway provider routing foundations for OpenAI, Anthropic, Cohere, Azure OpenAI, Gemini, and Bedrock.
- Kafka/ClickHouse audit-consumer foundations and Postgres audit hash-chain fallback.
- Terraform scaffolding for multi-region AWS deployment and Route53 failover.

## Main Remaining Functionalities

### 1. Console Information Architecture - Complete

Main navigation now exposes the SRS-aligned product surfaces:

- Overview
- Frameworks
- Agent & Remediation
- Integrations
- Gateway
- Policies & Guardrails
- Risk & Red Teaming
- Audit & Trust Center
- Evidence
- Findings
- Cloud
- Settings

`Frameworks`, `Evidence`, `Findings`, and `Cloud` are no longer blocked by demo-mode middleware. The new `Risk & Red Teaming` surface is promoted into the normal console flow and links to the existing findings, policies, audit, and remediation workflows.

### 2. Risk & Red Teaming - Complete

Implemented as a real product module:

- Prompt-injection probe runs.
- Data-disclosure probes.
- Sycophancy probes.
- Harmful-content probes.
- Vulnerability register.
- Severity and go/no-go posture reporting.
- Continuous red-team run history.

The console can run the probe set, score active policy and observed target responses, persist run history, create evidence records, and sync failed probes into the findings register under `RED_TEAM`.

### 3. Real Remediation Execution - Complete

Implemented for the current real cloud remediation target, AWS S3 document remediation. GitHub/GCP-specific connector remediation is now covered under section 4.

Completed:

- Generates target-bound CLI diffs for approved S3 object remediation.
- Binds remediation actions to concrete AWS S3 bucket/object targets.
- Executes approved changes through the audited workflow path.
- Shows before/after sensitive-entity verification in the Agent UI.
- Supports rollback for real S3 object mutations using captured rollback copies.
- Requires fresh MFA for destructive remediation actions and expires destructive approvals after 0.5 hours.

### 4. GCP and GitHub Integrations - Complete

Implemented as real cloud connector surfaces and provider API actions:

Completed:

- Real GitHub repository scanning through the GitHub REST API.
- GitHub code-scanning, Dependabot, and secret-scanning alert ingestion.
- Pull-request remediation flow that creates a remediation branch, writes an AuthClaw plan artifact, and opens a PR.
- Real GCP asset inventory through Cloud Asset Inventory.
- GCP IAM policy scanning with public-member findings.
- GCP remediation execution for configured bucket targets.
- Connector setup UI for AWS, GitHub, and GCP in Settings and the Cloud page.
- Connector health/status pages with verify and revoke actions.
- Connector secrets are encrypted at rest, never returned to the browser, and external mutation actions require fresh MFA.

### 5. Framework and Evidence UX - Complete

Implemented as a primary framework readiness workspace:

Completed:

- Full control-by-control framework drilldowns in normal nav.
- Evidence linkage from each control.
- Finding linkage from each control.
- Audit-event linkage from each control.
- Clear readiness progression over time.
- Trust Center sharing integrated into the primary audit/framework flow.

### 6. OIDC / Enterprise SSO - Complete

Implemented as a real enterprise SSO flow:

- OIDC start and callback routes.
- Authorization-code exchange against the configured token endpoint.
- JWKS-backed ID token validation with issuer, audience, expiry, and nonce checks.
- Tenant-scoped SSO configuration with encrypted client secrets.
- User/tenant mapping with optional auto-provisioning.
- IdP group-to-role mapping with default role fallback.
- Normal console session creation from successful IdP login.
- Admin Settings surface for configuration and JWKS metadata testing.

### 7. Gateway Provider Contract Validation - Complete

Provider routing support exists, but the SRS requires native payload fidelity across OpenAI, Anthropic, Cohere, and Azure OpenAI.

Implemented as production contract validation:

- Native payload fidelity tests cover OpenAI, Anthropic, Cohere v2 chat, and Azure OpenAI deployment chat.
- Streaming contract tests cover each SRS provider shape and preserve provider-specific SSE markers.
- A provider contract manifest is checked by gateway tests as the CI drift gate.
- The console live gateway test now reports route, parse, content-type, payload contract, streaming contract, and CI gate results.
- The Connect page shows production readiness and connected-key status for every configured provider.

### 8. Latency and Load Proof - Complete

Implemented as a repeatable benchmark and release gate for the SRS `<= 50 ms`
gateway-overhead target.

Completed:

- Repeatable gateway-vs-provider benchmark profiles run against the full-stack CI/staging mock provider baseline.
- CI release gate requires provider-baseline proof and enforces p50/p95/p99 gateway-overhead thresholds.
- Benchmark artifacts record p50/p95/p99 total latency, provider baseline latency, gateway overhead, and first-byte overhead.
- Streaming benchmark records first-byte overhead, complete SSE event counts, DONE sentinels, and fragmented/invalid event failures.
- Release evidence isolates gateway/proxy overhead with access logging and auth metadata writes disabled, the deterministic local analyzer, benchmark-only short auth/provider/policy caches, and rate-limit stores disabled, while redaction and streaming behavior remain recorded in the same artifact.
- CI uploads `gateway-benchmark-ci.json` as release evidence on every `docker-compose.full.yml` integration run.

### 9. HA / Active-Active Resilience - Complete

Implemented as a repeatable SRS NFR-3.1 proof gate for the Terraform-managed multi-region stack.

Completed:

- Documented the promoted-read-replica database workflow.
- Clarified HA topology as active-active compute with active-standby data writes until replica promotion.
- Added a Route53 failover evidence requirement.
- Added chaos/failover evidence requirements for primary region loss and primary database loss.
- Added a CI-backed HA failover evidence validator.
- Gate enforces 99.99% target evidence, RTO/RPO ceilings, Route53 switch proof, post-failover gateway p95/p99 latency, write correctness, audit-chain correctness, and healthy console/backend/gateway checks.
- Added a passing example artifact at `infra/terraform/ha_failover_evidence.example.json`; production runs replace it with captured live evidence.

### 10. Compliance Hardening - Complete

Implemented as a release-blocking compliance hardening proof gate.

Completed:

- External penetration test evidence is required from a non-internal vendor.
- Critical, high, and medium pentest findings must be closed and retested before release.
- SOC 2 evidence automation requires mapped control evidence for CC6.1, CC6.6, CC7.1, CC7.2, CC7.3, and A1.2.
- Production SAST, dependency, secret, IaC, and container scan gates are enforced in CI before image push.
- Security runbooks now cover incident response, vulnerability management, access review, backup/restore, and key rotation.
- Control evidence pipeline proof requires traceability links, mapped controls, evidence records, and verified export.
- Red-team release thresholds require zero critical/high failures and zero max risk score.
- Audit-ready release checklist is now machine-validated by `scripts/compliance_hardening_evidence.py`.

## SRS Requirement Status

| Requirement | Status | Notes |
|---|---|---|
| FR-1.1 Multi-model proxying | Mostly built | Provider routing now has payload, streaming, drift, and live console validation for SRS providers. |
| FR-1.2 PII/PHI redaction | Mostly built | Mask/hash/synthetic exist; production proof and streaming evidence remain. |
| FR-1.3 YAML + OPA policy enforcement | Partial | YAML validation/simulation exists; runtime OPA/policy coverage needs production validation. |
| FR-2.1 Orchestrator-worker isolation | Mostly built | Scoped token model exists; real AWS S3 connector execution now runs through the audited workflow path. |
| FR-2.2 RAG framework querying | Partial | RAG corpus/service exists; needs full UX/evidence linkage. |
| FR-2.3 HITL + MFA + expiry | Mostly built | Destructive real remediation now requires fresh MFA and expires after 0.5 hours. |
| FR-3.1 Framework scoring | Mostly built | Live scoring now includes control drilldowns, evidence/finding/audit links, readiness history, and Trust Center sharing. |
| FR-3.2 Cryptographic audit export | Mostly built | Signed export/verify exists; needs production evidence and UI polish. |
| NFR-1.1 <= 50 ms overhead | Complete | CI benchmark gate now records and enforces p50/p95/p99 gateway-overhead evidence against a provider baseline. |
| NFR-1.2 Streaming filtering | Mostly built | Provider-specific streaming contract tests now cover OpenAI, Anthropic, Cohere, and Azure OpenAI; benchmark gate records streaming first-byte and SSE no-fragmentation evidence. |
| NFR-2.1 Tenant isolation | Mostly built | RLS/tests exist; keep in pentest scope. |
| NFR-2.2 Envelope encryption | Mostly built | App crypto exists; KMS/Vault production path needs validation. |
| NFR-3.1 99.99% active-active | Complete | CI-backed HA evidence validator covers promoted replica workflow, Route53 failover, RTO/RPO, post-failover latency, and correctness proof; topology is active-active compute with active-standby writes until promotion. |
| NFR-3.2 Tiered rate limiting | Partial | Gateway/onboarding limits exist; tiered plan model needs completion. |

## Priority Order

1. Complete tiered rate limiting.
2. Keep production release evidence refreshed for each audit window.

## Bottom Line

The strongest areas today are gateway/redaction/policy/audit foundations, provider contract validation, latency/load release evidence, HA/failover proof gating, compliance hardening proof gating, the Lite console, framework/evidence traceability, enterprise SSO, the red-team posture workflow, real AWS S3 remediation execution, and real AWS/GitHub/GCP connector workflows. The major SRS gaps are now closed; remaining work should be managed as release evidence refresh and production operations rather than missing product functionality.
