# GDPR and SOC 2 P0 control matrix

| Metadata | Value |
|---|---|
| Baseline owner | Vidhi Sharma |
| Collaborator | Ravi |
| Jira issue | ACL-8 |
| Branch | `chore/compliance/ACL-8-control-matrix` |
| Baseline date | 2026-07-13 |
| Review cycle | Quarterly and after material product, infrastructure, regulatory, or claim changes |

This matrix freezes the launch baseline for P0 GDPR and SOC 2 readiness controls. It is
an engineering and operational traceability record, not legal advice, a compliance
opinion, or evidence of an independent SOC examination.

## Status definitions

- **Built-in**: the repository contains an implemented technical control and testable evidence path.
- **Partial**: some implementation or evidence exists, but an operating record or control component is still required.
- **Operational**: the control depends primarily on a documented human or organizational process.
- **Gap**: required implementation or evidence has not yet been identified.

Product owners maintain the implementation. Operational owners collect and review the
evidence. Governance reviews must be completed by an authorized reviewer; this does not
assign a formal legal or audit title.

## P0 launch controls

| Framework control | Launch requirement | Product owner | Operational owner | Status | Evidence source | Collection frequency | Required review or gap |
|---|---|---|---|---|---|---|---|
| SOC 2 CC6.1 | Restrict and trace access to tenant configuration, policies, API keys, audit evidence, and administrative functions. | Kunal | Kunal | Built-in | `backend/app/services/compliance_scoring.py`; `infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#access-review`; access-review export | Continuous audit events; formal review quarterly and before release | Preserve reviewer, timestamp, removed grants, and exception expiry. |
| SOC 2 CC6.6 | Protect sensitive data in transit and before model-provider egress through TLS, policy enforcement, redaction, or tokenization. | Kunal / Vidhi | Kunal | Built-in | `gateway/`; `services/agent/redaction.py`; gateway contract tests; redaction evidence records | Per request; aggregate evidence per release | Production configuration must demonstrate TLS and active redaction policies. |
| SOC 2 CC7.1 | Detect vulnerabilities, secrets, and insecure infrastructure before release. | Kunal | Kunal | Built-in | `.github/workflows/ci.yml`; `infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#vulnerability-management`; [ACL-7 audit evidence](https://github.com/AgentsArchitects/AuthClaw/pull/7) | Every pull request and release | Store real CI outputs; local or example manifests are not release evidence. |
| SOC 2 CC7.2 | Monitor security-relevant activity and triage events. | Kunal | Kunal / Authorized governance reviewer | Built-in | `audit_consumer/`; `backend/app/services/compliance_scoring.py`; incident record and signed audit export | Continuous collection; daily alert review; per incident | Record severity, affected tenants, first-seen time, and decision trail. |
| SOC 2 CC7.3 | Track findings, approvals, remediation, retest, and closure. | Kunal | Kunal | Partial | findings and remediation records; signed audit export; `infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#vulnerability-management` | Per finding; weekly open-finding review; per release | Closure needs fix commit, retest evidence, and owner approval. |
| SOC 2 CC8.1 | Authorize, test, review, and trace production changes. | Kunal | Authorized release governance reviewer | Partial | `docs/BRANCH_GOVERNANCE.md`; `.github/workflows/ci.yml`; pull request, approval, CI, and rollback evidence | Every change and release | Required CI must cover the actual `dev/*` PR flow; ACL-42 tracks the current routing gap. |
| SOC 2 A1.2 | Maintain recoverability through backups, restore tests, failover, and rollback evidence. | Kunal | Kunal | Partial | `infra/terraform/DR_RUNBOOK.md`; `infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#backup-and-restore`; release rollback record | Backup checks daily; restore/failover quarterly and after material changes | Local proof excludes live failover timing; preserve production test evidence separately. |
| SOC 2 C1.1 | Protect confidential tenant and provider data through tenant isolation, encryption, and controlled disclosure. | Kunal / Vidhi | Kunal | Built-in | `docs/COMPLIANCE_BOUNDARY.md`; tenant-isolation evidence; encryption configuration; redaction evidence | Continuous controls; tenant-isolation test per release; key review quarterly | Production KMS, secret-manager, and tenant-isolation evidence is required. |
| GDPR Article 5 | Enforce data minimization, purpose-aware handling, and limited retention of personal data. | Vidhi | Authorized governance reviewer | Partial | `services/agent/redaction.py`; `services/agent/policies/`; policy evaluation and redaction evidence | Per request; policy review quarterly | Organizational purpose, lawful-basis, and retention decisions remain required. |
| GDPR Article 17 | Support erasure and retention workflows for personal data and derived records. | Kunal / Vidhi | Authorized governance reviewer | Partial | retention/deletion foundations referenced in `docs/COMPLIANCE_BOUNDARY.md`; deletion and audit records | Per request; monthly aging review | End-to-end deletion verification and exception handling are tracked under ACL-15. |
| GDPR Article 25 | Apply privacy by design and default before data reaches external model providers. | Vidhi / Kunal | Authorized governance reviewer | Built-in | `services/agent/redaction.py`; policy and gateway configuration; `backend/app/services/compliance_scoring.py` | Per request; design review for every material data-flow change | Preserve design decision, default configuration, and test evidence. |
| GDPR Article 30 | Maintain records of processing activity, systems, purposes, data classes, recipients, and retention. | Kunal / Vidhi | Authorized governance reviewer | Partial | hash-chained audit records; evidence exports; framework-tagged processing records | Continuous technical records; formal register review quarterly | Technical logs do not replace the organization-approved record of processing activities. |
| GDPR Article 32 | Protect processing through access control, confidentiality, integrity, resilience, and regular testing. | Kunal | Kunal / Authorized governance reviewer | Built-in | RBAC/API-key controls; signed audit export; CI security gates; backup/restore evidence | Continuous controls; every release; resilience test quarterly | Production operation must be shown with real environment evidence. |
| GDPR Articles 33-34 | Detect, assess, document, and escalate personal-data breaches and notification decisions. | Kunal | Authorized governance reviewer | Operational | `infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#incident-response`; incident record; notification decision record | Per incident; tabletop exercise at least annually | Legal notification thresholds and regulator/data-subject decisions require authorized human review. |
| GDPR Article 35 | Identify high-risk processing and preserve DPIA decisions and approvals. | Vidhi | Authorized governance reviewer | Partial | risk findings; approval records; `backend/app/services/compliance_scoring.py`; DPIA record | At design time and before material high-risk changes; annual review | A formal organization-approved DPIA template and sign-off record are still required. |

## Evidence rules

1. Evidence must identify the environment, tenant or scope, control, owner, collection time, and source.
2. Example and `.local.json` files demonstrate schema or local behavior only; they cannot prove production operation.
3. A release claim must reference immutable CI, audit, test, approval, and rollback artifacts for that release.
4. External pentest or SOC evidence is valid only when the referenced report exists and its issuer and scope are verified.
5. Open gaps remain visible until their owner records implementation, operating evidence, review, and closure.

## Approval

The baseline becomes frozen when Vidhi confirms technical traceability and Ravi and an
authorized governance reviewer review the affected product surfaces and public language.
Later changes require a pull request linked to a Jira issue and an entry in the public
claim register when the change affects market-facing language.

## Authoritative references

- [Regulation (EU) 2016/679 (GDPR)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [AICPA Trust Services Criteria resources](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)

The SOC mappings are an internal readiness baseline. The applicable criteria, system
description, scope and examination conclusions remain subject to the service
organization's management and its independent CPA practitioner.
