# Public claim register

| Metadata | Value |
|---|---|
| Register owner | Vidhi Sharma |
| Public-surface collaborator | Ravi |
| Governance reviewer | Binod |
| Jira issue | ACL-8 |
| Baseline date | 2026-07-13 |
| Review cycle | Quarterly and before every public release or material claim change |

This register controls market-facing GDPR and SOC language. A claim is usable only when
its approval state is **Approved** or its stated condition has been satisfied and
recorded. Product features alone do not establish organizational compliance.

## Claim maturity levels

| Level | Meaning | Minimum evidence |
|---|---|---|
| Built-in | A technical capability exists in the product and has a traceable implementation and test path. | Source path, test or verification output, configuration assumptions, and responsible owner. |
| Audit-ready | A defined environment and period have complete, reviewed operating evidence for the scoped controls. | Immutable CI and operating records, control mapping, gap disposition, approval, and rollback evidence. |
| Report-ready | A scoped evidence package has been reviewed and is suitable to provide to an authorized assessor; no report or opinion is implied. | Audit-ready package, management assertions, scope and period, reviewer approval, and assessor-requested materials. |
| Externally attested | An independent authorized party has issued a current report, opinion, or other formal attestation for a defined scope and period. | Verified final report, issuer, covered entity, scope, period, exceptions, and approved publication language. |

## Registered claims

| ID | Proposed public wording | Level | Approval | Required evidence or permitted qualification | Owner |
|---|---|---|---|---|---|
| CLM-001 | “AuthClaw includes technical controls that support GDPR obligations and SOC 2 readiness.” | Built-in | Approved | Link `docs/COMPLIANCE_BOUNDARY.md`; retain the shared-responsibility qualification. | Vidhi / Ravi |
| CLM-002 | “AuthClaw can detect and redact configured sensitive-data patterns before model-provider egress.” | Built-in | Conditional | Name the enabled policy scope; preserve redaction and gateway test evidence; do not imply perfect detection. | Vidhi / Kunal |
| CLM-003 | “AuthClaw generates tamper-evident audit records and signed evidence exports.” | Built-in | Conditional | Production signing, storage, hash-chain verification, and tenant scope must be demonstrated for the referenced environment. | Kunal |
| CLM-004 | “AuthClaw automates control-to-evidence mapping and readiness scoring.” | Built-in | Approved | Describe scores as evidence-supported readiness indicators, not legal conclusions or auditor opinions. | Vidhi / Ravi |
| CLM-005 | “This AuthClaw release is audit-ready.” | Audit-ready | Conditional | The real release evidence package must pass the documented gates and receive owner approval; example evidence is insufficient. | Kunal / Binod |
| CLM-006 | “AuthClaw can produce material for a SOC 2 examination or SOC 3 report.” | Report-ready | Conditional | State that an independent CPA firm determines examination results and report issuance. | Binod / Ravi |
| CLM-007 | “AuthClaw is SOC 2 Type II certified.” | Externally attested | Prohibited | SOC 2 is an examination/report, not a product certification; no verified report is present. | Binod |
| CLM-008 | “AuthClaw has completed a SOC 2 Type II examination.” | Externally attested | Prohibited | May change only after verification of the final CPA report, entity, scope, period, and approved wording. | Binod |
| CLM-009 | “AuthClaw is SOC 3 certified.” | Externally attested | Prohibited | SOC 3 is a report, not a certification; no verified SOC 3 report is present. | Binod |
| CLM-010 | “AuthClaw is GDPR compliant” or “guarantees GDPR compliance.” | Report-ready | Prohibited | Replace with CLM-001 and name the supported control or workflow; organizational legal compliance cannot be guaranteed by the product. | Binod / Ravi |
| CLM-011 | “AuthClaw has passed an external penetration test.” | Externally attested | Prohibited | A real, current vendor report and retest must be verified. `compliance_hardening_evidence.example.json` is a template, not proof. | Kunal / Binod |
| CLM-012 | “AuthClaw has zero vulnerabilities” or “is completely secure.” | Audit-ready | Prohibited | Use time-bound, severity-specific scan results with scope and date; never guarantee absence of vulnerabilities. | Kunal / Ravi |
| CLM-013 | “AuthClaw guarantees audit readiness.” | Audit-ready | Prohibited | Audit readiness is release-, scope-, period-, and evidence-dependent. Use CLM-005 only after its conditions are satisfied. | Binod / Ravi |

## Publication workflow

1. Ravi maps proposed website, console, sales, or release wording to a registered claim ID.
2. The technical owner links current evidence and records environment, scope, and date.
3. Binod reviews conditional, report-ready, externally attested, and prohibited-language changes.
4. The change is merged only after claim wording and evidence links agree with the control matrix.
5. Expired, superseded, or unsupported claims are removed immediately and reviewed after incidents or material control failures.

## Current external-attestation position

As of 2026-07-13, this repository contains no verified final SOC 2 Type II report, SOC 3
report, or external penetration-test report. No externally attested claim in this
register is approved.

## Authoritative terminology references

- [AICPA SOC 2 examination guidance](https://www.aicpa-cima.com/cpe-learning/publication/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security-availability-processing-integrity-confidentiality-or-privacy-OPL)
- [AICPA SOC 3 general-use report overview](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-3)
- [Official GDPR text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
