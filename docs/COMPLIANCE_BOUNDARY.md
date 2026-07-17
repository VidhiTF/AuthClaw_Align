# Compliance and security boundary

AuthClaw implements controls that support GDPR obligations and SOC 2 readiness across
security, availability, confidentiality, processing integrity and privacy. It can generate
evidence usable during a SOC 2 Type II examination and in preparing a SOC 3 report.

It must not be marketed as "SOC 2 Type II certified" or "SOC 3 certified." SOC reports
are issued by an independent CPA firm after examination; Type II also evaluates control
operation over a defined period.

## Trust Summary

The Trust Summary groups existing control scores for presentation. **Verified** represents
controls currently meeting AuthClaw's automated framework-scoring criteria. **In Progress**
represents controls with the existing `partial` status, and **Planned** represents controls
with the existing `non_compliant` status.

These labels do not change the underlying control status or evidence lifecycle. The Trust
Summary is not an independent SOC 2 Type II report or a SOC 3 report, and it does not imply
certification. Existing control details, evidence signals, gaps and traceability remain the
supporting readiness information.

## Built-in technical controls

- Tenant-scoped RBAC, API keys and configurable OIDC SSO.
- TLS enforcement hooks and envelope encryption/KMS integrations.
- PII detection, tokenization/redaction and policy-controlled model egress.
- HITL approval for high-risk operations with MFA support.
- Hash-chained audit records, signed exports and evidence collection.
- Retention, deletion and tenant-isolation foundations for GDPR workflows.
- CI gates for secrets, dependencies, SAST, infrastructure and tests.

## Shared responsibility

Production compliance also depends on cloud configuration, corporate policies, staff
training, vendor agreements, legal basis/consent records, incident response, backup tests,
access reviews, change management and independent audit evidence. Product features alone
cannot establish organizational compliance.

## Governance artifacts

- [`compliance/GDPR_SOC2_CONTROL_MATRIX.md`](compliance/GDPR_SOC2_CONTROL_MATRIX.md)
  maps the P0 launch controls to implementation and operational owners, evidence sources,
  collection frequencies and open gaps.
- [`compliance/PUBLIC_CLAIM_REGISTER.md`](compliance/PUBLIC_CLAIM_REGISTER.md) defines
  built-in, audit-ready, report-ready and externally attested language and records which
  public claims are approved, conditional or prohibited.
