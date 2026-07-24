# ACL-35 public claims and legal-notice approval record

| Metadata | Value |
|---|---|
| Owner | Vidhi Sharma |
| Jira issue | ACL-35 |
| Branch | `feat/marketing/ACL-35-public-claims-notices` |
| Baseline date | 2026-07-20 |
| Release scope | Controlled beta |
| Status | Pending authorized approval |

## Publication decision

AuthClaw public surfaces may describe implemented technical controls and readiness
capabilities only within the qualifications in the public claim register. This change
does not assert certification, an issued SOC report, legal compliance, a universal
performance result, or a public availability commitment.

## Material claim review

| Topic | Approved public position | Register or evidence | Approval state |
|---|---|---|---|
| GDPR and SOC | Technical controls support GDPR obligations and SOC 2 readiness; organizational compliance remains a shared responsibility. | CLM-001; `docs/COMPLIANCE_BOUNDARY.md` | Approved wording |
| Sensitive-data controls | Configured policies can detect and redact supported patterns before model-provider egress; perfect detection is not claimed. | CLM-002; gateway and agent redaction tests | Conditional on deployed policy scope |
| Audit evidence | Audit records are tamper-evident and evidence exports can be signed when the production signing configuration is enabled. | CLM-003; audit-store tests | Conditional on environment evidence |
| Readiness scoring | Scores are evidence-supported readiness indicators, not legal conclusions or auditor opinions. | CLM-004 | Approved wording |
| SOC reports and certification | No verified SOC 2 Type II report, SOC 3 report, certification, or external penetration-test report is represented as available. | CLM-007–CLM-011 | Prohibited claims removed |
| Encryption and isolation | Capabilities are described as configuration- and environment-dependent controls, without guaranteeing complete security. | `docs/COMPLIANCE_BOUNDARY.md`; architecture ADRs | Controlled-beta qualification |
| Performance and uptime | Performance is described as environment-specific; availability commitments require a signed plan or agreement. | CI benchmark evidence; Terms of Use | No universal promise |
| Human approval | High-risk actions require approval when the applicable workflow and policy are configured. | ACL-18 tests and evidence | Scope-qualified |
| Privacy and legal notices | Privacy, Terms, cookie/storage, subprocessor, DPA, and security-contact paths are published and versioned. | Public legal routes; onboarding acceptance record | Engineering complete |

## Legal-notice evidence

- Terms and Privacy Notice versions are recorded during self-service onboarding.
- The Privacy Notice identifies controlled-beta account, tenant, usage, customer-content,
  and support data and explains purpose, retention, disclosure, and rights paths.
- Cookie/storage notice distinguishes essential session and OIDC state from optional
  analytics, which is not enabled by default.
- Subprocessor categories and a DPA request path are public.
- Security concerns can be reported to `security@authclaw.ai`.
- Operational owners must verify that all published mailboxes are monitored before
  production deployment.

## Automated prevention

`npm run test:claims` scans canonical and legacy deployable marketing sources for
prohibited certification, legal-guarantee, audit, immutability, absolute-coverage, and
unsupported SLA wording. The console CI job runs this check before build.

## Required authorization before deployment

| Reviewer | Decision | Date | Notes |
|---|---|---|---|
| Vidhi Sharma | Pending | — | Confirm implementation and evidence links. |
| Binod | Pending | — | Authorized approval required for material public claims and legal notices. |

This record documents required sign-off; it does not assign work or represent approval
until the named reviewer records a decision.

## Rollback

If wording or evidence becomes inaccurate, remove the affected claim from public routes,
restore the last approved notice version, and preserve the prior version and acceptance
records for audit traceability.
