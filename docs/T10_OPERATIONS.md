# T10: evidence-qualified compliance readiness

T10 scores weighted coverage of qualified, independently reviewed control evidence.
A fully qualified and implemented control earns 100; an unqualified control earns
zero. Product activity is separate, non-authoritative diagnostic information.
Activity volume, free-text matches,
closed finding statuses, missing data, and agent diagnostics cannot establish
compliance. These are engineering readiness indicators, not certifications.

## Deployment and configuration

1. Obtain required component, consumer, security and governance reviews, including
   the material-growth exception; run required CI against the reviewed commit.
2. Back up the database and test restore. Stop/drain old backend snapshot and MFA writers.
   Migration 050 changes the daily uniqueness key; old writers cannot overlap it.
3. Run the existing database bootstrap/migrator procedure through revision 051.
   Existing rows become `legacy_unversioned`; no evidence is reclassified.
   Migration 051 adds the per-user consumed TOTP timestep. Old MFA writers must
   not overlap the deployment because they do not enforce this replay state.
4. Deploy the new backend with `AUTHCLAW_EXPECTED_DB_REVISION=051`, then agent and
   console changes. The gateway accepts 050/051 for the cutover; backend requires
   051. Existing versionless console data displays an explicit legacy label.
5. Set `COMPLIANCE_ENVIRONMENT` to the deployment scope (`local`, `ci`, `staging`,
   `production`), matching `AUTHCLAW_ENV`. Default `unconfigured` blocks evidence
   qualification. Incorrect explicit scope fails configuration validation.
6. Optionally set `COMPLIANCE_OWNER_MAP_JSON`, for example
   `{"platform_security":["Security operations"],"governance":["Assurance team"]}`.
   Supported roles also include `agent_engineering` and `release_governance`.
   Missing mappings use neutral role labels; public shares always use those labels.
7. Verify private/public score parity, evidence gaps, calculation version, history
   boundaries, reviewed assessment intake, and same-version score-drop alerts.

The application must ship its Python source modules. Calculation identity hashes
normalized scoring/qualification definitions, catalog rules, and evidence-integrity
rules. Retain the deployed image/commit with assessment evidence. Rule changes
change the version and require new reviews; historical assessments and snapshots
remain available. Display-owner configuration does not change the calculation.
The review correction uses the `evidence-v3-` method prefix; prior assessments must
be reviewed again under the corrected method to qualify.

## Trusted assessment intake

Use authenticated backend user sessions with tenant owner/admin role. API keys
cannot propose, inspect or review assessments. An assessment requires a different
active owner/admin reviewer with MFA enabled and a fresh verified code. The
dedicated APIs reuse the existing approval, audit and evidence stores; there is no
new assessment administration UI in T10.

1. Collect immutable source evidence in the target tenant and environment through
   the existing evidence producer. The server stamps the configured environment
   before hashing. Legacy evidence without that stamp cannot qualify; collect
   fresh evidence rather than changing an old record.
2. Submit `POST /v1/compliance-scores/assessments` with an exact framework and
   catalog control, `environment`, 1–50 `evidence_ids`, timezone-aware `observed_at`,
   `period_start`, `period_end`, `outcomes`, and a 20–2000-character `review_note`.
   Every required outcome must be `pass`, `fail` or `unknown`. Source timestamps
   must lie in the covered period; the period ends by the observation, which must
   not be in the future. The current producer supports SOC2 only.
3. The reviewer retrieves
   `GET /v1/compliance-scores/assessments/{approval_id}` and inspects the linked
   evidence through existing tenant evidence access. Review every claimed outcome.
4. Within 30 minutes, the reviewer sends
   `POST /v1/compliance-scores/assessments/{approval_id}/review` containing
   `approve`, the retrieved `action_hash`, a meaningful `reason`, and `totp_code`.
   Approval atomically consumes the request once, records the MFA-backed review,
   and creates integrity-protected assessment evidence. Rejection records the
   decision without creating an assessment. A changed/expired request needs a new
   proposal; code and hash values must never be retained in support logs.

Successful MFA proofs are consumed per user across operations. Wait for a new
authenticator timestep before approving another request; previously consumed or
older timesteps cannot authorize a second successful action. Backup codes are
also single-use. Consumption and the protected action commit together; an action
that rolls back does not consume a proof. Database row locks serialize concurrent
attempts, independently of operation-specific Redis failure counters.

The JSON field names above describe the backend contract. Confirm the configured
API prefix from the deployment OpenAPI document when calling directly.

For resolved or false-positive findings, include `finding_dispositions` mapping
finding UUIDs to `RESOLVED` or `FALSE_POSITIVE`. Each must already have the matching
status, resolution timestamp and meaningful remediation summary. The reviewed
snapshot binds status, update/resolution times and summary. Later edits invalidate
it. Each control must cover all terminal findings in its framework; open findings
and accepted risks remain blockers. Existing finding scope is framework-wide, so
T10 deliberately does not infer narrower scope from prose matches.

## Qualification rules

`backend/app/services/control_assessments.py:CONTROL_REQUIREMENTS` is the exact
machine-readable policy. The conservative initial validity periods are:

| SOC2 control | Required outcomes | Maximum age |
| --- | --- | --- |
| CC6.1 | access_review; access_negative_tests | 90; 30 days |
| CC6.6 | transport_enforcement; redaction_enforcement | 30; 30 days |
| CC7.1 | release_security_scans; blocking_findings_disposition | 7; 7 days |
| CC7.2 | monitoring_operation; alert_triage_review | 1; 1 day |
| CC7.3 | finding_closure_retest; closure_owner_review | 7; 7 days |
| CC8.1 | change_authorization; release_checks_and_rollback | 7; 7 days |
| A1.2 | backup_operation; restore_failover_test | 1; 90 days |
| C1.1 | tenant_isolation; encryption_and_key_review | 30; 90 days |

Age starts at the earlier of period end and observation, so re-reviewing old
sources cannot renew their age. The latest reviewed observation wins; failure
wins ties over unknown and pass. Missing/corrupt latest evidence blocks qualification
instead of restoring an older pass. Missing, invalid, stale, failed, wrong-scope,
unreviewed-disposition and unsupported evidence produce explicit reason codes.

CC7.3, CC8.1 and A1.2 retain their existing `partial` implementation status. GDPR
and HIPAA have explicit requirements but no supported producer and retain incomplete
implementation mappings. They cannot become compliant/audit-ready in this release.
Do not change those flags merely to obtain a desired score. Requirement/validity
changes need governance review and a new version. The separate integer-tenant agent
engine remains diagnostic, non-authoritative and unassessed.

## History, incidents and rollback

Snapshots are unique by tenant, framework, UTC day and calculation version. Newer
same-day observations replace only their matching version. Stale writes cannot
overwrite newer ones. Drops compare the same version and environment, with snapshot
and notification committed together. A method change alone cannot trigger a drop.

On database/read failure, consumers show unavailable state and clear old green
results. Investigate the actual failure; do not substitute an affirmative score.
If rollout fails, stop assessment/snapshot writes and disable the affected score
surfaces while deploying a forward fix that preserves the evidence gate. Restore
from backup only under the established incident/recovery procedure. Do not deploy
the former count-only scorer as an emergency compliance assertion.

Migration downgrade refuses to discard consumed MFA replay state, versioned history or assessment audits.
Before any T10 data exists, downgrade to 049 is possible during a drained maintenance
window; after MFA consumption or intake, retain 051 and use a forward fix. Immutable T10 audit records
also intentionally prevent destructive updates/deletes; retention operations must
account for this. Do not disable triggers/RLS to make a rollback pass.
