# AuthClaw Compliance Hardening Runbook

This runbook closes the Phase 4 hardening evidence loop. A release is audit-ready only after `scripts/compliance_hardening_evidence.py` accepts the release evidence JSON.

## Release Gate

```bash
python scripts/compliance_hardening_evidence.py infra/security/compliance_hardening_evidence.example.json
```

For production, replace the example with the release artifact captured from the real CI run, external pentest report, red-team run, SOC 2 evidence export, and release approval.

Local no-credential proof uses the separate manifest below and does not claim external pentest completion, SOC 2 attestation, or live cloud behavior:

```bash
python scripts/no_credential_proof.py infra/security/no_credential_proof.local.json
```

## Incident Response

1. Open a security incident with severity, affected tenants, first-seen time, and suspected data classes.
2. Preserve audit exports before containment changes.
3. Rotate exposed credentials and tenant-scoped API keys.
4. Record containment, eradication, recovery, and customer notification decisions.
5. Link the incident record to SOC 2 CC7.2 and CC7.3 evidence.

## Vulnerability Management

1. Every release must pass CodeQL, dependency audits, secret scan, IaC scan, and container scan.
2. Critical, high, and medium external pentest findings must be closed and retested before release approval.
3. Findings stay open until the fix commit, retest evidence, and owner approval are attached.
4. Link the closed finding set to SOC 2 CC7.1 and CC7.3 evidence.

## Access Review

1. Review production IAM, GitHub admin, cloud connector, and database access before release.
2. Remove stale users, stale tokens, and unused service principals.
3. Record reviewer, timestamp, removed grants, and exception expiry.
4. Link the review to SOC 2 CC6.1 evidence.

## Backup And Restore

1. Confirm latest PostgreSQL backup and cross-region replica status.
2. Run the HA failover evidence gate for material infrastructure changes.
3. Verify audit-chain export after restore or failover tests.
4. Link backup, restore, and HA evidence to SOC 2 A1.2.

## Key Rotation

1. Rotate exposed or scheduled JWT, session, envelope, provider, and cloud connector secrets.
2. Verify old keys are revoked or past grace period.
3. Run login, gateway, audit export, and connector smoke checks after rotation.
4. Link the rotation record to SOC 2 CC6.1 and CC6.6.

### JWT and session secrets

- JWT signing currently uses one active secret and has no multi-key compatibility.
  Rotating it invalidates existing JWTs. Deploy the replacement through the existing
  secret-injection process, then verify new login and authenticated API requests; record
  the expected rejection of tokens signed with the previous secret.
- Session signing currently uses one active secret and has no multi-key compatibility.
  Rotating it invalidates existing sessions. Deploy the replacement through the existing
  secret-injection process, then verify that a new login creates a usable session and that
  sessions created with the previous secret are rejected.
- Do not claim seamless JWT or session-secret rotation. Record the deployment identifier,
  rotation time, smoke-check results and resulting authentication telemetry as release evidence.

### Certificate rotation

The controlled-beta ACM certificate is an external account-bootstrap input documented in
`infra/terraform/BETA_DEPLOYMENT.md`; this repository does not issue or renew it.

1. Confirm the replacement ACM certificate is issued in the deployment region, covers the
   configured beta hostname, and is valid before changing the deployment input.
2. Preserve the current certificate ARN for rollback, update `BETA_CERTIFICATE_ARN` through
   the existing controlled-beta configuration, and run the existing deployment workflow.
3. Verify the deployed hostname presents the replacement certificate and that the existing
   endpoint health checks succeed.
4. Record the workflow URL, certificate ARN, validation output and deployment artifact.
   This is staging or production evidence; repository validation alone is insufficient.

## Audit Export Verification

1. Generate a signed audit export from the console or backend audit endpoint.
2. Verify it with `backend/scripts/verify_audit_export.py`.
3. Confirm signature, payload digest, record count, and hash-chain verification all pass.
4. Preserve the verification output with release evidence.
5. Any tamper or chain failure blocks release until the audit store is repaired or the export is regenerated from verified records.

## Release Rollback

1. Record the release artifact, image tags, migration revision, and previous known-good versions.
2. Confirm rollback can restore console, backend, gateway, audit consumer, and database schema compatibility.
3. For migrations, document whether rollback is automatic, manual, or forward-fix only.
4. Run smoke checks for login, gateway proxy, evidence lookup, findings, and audit export after rollback.
5. Attach rollback notes to the audit-ready release checklist.

### Rotation rollback and verification

- **Certificate:** restore the preserved certificate ARN through the same controlled-beta
  configuration and deployment workflow. Existing sessions are not intentionally invalidated
  by certificate replacement. Verify the hostname presents the restored certificate and that
  endpoint health checks pass.
- **JWT secret:** restoring the previous secret permits only JWTs signed with that secret;
  JWTs issued under the replacement secret become invalid because only one active signing
  secret is supported. Require a fresh login and rerun authenticated API smoke checks.
- **Session secret:** restoring the previous secret invalidates sessions created with the
  replacement secret because only one active session secret is supported. Require a fresh
  login and verify new-session creation, logout and protected-route access.
- Preserve the original rotation record. Attach the rollback workflow URL, configuration
  version, certificate validation where applicable, smoke results, authentication telemetry
  and approval to the release evidence.

### F21 release-content rollback

1. Use the existing controlled-beta rollback to restore the previous known-good image
   digests; do not deploy untested content outside the release process.
2. If a public claim no longer matches its evidence, restore the last approved wording
   and claim-register mapping, then rerun `npm run test:claims` before release.
3. If supported configuration or limitation text is inaccurate, revert the affected
   documentation with the release commit while preserving prior acceptance evidence.
4. Rerun the release-candidate Playwright suite and documentation validation after the
   rollback. A failed browser, claim, or documentation gate blocks the replacement release.
5. Record the rollback commit, restored image digests, gate results, and approval in the
   existing release evidence; do not edit historical evidence to describe the new state.

## Red-Team Release Thresholds

- Critical failed probes: `0`
- High failed probes: `0`
- Maximum red-team risk score: `0`
- Minimum probe count: `4`

Any threshold breach blocks release until the policy, gateway behavior, or target response is fixed and retested.
