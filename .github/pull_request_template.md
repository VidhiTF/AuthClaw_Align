## Jira

- Issue: ACL-
- Action-plan task and source IDs (or N/A with reason):
- Corrected disposition and classification (defect/security risk, debt, advisory/
  roadmap, SDLC improvement, or closed/disproved):

## Engineering rules and prerequisite

Read [CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md).
Complete every field; use N/A with a reason where appropriate.

- T01 activation verifier output (manifest, approvals, merged SHA, UTC effective date):
- [ ] T01 is merged and effective before implementation, or this PR is T01,
      read-only verification, or documentation preparation (explain).

## Scope

- [ ] Change stays within the contributor's owned paths, or cross-owner review is attached.
- [ ] API/schema changes are documented.
- [ ] Tests cover the change.
- Intended behavior/acceptance criteria:
- Active runtime path and reproduction/direct evidence (or documentation scope):
- Why the corrected disposition warrants this change:
- [ ] This PR contains one coherent change without unrelated cleanup.

## Customer impact

- User-visible changes, affected customers, and operational/support impact:

## Release notes

- Release-note entry/link, or explicit no-note disposition with reason:

## Schema and rolling-deployment compatibility

- API/database/event schema compatibility, old/new producer and consumer behavior:
- Mixed-version rollout order, expand/contract migrations, and compatibility window:
- Migration steps and data backfill, or N/A tied to changed paths:

## Existing-code reuse

- Existing implementations, extension points, configuration, and test seams searched
  (paths and search results):
- What was modified, reused, simplified, consolidated, or deleted:

## New-line justification

- Why existing code cannot safely be changed, reused, or simplified to avoid new
  production lines (document before adding them; or state no new production lines):
- Added/deleted production lines, affected budget usage, and counting method:
- Existing code considered for any added lines; explanation of material increases:
- [ ] AGENTS.md line budgets are respected.
- Semantic duplicates: N/A with reason, or AST/cluster evidence, proposal approval,
  normalization, tests at both locations, and pointer/side-effect stability evidence:

## Security and compliance

- [ ] No secrets, personal data, tokens or keys were committed or logged.
- Security implications and affected trust boundaries:
- [ ] Audit/evidence behavior was considered.
- [ ] Migration and rollback steps are documented where applicable.
- Production-like fail-closed behavior and relevant negative-case evidence for
  secrets, transport security, debugging, and external services (or N/A with reason):

## Material line-growth exception

- Positive net growth in non-prose files, counted per file (code, tests and config):
- At 100 or more lines, explain the exception and rejected reuse/deletion options;
  below that threshold, state the count and why an exception is not required:
- Component owners must include the marker printed by
  `python scripts/repository_policy.py --pr-evidence <PR-number>` in their current-head
  approving review. The author cannot grant this exception; PR edits change its digest.

## Tenant isolation evidence

- Tenant key and trusted source; affected paths and operations:
- Application enforcement and database enforcement (RLS/role/transaction context):
- Negative cross-tenant reads, inserts, updates, exports, and applicable similarity
  searches: commands, test identities/roles, expected denial, and observed results:
- Layer-specific gaps/alternative controls; N/A only with path/operation-specific reason:

## Test evidence

- Commands, environment, reviewed commit, exit results, and output/evidence links:
- Before/after characterization evidence for risky refactoring (or N/A with reason):
- Acceptance criteria mapped to tests or reproducible operational proof:
- Failures, skipped checks, limitations, and reasons:

PR CI must pass before merge. Path-based skips are valid only for unselected
components; list the selection and actual coverage. Post-merge smoke, full
regression, and release/deployment results are separate evidence.

## Risk

- Affected contracts, compatibility, data, configuration, and operational risks:

## Rollback

- Concrete revert/recovery steps, triggers, and migration limitations:

## Reviewer sign-off

- Implementing engineer:
- Component-owner/deputy and risk-review roles for changed paths per CODEOWNERS:
- Reviewed commit and approval links (completed by the reviewers):
- Acceptance criteria independently verified and evidence checked:
- [ ] Required cross-review and owner approval are complete; no self-approval.

## T01 completion record (T01 only; otherwise N/A)

- Repository Policy tests and activation-verifier evidence:
- Both manifest stakeholder approval links and final reviewed commit:
- Administrator evidence of live two-approval and required-check enforcement:
- Record-owner retained verifier output: merged SHA/link and UTC effective date:

Leave pending evidence explicitly pending. The version-controlled activation
manifest and verified GitHub reviews/merge are authoritative, not this PR body.
