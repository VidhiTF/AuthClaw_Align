## Jira

- Issue: ACL-
- Action-plan task and source IDs (or N/A with reason):
- Corrected disposition and classification (defect/security risk, debt, advisory/
  roadmap, SDLC improvement, or closed/disproved):

## Engineering rules and prerequisite

Read [CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md).
Complete every field; use N/A with a reason where appropriate.

- T01 PR/task record (for T02–T21: approvals, merged commit, effective date):
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
- [ ] Tenant isolation and authorization were tested.
- [ ] Audit/evidence behavior was considered.
- [ ] Migration and rollback steps are documented where applicable.
- Production-like fail-closed behavior and relevant negative-case evidence for
  secrets, transport security, debugging, and external services (or N/A with reason):

## Test evidence

- Commands, environment, reviewed commit, exit results, and output/evidence links:
- Before/after characterization evidence for risky refactoring (or N/A with reason):
- Acceptance criteria mapped to tests or reproducible operational proof:
- Failures, skipped checks, limitations, and reasons:

CI runs after merge on `master`; absent PR CI is not passing evidence.

## Risk

- Affected contracts, compatibility, data, configuration, and operational risks:

## Rollback

- Concrete revert/recovery steps, triggers, and migration limitations:

## Reviewer sign-off

- Implementing engineer:
- Independent engineer and required additional reviewers per CONTRIBUTING.md:
- Reviewed commit and approval links (completed by the reviewers):
- Acceptance criteria independently verified and evidence checked:
- [ ] Required cross-review and owner approval are complete; no self-approval.

## T01 completion record (T01 only; otherwise N/A)

- Manual T01 policy-check evidence from CONTRIBUTING.md:
- Ravi approval link and reviewed commit:
- Vidhi approval link and reviewed commit:
- Kunal post-merge record: full merged commit SHA/link and effective date/timezone:

Leave pending evidence explicitly pending. Kunal completes the post-merge record
in the T01 PR/task before implementation tasks begin.
