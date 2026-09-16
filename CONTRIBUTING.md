# Contributing to AuthClaw

These T01 engineering rules apply to all human and AI-assisted changes. Read
[AGENTS.md](AGENTS.md) for the canonical remote, semantic duplicate protocol, and
line budgets, and [branch governance](docs/BRANCH_GOVERNANCE.md) for ownership and
the existing review and integration workflow. Complete the
[pull request template](.github/pull_request_template.md) for every change.

## T01 prerequisite and approval record

T01 must be approved and merged into `master` before implementation tasks
T02–T21 begin. Read-only verification and documentation preparation may proceed.
An edited file, an AI review, or an open PR does not satisfy this gate.

The version-controlled [activation manifest](.github/t01-activation.json) pins
the T01 PR, repository, two one-time stakeholder approvers, and record owner.
`python scripts/repository_policy.py --verify-github` checks GitHub review and
merge evidence: both stakeholders must approve the final head, the PR must be
merged, and its merge commit must be an ancestor of `master`. Its output records
the verified SHA and UTC effective date from GitHub's merge event. The manifest
and authenticated GitHub evidence are authoritative, never a mutable PR body.
The record owner retains the output with task evidence after merge; a new
timestamp or assertion in a task description cannot activate T01.

For T01's own PR, CI requires both final-head approvals but permits the merge to
remain pending. Other PRs fail this gate until T01 is merged. Preparation can
continue locally before activation. Missing evidence or API failures fail closed.
PR review submission, editing, and dismissal rerun CI to refresh the gate, using
the same component selection as PR updates. If a run needs a manual retry, rerun
the latest PR CI; do not push an empty commit because it invalidates approvals.

T01 must not merge until an administrator applies and verifies the checked-in
two-approval protection configuration. See the
[activation runbook](docs/BRANCH_GOVERNANCE.md#t01-enforcement-bootstrap).
This setup is part of T01, not deferred to T19. Activation is pending until the
live settings, stakeholder approvals, required checks, and merge are evidenced.

## Engineering rules

1. **Modify existing code first.** Before creating code, search for an existing
   implementation, extension point, configuration, or test seam. Record the paths
   and alternatives considered in the PR, including searches that found no match.
2. **Restrict new production lines.** Before adding them, document why existing
   code cannot safely be changed, reused, or simplified. Put that justification
   in the PR; a lower net line count does not exempt newly added production code.
3. **Prefer deletion and consolidation.** When behavior is equivalent, remove
   obsolete branches, aliases, wrappers, and duplicated helpers rather than add
   another path. Verify callers and compatibility before deleting anything.
4. **Preserve behavior deliberately.** Add or update characterization tests before
   risky refactoring. State the intended contract and show before/after evidence
   that it remains stable. Explicitly identify intentional behavior changes.
5. **Require evidence before remediation.** Confirm the active runtime path and
   reproduce the behavior where practical. Record source IDs, corrected
   disposition, and evidence. Classify work as a confirmed defect/security risk,
   maintainability/operability debt, advisory/roadmap, or SDLC improvement. Closed
   or disproved claims require new evidence before reopening; a review severity
   label alone is insufficient. If reproduction is impractical, explain why and
   supply direct evidence and its limits.
6. **Follow the semantic duplicate protocol.** The full protocol in
   [AGENTS.md](AGENTS.md#refactoring-protocol-semantic-duplicates) is mandatory:
   Python `ast` or Go AST/parser analysis, cluster proposal and approval before
   merging, normalization, tests at original and destination locations before
   removal, and pointer stability with idempotent, side-effect-free shared logic.
   Consolidation must preserve caller-visible behavior; if those properties
   cannot be maintained, do not merge the cluster.
7. **Keep PRs reviewable.** Submit one coherent change, state acceptance criteria,
   customer impact, release-note disposition, schema and rolling-deployment
   compatibility, migrations, security implications, risk, and concrete rollback
   steps. Avoid unrelated cleanup.
8. **Reject insecure defaults.** Production-like modes, including shared test,
   staging, and production, must fail closed for missing or invalid secrets,
   transport security, debugging, and external service configuration or failures.
   Do not silently downgrade to insecure transports, debug exposure, development
   credentials, or permissive service fallbacks. Verify negative cases relevant
   to the change; local development exceptions must be explicit and isolated.
9. **Respect line budgets.** Use the limits in
   [AGENTS.md](AGENTS.md#line-budgets). Report added/deleted production lines and
   affected budget usage with the counting method. Explain any material increase
   and identify existing code considered first for every change adding lines.
   Do not silently exceed a budget; any budget change needs an explicit policy
   change and the required repository-policy review.
10. **Close with evidence and independent review.** Supply test output or
    reproducible operational proof mapped to acceptance criteria. Record failures,
    skipped checks, and limitations honestly. Independent owners of affected
    components and risk boundaries verify acceptance as described below.
    Self-review or AI assistance cannot replace human approval.

### Tenant-sensitive evidence

For affected tenant data paths, identify the tenant key and its trusted source,
application authorization/scoping, and database enforcement (including RLS,
restricted roles, and transaction tenant context where applicable). Supply denied
cross-tenant reads, inserts, updates, exports, and applicable similarity-search
evidence. Verify the layers independently; a privileged database test role must
not mask missing tenant enforcement. Document any absent layer and the actual
alternative control without claiming coverage. N/A requires a reason tied to the
changed paths and operations. A checked box is not evidence.

## Cross-review and completion

Review follows changed paths and risk boundaries, not the author's identity.
Require two independent human approvals, including a component owner or designated
deputy for each affected boundary. API/schema changes also require a consuming
component's owner; security, tenant, or authentication changes require the security
role; CI, release, ownership, and policy changes require governance custodians.
The author cannot satisfy a review role. Record the roles and evidence reviewed.

[CODEOWNERS](.github/CODEOWNERS) holds current role assignments; the role model and
primary/deputy responsibilities are in [branch governance](docs/BRANCH_GOVERNANCE.md).
This user-owned repository cannot use organization teams. After a transfer to an
organization, replace login assignments with real teams having repository access.
Membership changes update assignments, not these engineering rules. Never invent
team handles. The policy verifier requires two current-head approvals and the
primary owner for every changed path (a deputy when the primary is the author).
It uses base-branch ownership for subsequent PRs so a PR cannot reassign its own
reviewers. Cross-cutting risk and consumer-contract acceptance remain explicit
review obligations beyond path matching.

Reviewers identify the final commit and independently check acceptance evidence.
Material edits invalidate approvals. Record the merged change and evidence before
closing work. PR CI runs before merge and is required through `ACL-14 Required
Checks`. Change detection selects component suites; an unselected suite may skip,
but a selected missing/skipped/failed suite fails the aggregate gate. Report actual
coverage rather than calling a skip a pass. Master pushes run policy and selected
smoke checks; scheduled/manual full regression and enabled release-image/deployment
validation are separate. See branch governance for the exact event model.

## T01 policy check

The implementer supplies this checklist; the manifest's stakeholders verify it.
The existing Repository Policy job runs `scripts.test_repository_policy` and the
live activation verifier. Tests supplement, rather than replace, human acceptance.

- [ ] All ten rules are present here and apply to human and AI-assisted changes.
- [ ] AGENTS.md and the PR template link to this guidance.
- [ ] The template explicitly requests existing-code reuse, new-line justification,
      test evidence, risk, rollback, and reviewer sign-off.
- [ ] The existing semantic duplicate protocol, remote rule, and line budgets
      remain intact and the Markdown links resolve.
- [ ] The T01 prerequisite and named approvals are explicit; no implementation
      task is bundled with T01.
- [ ] Both stakeholder approvals cover the final head and live two-approval
      protection is verified by an administrator before merge.
- [ ] After merge, the record owner retains verifier output containing the merged
      SHA and effective date; downstream CI verifies the same GitHub evidence.
