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

Kunal owns T01. Ravi and Vidhi must both approve the rule set. Kunal records the
following evidence in the T01 PR/task record after merge; link that completed
record in each implementation PR. Do not invent approvals or predate activation.

| Required evidence | Record to complete |
| --- | --- |
| T01 PR/task record | Pending: link |
| Ravi approval | Pending: review link and reviewed commit |
| Vidhi approval | Pending: review link and reviewed commit |
| Merged commit on `master` | Pending: full SHA and merge link, recorded by Kunal |
| Effective date | Pending: YYYY-MM-DD and timezone, recorded by Kunal |
| T01 policy check | Pending: checklist evidence below |

The pending entries describe the state when this guidance was prepared. The
linked, completed T01 PR/task record is the authoritative activation evidence;
later PRs must consult it rather than infer activation from this file's presence.

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
   document risk and concrete rollback steps, and avoid unrelated cleanup.
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
    skipped checks, and limitations honestly. One of the other two engineers must
    verify acceptance; follow the additional cross-review requirements below.
    Self-review or AI assistance cannot replace named engineer approval.

## Cross-review and completion

| Implementer | Required cross-review |
| --- | --- |
| Kunal | Ravi; also Vidhi for T01 and release-governance changes |
| Ravi | Vidhi; also Kunal for security-sensitive or repository-policy changes |
| Vidhi | Kunal; also Ravi for API-contract and configuration changes |

T01 specifically requires both Ravi and Vidhi regardless of who prepares the
files. Cross-owner review and repository-owner approval from existing branch
governance still apply. Reviewers identify the commit reviewed and independently
check the acceptance evidence before signing off. Material follow-up edits need
renewed review. Record the merged change and verification evidence in the task
record before closing it.

CI currently runs after merge on `master`, not on PRs. Run applicable documented
local checks before review; do not describe a skipped or absent workflow as a
passing test. Documentation-only changes may use link, content, and diff checks
with a stated reason that runtime tests are not applicable. These rules are a
review gate; this document does not configure GitHub branch protection. Settings
enforcement remains governed by the existing branch policy and T19.

## T01 policy check

The implementer supplies evidence for this checklist in the T01 PR; Ravi and
Vidhi verify it before approval. This is a manual policy check, not a new CI job.

- [ ] All ten rules are present here and apply to human and AI-assisted changes.
- [ ] AGENTS.md and the PR template link to this guidance.
- [ ] The template explicitly requests existing-code reuse, new-line justification,
      test evidence, risk, rollback, and reviewer sign-off.
- [ ] The existing semantic duplicate protocol, remote rule, and line budgets
      remain intact and the Markdown links resolve.
- [ ] The T01 prerequisite and named approvals are explicit; no implementation
      task is bundled with T01.
- [ ] Ravi and Vidhi approvals are linked to the reviewed rule set.
- [ ] After merge, Kunal records the full merged commit and effective date in the
      T01 PR/task record so implementation work can start.
