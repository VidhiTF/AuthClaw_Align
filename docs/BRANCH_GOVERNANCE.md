# Branch governance

## Ownership and review roles

Review routing depends on changed components and risk boundaries, not authors.
[CODEOWNERS](../.github/CODEOWNERS) is the authoritative login assignment map.
Current primary/deputy assignments are encoded there; this table defines roles.

| Role | Boundary | Responsibility |
| --- | --- | --- |
| Platform/security | backend, gateway, audit, SDK, infrastructure, operational scripts | Runtime contracts, tenant/auth boundaries, data and transport safety |
| Agent | services/agent | Agent runtime, RAG, model and tool integration |
| Console/API consumer | console | User experience and consumed API compatibility |
| Governance custodians | repository guidance, CI, ownership, activation | Policy integrity, release controls and ownership changes |

Each boundary has a primary and deputy so its author cannot self-approve. Require
review by the primary when independent; otherwise use the designated deputy.
Cross-component changes need each affected role, API/schema changes need the
consumer role, and security/tenant/auth changes need the security role. Record the
roles and acceptance evidence in the PR. Governance custodians review CI/release
and policy changes. Two distinct non-author approvals are mandatory.

This is a user-owned repository. GitHub organization teams cannot be assigned
here. Use the path-specific primary/deputy logins in CODEOWNERS; after an approved
organization transfer, substitute real teams with repository access. Update role
assignments through reviewed policy changes when membership changes. Native
CODEOWNERS is supplemented by the policy verifier: two current-head approvals and
the primary for every changed path, or a deputy if the primary authored the PR.
The verifier reads ownership from the immutable PR base (except the one-time T01
bootstrap). Renames check both old and new paths. Current supported CODEOWNERS
syntax is the default wildcard plus rooted literal files/directories; other
syntax fails closed until the verifier supports it. Cross-cutting security and
consumer-contract sign-off must also be recorded explicitly.

## Required GitHub rules for master

[branch-protection-master.json](../.github/branch-protection-master.json) requires:

- Two approving reviews, CODEOWNER review, stale-approval dismissal, and approval
  of the latest push by someone other than the pusher.
- Strict `ACL-14 Required Checks` before merge, with the branch up to date.
- Enforcement for administrators, no review bypass lists, resolved conversations,
  linear history, and no force pushes or deletions.

The checked-in file is desired configuration, not proof of live settings. The
administrator must inspect existing protection/rulesets, preserve any additional
restrictions, apply the reviewed configuration, and retain read-back evidence.
Signed commits remain required where supported by the repository configuration.

## T01 enforcement bootstrap

T01 remains blocked until the administrator completes this setup. The preparing
account KunalTF has push access but no admin access; live enforcement has not been
changed by this PR. Do not merge based solely on this file or a green old CI run.

1. Inspect live protection and rulesets with an administrator account. Apply the
   reviewed two-approval payload while preserving any stronger existing settings:

   ```powershell
   gh api repos/VidhiTF/AuthClaw_Align/branches/master/protection
   gh api repos/VidhiTF/AuthClaw_Align/rulesets
   gh api --method PUT repos/VidhiTF/AuthClaw_Align/branches/master/protection --input .github/branch-protection-master.json
   gh api repos/VidhiTF/AuthClaw_Align/branches/master/protection
   ```

   Also install the additive, CI-readable
   [review ruleset](../.github/master-review-ruleset.json). If its name already
   exists, update that resolved ID with PUT instead of creating a duplicate.
   Keep the existing deletion/force-push ruleset and stronger controls intact:

   ```powershell
   gh api --method POST repos/VidhiTF/AuthClaw_Align/rulesets --input .github/master-review-ruleset.json
   gh api repos/VidhiTF/AuthClaw_Align/rules/branches/master
   ```

   CI queries this effective-rules endpoint, validates one complete enforcing
   ruleset, and uses GraphQL `RepositoryRuleset.bypassActors.totalCount` to require
   no bypasses. Ordinary CI does not receive an admin token. Missing permissions
   or incomplete controls fail closed. Classic protection alone is not sufficient
   for this read-only machine gate; keep both checked-in configurations aligned.

2. Verify the read-back: two approvals, CODEOWNER review, stale dismissal, latest
   push approval, strict required CI, administrator enforcement, and no bypasses.
   Retain the output and a PR showing that one approval cannot merge. Do not
   weaken existing required checks to get T01 through.
3. Obtain both stakeholders' final-head approvals as specified in
   [t01-activation.json](../.github/t01-activation.json). Rerun the latest PR CI
   if necessary; review submission, editing, and dismissal also rerun CI. Pending
   approvals intentionally fail Repository Policy. A new push needs new approvals.
   For material growth, the component owners also include the explicit exception
   marker from `python scripts/repository_policy.py --pr-evidence 52` in their
   approving reviews. See CONTRIBUTING.md for the threshold and digest contract.
4. Confirm required checks and stakeholder evidence, then merge T01. CODEOWNERS
   is read from the base branch, so its new ownership mapping takes effect after
   this merge. The T01 verifier supplies the specific bootstrap stakeholder gate.
5. The manifest record owner runs
   `python scripts/repository_policy.py --verify-github` and retains its JSON
   output (reviewed commit, merged SHA, UTC effective date). The reviewed manifest
   plus GitHub reviews/merge, not a PR-body edit, determine activation. Subsequent
   CI re-verifies merge ancestry and stakeholder approvals; missing evidence fails.

Preparation may proceed locally while T01 is pending, but downstream PRs cannot
pass the activation check until it is merged. Tests validate the policy and gate;
only administrator read-back and merge-blocking evidence prove live enforcement.

## GitHub Actions execution policy

- `.github/workflows/ci.yml` runs on PRs targeting master, their review events,
  master pushes, a weekly
  schedule, and manual dispatch (with full-regression and ARM64 inputs).
- PRs run change-selected component suites. Change detection and Repository Policy
  always run. `ACL-14 Required Checks` rejects failed, missing, or skipped selected
  jobs; only unselected jobs may skip. Documentation-only changes can legitimately
  skip component suites while policy checks run.
  PR-description edits rerun the evidence gate. Policy also runs the existing
  Tokei line-budget checker and verifies live enforcement before activation.
- Master pushes normally run policy and selected smoke/contract checks. Scheduled
  and manual full regression select the established broader suites. ARM64 image
  checks require the relevant input/configuration and eligible event.
- Release images require an eligible master push and controlled-beta enablement.
  Deployment is triggered by successful source CI only when its event was a master
  push and all seven release images and the release completion gate succeeded.
  PR, scheduled, and manual runs do not deploy.

Report selected jobs and actual results. A green aggregate with legitimate skips
is not proof that every component suite ran. Use local tests before review and
retain separate release/deployment evidence; skipped deployment is not live proof.

## Branch workflow

`master` is the release integration branch. Existing development branches are
`dev/kunal` (platform), `dev/vidhi` (agent), and `dev/ravi` (console). Contributors
use `feat|fix|chore/<area>/<task>-slug` branches and review changes through their
assigned development branch or an explicitly authorized direct PR to master.
Development branches require reviewed PRs and no force pushes/deletion; this
workflow's pre-merge CI target is master. Never claim dev-branch PR CI ran when the
trigger excludes it. Review routing follows changed boundaries on every branch.
