# Branch governance

## Branches

| Branch | Contributor | Primary paths |
|---|---|---|
| `master` | AgentsArchitects (owner) | Release integration only |
| `dev/kunal` | Kunal | `gateway/**`, `backend/**`, `audit_consumer/**`, `infra/**`, `.github/**` |
| `dev/vidhi` | Vidhi Sharma | `services/agent/**` |
| `dev/ravi` | Ravi Dhakad | `console/**` |

## Required GitHub rules for `master`

- Restrict direct pushes and force pushes to the owner.
- Require pull requests and one approving owner review.
- Dismiss stale approvals after new commits.
- Require all conversations to be resolved.
- Require signed commits where the GitHub plan supports it.
- Run `ACL-14 Required Checks` after each push to `master`. It remains the stable
  aggregate for every build, test, dependency/secret scan, integration, compliance,
  and image-scan gate, but it is not a pre-merge required status check.
- Do not allow branch deletion.

## Required GitHub rules for `dev/*`

- Require feature branches to merge through pull requests.
- Require resolved conversations and owner review. GitHub Actions do not run on
  feature, development, or pull-request refs.
- Block force pushes and branch deletion.
- Keep the repository owner eligible to review and merge.

## GitHub Actions execution policy

- `.github/workflows/ci.yml` runs only for pushes to `master`.
- `.github/workflows/terraform.yml` runs only for Terraform-related pushes to
  `master`.
- `.github/workflows/deploy-controlled-beta.yml` runs only after the master CI
  workflow completes successfully.
- No workflow uses `pull_request`, `schedule`, or `workflow_dispatch` triggers.
- Workflow files are versioned source and therefore may be present in branches
  created from `master`; trigger filters, not file absence, guarantee that Actions
  execute only for `master`.

This is a post-merge validation model. Contributors must run the documented local
test suites before requesting review. A failed master CI run blocks release and
deployment, but it cannot block the merge that caused the failure.

Developers branch from their assigned `dev/*` branch and use
`feat|fix|chore/<area>/<JIRA-KEY>-slug`, for example
`feat/docs/ACL-12-aws-url-contract`. They open a PR back to their `dev/*` branch. The
owner opens or approves the release PR from `dev/*` to `master`.

`CODEOWNERS` supports review routing; it does not replace branch protection.
The API-ready protection payload and owner command are documented in
`infra/terraform/BETA_DEPLOYMENT.md`.
