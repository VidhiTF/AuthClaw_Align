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
- Require the CI, dependency/secret scan, backend, gateway, agent and console checks.
- Do not allow branch deletion.

Developers branch from their assigned `dev/*` branch, use names such as
`ACL-12-short-description`, and open a PR back to their `dev/*` branch. The owner opens
or approves the release PR from `dev/*` to `master`.

`CODEOWNERS` supports review routing; it does not replace branch protection.
