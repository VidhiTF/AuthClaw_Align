# CI execution policy

`scripts/ci_plan.py` selects jobs; the required aggregate verifies that every
selected job actually succeeded. Unexpected failures/cancellations cannot pass
as intentional skips.

CodeQL was removed from this workflow at the user's request on 2026-09-04,
including scheduled/manual runs and the aggregate's dependencies. Its source
analysis coverage is no longer provided by CI. Gitleaks, Trivy, component tests
and fail-closed required-job validation remain enabled. Historical CodeQL evidence
is not evidence of a current scan. Repository-level default scanning and branch
protection settings are not changed by this workflow edit.

| Trigger | Work |
| --- | --- |
| Pull request | Full affected component suites; shared/security contracts conservatively include consumers |
| Master push | Lightweight smoke for affected executable/configuration changes |
| Documentation-only update | Planner/policy and aggregate checks; no component or image rebuild |
| Weekly schedule | All established CI suites, regardless of changed paths |
| Manual dispatch | Full regression by default; optional lightweight mode |
| Explicit ARM64 opt-in | Standalone ARM64 only on eligible master push/manual dispatch, never every PR |

Unknown executable/configuration paths fan out conservatively. Renames and
deletions are included. Tests-only changes select their owning component without
automatically selecting unrelated consumers. Workflow/planner changes receive
broad coverage. "Full regression" means the suites configured in this workflow,
not every test file anywhere in the repository.

Release images run only for enabled master pushes with affected components;
existing release-image architecture coverage is retained. Deployment additionally
requires a successful master **push** source run, all seven image jobs, release
completion and the required aggregate. Scheduled/manual/docs-only runs do not
deploy merely because CI is green.

Branch protection is unchanged, as requested. Therefore this change does not
enforce that direct pushes previously passed PR checks. Teams must preserve the
reviewed-PR merge process through their existing repository governance.
