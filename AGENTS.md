# AuthClaw agent guardrails

## Required engineering workflow

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for all human and AI-assisted changes.
It defines the T01 gate, engineering rules, evidence requirements, and ownership-based
cross-review. Read it before editing and use the existing
[PR template](.github/pull_request_template.md) when preparing a change.

- Before T02–T21 implementation, run the activation verifier described in
  CONTRIBUTING.md against the version-controlled `.github/t01-activation.json`.
  Require verified stakeholder approvals, merge ancestry, and effective date.
  Until then, limit work to T01, read-only verification, or documentation preparation.
- Search existing implementations, extension points, configuration, and test seams
  first. Document reuse decisions and why new production lines are unavoidable
  before adding them. Prefer safe deletion and consolidation.
- Confirm runtime evidence and the corrected issue disposition before remediation.
  Characterize behavior before risky refactoring and verify the intended contract.
- Keep one coherent scope, respect the budgets below, and document line growth,
  tests or operational proof, risk, and rollback in the PR.
- Require fail-closed production-like defaults for secrets, transport security,
  debugging, and external services, with relevant negative-case evidence.
- Follow the semantic duplicate protocol below before merging logical duplicates.
- Obtain independent component and risk-owner review per CONTRIBUTING.md and
  path-specific CODEOWNERS. For tenant-sensitive paths, identify the tenant key,
  application/database controls, and negative cross-tenant operation evidence.
  Never mark approvals, merge evidence, tests, or completion as satisfied without evidence.

## Repository Remote

Use the `align` remote (`https://github.com/VidhiTF/AuthClaw_Align.git`) for
AuthClaw Git fetch, pull, and authorized push operations. A request to pull
`master` means `align master`. Do not use another repository unless the user
explicitly requests it. This selects the repository, not a different login identity.

## Refactoring Protocol (Semantic Duplicates)

When a task involves "semantic duplicate" removal:

1. **AST Analysis**: For Python, use `ast` to compare function logical structures. For Go, use `ast/parser`.
2. **Cluster & Propose**: Do not refactor immediately. Print the identified cluster and ask: "I found this semantic match. Shall I merge into `backend/app/services/shared_utils.py`?"
3. **Normalization**: When merging, strip unique variable names and inline local configuration. Keep the "logical skeleton."
4. **Safety Check**: Before removing a duplicate, check if `pytest` or `go test` passes in both the original and destination files.
5. **Pointer Stability**: If merging shared logic, ensure the new utility function is idempotent and has no side effects.

## Line Budgets

| Path pattern | Max code lines |
| --- | ---: |
| `backend/app/*` | 10000 |
| `gateway/*` | 10000 |
| `audit_consumer/*` | 10000 |
| `console/src/*` | 10000 |
