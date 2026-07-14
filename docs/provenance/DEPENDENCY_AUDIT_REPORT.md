# Dependency Audit Report

This report documents the security audit of third-party dependencies used by the Python, Node.js, and Go components of AuthClaw.

## Audit Summary

- **Date**: 2026-07-13
- **Auditor**: Vidhi
- **Collaborator**: Kunal
- **Jira Issue**: ACL-7
- **Branch**: `chore/security/ACL-7-repository-audit`
- **Scanned Commit**: `781c7593a9e95d60f2ab13bee352e390c935c7a5`
- **Assistance**: The audit was performed by Vidhi Sharma; AI (Codex/ChatGPT) was used only for documentation and development assistance.
- **Verified result**: 2 Moderate Node.js findings; 0 High or Critical findings; no known Python or Go vulnerabilities found.

## Python Audit

- **Tool**: `pip-audit` 2.10.1 on Python 3.12.13
- **Command**:

  ```powershell
  python -m pip_audit `
    -r backend/requirements.txt `
    -r services/agent/requirements.txt `
    -r audit_consumer/requirements.txt `
    --strict
  ```

- **Result**: `No known vulnerabilities found`
- **Exit code**: 0
- **Scope**: All three checked-in Python requirement files and their resolved dependency graphs

## Node.js Audit

- **Tool**: npm 11.16.0
- **Commands**:

  ```powershell
  cd console
  npm audit --json
  npm audit --audit-level=high
  ```

- **Result**: 2 Moderate findings; 0 High; 0 Critical
- **CI-equivalent High/Critical gate exit code**: 0
- **Resolved dependency count reported by npm**: 845

| Dependency | Relationship | Severity | Advisory | Affected range | Fix guidance | Owner | Due date | Status |
|---|---|---|---|---|---|---|---|---|
| `postcss` | Transitive through `next` | Moderate | `GHSA-qx2v-qp2m-jg93` | `<8.5.10` | Requires a reviewed Next.js/PostCSS upgrade; `npm audit fix --force` proposes a breaking downgrade and must not be used blindly | Ravi | 2026-07-20 | Open |
| `next` | Direct | Moderate | Inherits the PostCSS advisory | `9.3.4-canary.0 - 16.3.0-canary.5` | Review a supported upgrade path with the console owner | Ravi | 2026-07-20 | Open |

## Go Audit

- **Tool**: `govulncheck` 1.6.0 with Go 1.26.5
- **Command**:

  ```powershell
  cd gateway
  govulncheck ./...
  ```

- **Result**: `No vulnerabilities found.`
- **Exit code**: 0
- **Scope**: Reachable vulnerabilities in the complete `gateway` package graph

## Trivy Filesystem, Secret, and IaC Audit

- **Tool**: Trivy 0.72.0
- **Scanners**: vulnerability, secret, and misconfiguration
- **Severity gate**: High and Critical; unfixed findings ignored to match CI
- **Result**: 0 High/Critical vulnerabilities in `console/package-lock.json` and `gateway/go.mod`; 0 reportable Dockerfile or Terraform misconfigurations; no secret findings
- **Exit code**: 0

## Remediation Plan

| Finding | Action | Owner | Target date | Release impact |
|---|---|---|---|---|
| `GHSA-qx2v-qp2m-jg93` through Next.js/PostCSS | Create or link a console remediation issue and test a supported dependency upgrade | Ravi | 2026-07-20 | Does not fail the current High/Critical CI gate; remains tracked technical debt |

## Completion Evidence

- Local Gitleaks, pip-audit, npm audit, govulncheck, and Trivy checks completed.
- The GitHub `dependency-and-secret-scan` job must pass on the PR before ACL-7 is closed.
- No dependency was changed as part of ACL-7; remediation belongs in a separately reviewed console change.
