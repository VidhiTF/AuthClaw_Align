# Secret Scanning Report

This report records the repository-wide secret scanning performed for ACL-7.

## Audit Overview

- **Scan Date**: 2026-07-13
- **Auditor**: Vidhi
- **Collaborator**: Kunal
- **Jira Issue**: ACL-7
- **Branch**: `chore/security/ACL-7-repository-audit`
- **Scanned Commit**: `781c7593a9e95d60f2ab13bee352e390c935c7a5`
- **Scope**: Entire AuthClaw working tree at `C:\Users\Dell\Desktop\AuthClaw_01`
- **Assistance**: The audit was performed by Vidhi Sharma; AI (Codex/ChatGPT) was used only for documentation and development assistance.
- **Result**: No secrets were detected by Gitleaks or Trivy.

## Verified Scans

### Gitleaks

- **Tool**: Gitleaks v8.30.1, installed as an isolated Go tool under the system temporary directory
- **Configuration**: `.gitleaks.toml`
- **Command**:

  ```powershell
  gitleaks detect --source . --no-git --redact --verbose --config .gitleaks.toml
  ```

- **Result**: `no leaks found`
- **Data scanned**: Approximately 7.75 MB
- **Exit code**: 0
- **Exclusions/allowlists**: Only the rules declared in `.gitleaks.toml`; the command used `--no-git`, matching the CI working-tree scan.

### Trivy filesystem scan

- **Tool**: Trivy v0.72.0 official Windows binary
- **Command**:

  ```powershell
  trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
  ```

- **Result**: No secret findings and no High or Critical vulnerability or misconfiguration findings
- **Exit code**: 0
- **Excluded generated/cache paths**: `.git`, `.terraform`, `node_modules`, `console/node_modules`, Python virtual environments, and pytest caches, matching the intent of the CI exclusions.

## Finding Classification

No potential production credential was reported by either verified scanner. Test fixtures and deliberately fake values covered by the repository's Gitleaks configuration were not treated as production credentials.

## Revocation and Rotation Status

- **Exposed production credentials**: None detected
- **Revocations completed**: None required
- **Rotations completed**: None required

## Reproducibility Notes

- The previous reference to `scratch/scan_secrets.py` was removed because that file does not exist in the repository.
- The official CI workflow independently repeats Gitleaks and Trivy scanning. The PR workflow result must be linked to ACL-7 before the issue is closed.
- Scan output must remain redacted in GitHub and Jira.
