# License Inventory and Compliance Review

This report reviews direct and resolved transitive dependency license metadata for AuthClaw. It records technical license evidence and does not replace legal advice.

## Audit Metadata

- **Date**: 2026-07-13
- **Auditor**: Vidhi
- **Collaborator**: Kunal
- **Jira Issue**: ACL-7
- **Branch**: `chore/security/ACL-7-repository-audit`
- **Scanned Commit**: `781c7593a9e95d60f2ab13bee352e390c935c7a5`
- **Assistance**: The audit was performed by Vidhi Sharma; AI (Codex/ChatGPT) was used only for documentation and development assistance.

## Executive Summary

- **Technical review status**: Complete for the dependency manifests and resolved environments described below
- **Commercial compatibility status**: **Conditional — owner/legal review required**
- **Reason**: Resolved Node.js and Python dependencies include LGPL- and MPL-licensed components with notice, source-availability, relinking, or file-level obligations depending on how AuthClaw is distributed.
- **Repository license**: Missing; the project owner must select and approve the AuthClaw license before external distribution.
- **Third-party notice file**: Missing; distribution packaging should include applicable notices and license texts.

The earlier assertion that no copyleft dependencies were present was incorrect and has been removed.

## Methodology and Scope

| Ecosystem | Evidence source | Coverage | Tool/method |
|---|---|---|---|
| Node.js | `console/package-lock.json` | 845 resolved package entries; every entry contains license metadata | Lockfile enumeration |
| Python | Combined backend, agent, and audit-consumer requirements | 138 resolved packages in an isolated Python 3.12 environment | `pip-licenses` 5.5.5 |
| Go | `gateway/go.mod`, resolved module graph, and compiled package graph | Direct and transitive packages reachable from `gateway` | `go-licenses report ./...` 1.6.0 |

## Node.js License Review

The lockfile contains permissive licenses including MIT, ISC, Apache-2.0, BSD variants, BlueOak-1.0.0, CC0-1.0, and Python-2.0. It also contains weak-copyleft or attribution-sensitive entries requiring review:

| Package family | Version | License metadata | Relationship | Review note |
|---|---|---|---|---|
| `@img/sharp-libvips-*` | 1.2.4 | LGPL-3.0-or-later | 10 optional platform packages | Confirm distribution and dynamic-linking/source-offer obligations for shipped targets |
| `@img/sharp-*` platform binaries | 0.34.5 | Apache-2.0 and/or LGPL-3.0-or-later and MIT | 4 optional platform packages | Preserve applicable notices and review LGPL obligations |
| `lightningcss` and platform packages | 1.32.0 | MPL-2.0 | 12 production entries | Preserve notices; modifications to MPL-covered files may require source availability |
| `axe-core` | 4.12.1 | MPL-2.0 | Development dependency | Retain notices if redistributed |

## Python License Review

The isolated resolved environment contained 138 packages. Most declared MIT, BSD, Apache, ISC, PSF, Unlicense, or compatible combinations. The following packages require explicit weak-copyleft review:

| Package | Resolved version | License metadata | Review note |
|---|---|---|---|
| `psycopg` | 3.3.4 | LGPL-3.0-only | Confirm use and distribution obligations |
| `psycopg-binary` | 3.3.4 | LGPL-3.0-only | Confirm binary redistribution obligations |
| `psycopg2-binary` | 2.9.12 | GNU Library/Lesser GPL | Confirm binary redistribution obligations |
| `certifi` | 2026.6.17 | MPL-2.0 | Preserve required notices |
| `pathspec` | 1.1.1 | MPL-2.0 | Preserve required notices |
| `orjson` | 3.11.9 | MPL-2.0 and Apache-2.0 or MIT | Confirm selected license expression and preserve notices |
| `tqdm` | 4.68.4 | MPL-2.0 and MIT | Preserve applicable notices |

## Go License Review

`go-licenses` identified the compiled third-party dependency graph as MIT, BSD-2-Clause, BSD-3-Clause, or Apache-2.0. No copyleft license was reported for the resolved third-party Go packages. The root `gateway` module was reported as `Unknown` because AuthClaw has no root license file.

Representative verified modules include `go-chi/chi`, `go-redis`, `kafka-go`, `lib/pq`, `lz4`, `klauspost/compress`, `xxhash`, `godotenv`, `atomic`, and `yaml.v3`.

## Required Owner Decisions and Follow-up

1. **Kunal/project owner**: Select and approve a root AuthClaw license before external distribution.
2. **Kunal/legal reviewer**: Confirm that the identified LGPL/MPL usage and distribution model are commercially acceptable and record any required source-offer, relinking, modification-disclosure, or notice obligations.
3. **Release owner**: Add a generated `THIRD_PARTY_LICENSES.txt` or equivalent notice bundle after the legal disposition is approved.
4. **Vidhi**: Link the approval or follow-up Jira issue to ACL-7 before closure.

## Conclusion

No dependency was identified as AGPL-licensed. The resolved trees do contain LGPL and MPL components, so final commercial compatibility cannot be claimed until the owner/legal review and notice plan are recorded. This is an evidence-backed release condition, not a vulnerability finding.
