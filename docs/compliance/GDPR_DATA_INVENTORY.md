# AuthClaw GDPR P0 data inventory

| Metadata | Value |
|---|---|
| Owner | Vidhi Sharma |
| Collaborator | Kunal |
| Jira issue | ACL-15 |
| Branch | `feat/privacy/ACL-15-gdpr-data-lifecycle` |
| Baseline date | 2026-07-17 |
| Status | Engineering baseline; organizational and legal review required |

## Purpose

This inventory records the P0 personal-data processing flows implemented by
AuthClaw. It supports data minimization, retention, deletion and engineering
traceability.

It is not legal advice and does not replace an organization-approved Record of
Processing Activities, lawful-basis assessment, processor agreement or privacy
notice.

## P0 processing inventory

| Processing flow | Personal-data classes | Technical purpose | Source | Components and storage | Recipient or processor | Tenant isolation | Current retention and deletion |
|---|---|---|---|---|---|---|---|
| User identity and access | Name, email, user identifier, tenant membership, roles and OIDC claims | Authentication, authorization and account administration | User, administrator or configured identity provider | Console; `backend/`; PostgreSQL | AuthClaw control plane and configured identity provider | Records and authorization are scoped by `tenant_id` | Retained for the account and tenant lifecycle; organization-approved deletion and exception rules are required |
| API and gateway requests | Request identifier, tenant identifier, provider, model, route and request metadata | Route authorized model requests and enforce policy | Authenticated API client | `backend/`; `gateway/`; operational metadata stores | Configured model provider | Tenant context is established before policy and provider routing | Request payloads should remain transient unless an approved workflow requires persistence |
| Prompts and model responses | Free-form text that may contain names, contact details, identifiers, financial, health or other personal data | Provide the requested AI operation | End user or authorized application | `gateway/`; `services/agent/`; provider request lifecycle | Configured model provider | Requests are processed using authenticated tenant context | Minimize persistence; raw content must not be written to operational logs or audit metadata by default |
| Redaction and tokenization mappings | Encrypted original value, token value, entity type, strategy and usage metadata | Replace sensitive values before provider egress and support authorized reversal | Gateway sensitive-data detection | `redaction_tokens` in PostgreSQL; `gateway/redact.go` | AuthClaw gateway and authorized control-plane users | Every mapping contains `tenant_id`; cross-tenant access is forbidden | Tenant-configurable 1-3650 days; default 90 days; expired mappings are eligible for purge |
| Agent conversation history | User message, agent response, session identifier and tenant identifier | Maintain authorized conversational context | End user through the canonical agent API | `services/agent/` tenant-scoped memory/database | AuthClaw agent service | ACL-14 introduces tenant-isolated chat history | Retention and deletion period must be defined and tested under ACL-15 |
| Compliance workflows and approvals | Actor identifier, action description, decision, comment, workflow state and request identifier | Human approval and compliance workflow execution | User, reviewer or system workflow | `backend/`; PostgreSQL | Authorized tenant users and AuthClaw services | Workflow and approval records are tenant-scoped | Retention period and deletion exceptions require an approved policy |
| Audit and evidence metadata | Actor identifier, action, request identifier, provider, model, status, policy and integrity hashes | Security monitoring, accountability and evidence integrity | Gateway, backend and agent services | PostgreSQL metadata; ClickHouse audit events | Authorized security and governance users | Audit queries and records are tenant-scoped | Retention must balance storage limitation with security, contractual and legal evidence requirements |
| Uploaded documents and extracted content | Document text and any personal data contained in it | Document analysis, retrieval and compliance workflows | Authorized user | `services/agent/` document-processing and retrieval components | AuthClaw agent and configured model provider where authorized | Processing must preserve tenant context | Minimize stored extracts; define deletion for source documents, chunks and derived indexes |
| Operational logs and telemetry | Request identifiers, timing, counts, error categories and service metadata | Reliability, security monitoring and incident investigation | AuthClaw services | Runtime logs and monitoring systems | Authorized operators | Tenant identifiers may be used only where operationally necessary | Store metadata only; never store raw prompts, credentials or detected personal values by default |

## Data-minimization rules

1. Raw prompts, responses, credentials and detected personal values must not be
   written to operational logs or audit metadata by default.
2. Audit events should record identifiers, counts, entity types, decisions and
   outcomes instead of personal-data values.
3. Provider-bound content must pass through the canonical gateway policy and
   redaction controls.
4. Collection and persistence must be limited to fields required for an
   identified technical purpose.
5. Diagnostic and test evidence must use synthetic data.

## Retention and deletion rules

1. Retention evaluation must always use the authenticated tenant context.
2. Redaction mappings use the tenant-configured retention period, with the
   current technical default of 90 days.
3. Expired personal-data records must be deleted without affecting another
   tenant.
4. Deletion evidence must record the tenant, data class, operation, record
   count, timestamp, request identifier and outcome.
5. Deletion evidence must not contain the personal-data values that were
   deleted.
6. Failed deletion must be observable and safely retryable.
7. Legal, contractual, security or backup exceptions require an authorized
   organizational decision and documented expiry.

## Current implementation evidence

- `backend/app/db/models.py` - tenant-scoped redaction mapping lifecycle fields.
- `backend/app/api/v1/endpoints/redaction.py` - tenant-authorized expired-token purge.
- `backend/app/schemas/models.py` - retention validation from 1 to 3650 days.
- `gateway/redact.go` - tenant retention configuration, expiration and automatic purge.
- `backend/app/core/auth.py` and `backend/app/db/session.py` - tenant authorization context.
- `services/agent/memory.py` - tenant-isolated agent history foundation.
- `docs/compliance/GDPR_SOC2_CONTROL_MATRIX.md` - GDPR control mapping.

## Open ACL-15 implementation gaps

- Produce durable, non-sensitive audit evidence for deletion operations.
- Centralize backend retention and deletion behavior in a testable service.
- Verify that logging defaults never expose raw detected personal data.
- Define and test retention behavior for P0 persisted data classes.
- Add cross-tenant, authorization, expiry, retry and audit tests.
- Document telemetry, failure handling and rollback behavior.
