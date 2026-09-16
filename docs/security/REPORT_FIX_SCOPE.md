# Backend and gateway review fixes

This patch addresses the ten backend findings and five gateway findings in the
supplied source reviews of revision `fe4031c`. It is rebuilt on `73696bd`.
Finding numbers are local to each report.

| Report finding | Implementation | Regression evidence |
| --- | --- | --- |
| Backend 1: SQL parameter logging | `app/db/session.py`, default DEBUG false | `test_review_logging_and_event_identity.py` |
| Backend 2: reset issuance abuse | Account/IP limits before lookup; signed BFF identity | `test_reset_abuse_security.py`, backend/console BFF tests |
| Backend 3: cloud action MFA | Normalize before MFA and provider dispatch | `test_cloud_security.py` |
| Backend 4: predictable export signer | Explicit signing keys in shared environments | `test_review_audit_security.py` |
| Backend 5: regex resource exhaustion | Bounded RE2 evaluation; no backtracking fallback | `test_policy_chat_security.py` |
| Backend 6: framework disclosure | Signed opaque proofs for nonmatching records; malformed proofs rejected | `test_review_audit_security.py`, `test_audit_export.py` |
| Backend 7: revoked connector reuse | Reject revoked state before credential use | `test_cloud_security.py` |
| Backend 8: finding event deduplication | Distinct occurrence identity; explicit retry identity retained | `test_review_logging_and_event_identity.py` |
| Backend 9: chat quota bypass | Delegate to existing workflow quota enforcement | `test_policy_chat_security.py` |
| Backend 10: auditor OTP races | Lock and refresh before attempt/consume/resend; signed browser limits | `test_review_otp_postgres.py`, BFF tests |
| Gateway 1: shared Bedrock authorization | Explicit tenant/model entitlement | `bedrock_security_test.go` |
| Gateway 2: Bedrock spending races | Atomic conservative reservation; database errors deny egress | `bedrock_security_test.go`, including PostgreSQL concurrency |
| Gateway 3: prompt inspection bypass | Schema-aware supported Bedrock adapters; unsupported shapes rejected | `normalization_security_test.go` |
| Gateway 4: PostgreSQL plaintext default | Verified TLS in shared environments, explicit local opt-out | `db_test.go` |
| Gateway 5: unbounded listener lifetime | Header/read/idle and streaming-aware transport deadlines | `transport_limits_test.go` |

Backend test paths above are relative to `backend/tests`; implementation paths
are relative to `backend`. Gateway paths are relative to `gateway`.

The patch includes only supporting RE2 lock entries, BFF route signing, test
fixtures and CI selection. It does not include the earlier agent implementation,
tenant registry, migration bumps, UI redesign or console dependency upgrades.
Gateway remains compatible with master revisions 046/047.

Shared deployments must explicitly configure an audit export signing key and
independent verification trust keys. Bedrock entitlement and budget configuration
is documented in `BEDROCK_VALIDATION.md`. No live deployment is certified here.

The unchanged master console dependency lock has known audit findings. They are
outside these two reports and are not waived by this patch.
