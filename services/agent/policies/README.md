# AuthClaw OPA Policies

This directory contains the Rego policy bundle loaded by the production Docker Compose OPA service.

The Python policy engine still keeps the existing `policies.yaml` validation path as a fallback, so OPA outages do not break current gateway enforcement.

Local endpoint:

```text
http://localhost:8181/v1/data/authclaw/policy
```
