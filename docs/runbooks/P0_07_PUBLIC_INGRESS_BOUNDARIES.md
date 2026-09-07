# P0-07 public ingress and environment URL boundaries

This runbook implements the accepted design in
[ADR-0002](../adr/0002-aws-url-environment-boundary.md). The task-list document is
reference material; this runbook and the reviewed Terraform are the executable release
contract.

## Resulting boundary

| Boundary | Staging | Production |
| --- | --- | --- |
| Marketing / combined console edge | `dev.authclaw.ai` | `authclaw.ai`, with `www.authclaw.ai` returning a permanent redirect |
| Authenticated console | `dev.authclaw.ai` | `app.authclaw.ai` |
| API | `api.dev.authclaw.ai` | `api.authclaw.ai` |
| Gateway | `gateway.dev.authclaw.ai` | `gateway.authclaw.ai` |
| OIDC callback | `https://dev.authclaw.ai/api/auth/oidc/callback` | `https://app.authclaw.ai/api/auth/oidc/callback` |
| CORS allowlist | only `https://dev.authclaw.ai` | only `https://app.authclaw.ai` |
| Session cookie | `authclaw_session_stg`, host-only | `authclaw_session_prod`, host-only |

Route 53 aliases point only to CloudFront. A WAF web ACL protects every distribution.
CloudFront VPC origins reach three service-specific internal ALBs in private subnets.
Each ALB has only an HTTPS 443 listener and its security group accepts only the AWS-managed
`com.amazonaws.global.cloudfront.origin-facing` prefix list. ECS tasks remain in private
subnets without public IPs; agent, OPA, Presidio, PostgreSQL, Redis, ClickHouse, Kafka/SQS,
and service-discovery endpoints are not load-balancer targets.

Staging uses one combined `dev.authclaw.ai` distribution: the console is the default dynamic
origin, `/`, `/demo*`, `/early-access*`, and `/marketing/*` use the private versioned S3
marketing origin, and `/api/public/v1/access-requests*` uses the backend intake origin.
Production separates marketing, console, API, and gateway distributions. Marketing assets
must use the `/marketing/` prefix when referenced from staging pages so they cannot fall
through to the console origin.

## Configuration and fail-closed gates

Set these values in an environment-specific, encrypted tfvars source; do not commit account
IDs or certificate ARNs.

```hcl
enable_public_edge      = true
public_url_environment  = "staging" # or "production"
aws_account_id          = "<12-digit deployment account>"
hosted_zone_id          = "<environment Route 53 zone id>"
edge_certificate_arn    = "<us-east-1 ACM certificate covering only this environment>"
primary_certificate_arn = "<primary-region ACM certificate for origin HTTPS>"
secondary_certificate_arn = "<secondary-region ACM certificate for origin HTTPS>"
edge_log_retention_days = 90
edge_alarm_action_arns   = ["<approved SNS or incident-action ARN>"]
```

Terraform rejects a production URL boundary when `enable_public_edge` is false, a viewer
certificate outside `us-east-1`, missing regional origin certificates, missing Route 53
zone, or retention below 30 days. The staging and production hostnames are constants, not
caller-provided strings. Runtime `authclaw_env=production` continues to enforce the separate
P0-06 internal service-TLS gate; do not weaken that gate to deploy P0-07.

Run a saved plan and have the platform and security owners review all replacements before
apply. Moving from the legacy ALB changes every public-service ALB and target attachment.

```powershell
terraform -chdir=infra/terraform init
terraform -chdir=infra/terraform fmt -recursive -check
terraform -chdir=infra/terraform validate
terraform -chdir=infra/terraform test
terraform -chdir=infra/terraform plan -var-file=<secured-environment.tfvars> -out=p0-07.tfplan
terraform -chdir=infra/terraform show p0-07.tfplan
```

The reviewed plan must show:

- exactly three internal ALBs per enabled region, private-subnet attachments, HTTPS 443,
  CloudFront prefix-list ingress, access logging, and no `0.0.0.0/0`/`::/0` ingress;
- only the documented CloudFront distributions and Route 53 aliases;
- WAF common, known-bad-input, and per-IP rate-limit rules on every distribution;
- private S3 marketing content with Block Public Access, versioning, and OAC-only reads;
- exact runtime URLs/CORS/OIDC values and environment-specific cookie names;
- no load balancer or public IP for any internal service or data store.

## Logging and data minimization

WAF logs are the canonical edge request log. They omit sampled-request storage and redact
the `Authorization` header, `Cookie` header, and complete query string before delivery to an
environment-specific CloudWatch log group. ALB access logs are written to a dedicated
private S3 bucket with SSE-S3 and lifecycle expiration. AWS ALB access logging supports
SSE-S3 rather than customer-managed SSE-KMS; this is the documented exception to ADR-0002's
general KMS preference. Applications must never place tokens, authorization codes, tenant
secrets, or personal data in paths. CloudFront legacy standard logs are deliberately not
enabled because they would retain OIDC query parameters without field-level redaction.

## Staged proof and rollback

1. Apply to staging and wait for all distributions and VPC origins to report deployed.
2. Upload the immutable marketing release under the approved paths. Confirm direct S3 reads
   fail and only the CloudFront URL succeeds.
3. Run HTTP-to-HTTPS, certificate/SNI, console, `/health`, and public-intake probes. Record
   the CloudFront request IDs and UTC timestamps.
4. From outside the VPC, attempt each ALB DNS name on 443, 8000, and 8080. Record DNS
   unreachability, timeout, or denial. Also export the ALB scheme/subnets/listeners and
   security-group rules.
5. Test the exact allowed Origin and one production/staging cross-origin. Confirm the latter
   has no `Access-Control-Allow-Origin` response header.
6. Complete password and OIDC login. Inspect `Set-Cookie` for the environment name,
   `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and absence of `Domain`. Register no
   wildcard callback and prove the other environment callback is rejected.
7. Use a tenant-A session against a tenant-B resource and record the denial plus audit ID.
8. Trigger a benign WAF test and the approved rate-limit rehearsal. Correlate the request ID
   to a redacted log event; confirm ALB logs arrive and both retention controls are active.
9. Validate the evidence JSON:

   ```powershell
   python scripts/verify_p007_edge_evidence.py <release-evidence.json>
   ```

Production promotion requires accepted staging evidence, separate production certificates
and secrets, a reviewed production plan, and P0-06 production runtime TLS. Store the accepted
JSON and plan digest with the release artifact; never commit live tokens or headers.

Rollback changes Route 53 aliases/distribution origins to the last reviewed edge version and
rolls ECS task definitions back together. Never restore the internet-facing ALB or alternate
ports. Re-run origin denial, cookies, CORS, login, health, WAF, and log-delivery checks after
rollback.

## Completion ownership

Platform owns Route 53, ACM, CloudFront, WAF, private ALBs, logging, alarms, plan/apply, and
rollback. Security accepts origin-denial, WAF, redaction, tenant-boundary, and callback
evidence. Console/identity owners accept cookies, login, logout, invitation, and OIDC. P0-07
is release-complete only when the validator accepts both the staging artifact and the
production artifact and those artifacts are attached to the corresponding releases.
