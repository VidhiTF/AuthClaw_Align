# Quota alert verification

Reuse decision before implementation: reuse the checked-in quota alert rules,
Prometheus promtool rule-testing mechanism, and ACL21 severity/summary/runbook
conventions. Existing rules tests cannot verify Alertmanager delivery. A bounded
rehearsal script therefore runs unchanged rules with a controlled metric exporter
and isolated webhook receiver. The receiver is chosen under the user's permission
to choose the best test receiver; it sends no external messages.

The rehearsal uses a private Docker network, without published application ports.
Its exporter and receiver run in one disposable container. Evidence must show
Prometheus-generated alerts delivered by Alertmanager, both firing and resolved.
Controlled metrics test monitoring integration, not real application Redis behavior.
Application outage/load evidence remains a separate acceptance requirement.

Reproduce from the repository root with Docker available:

```powershell
python scripts/quota_alert_rehearsal.py --work .quota-alert-evidence
```

The script first runs `promtool test rules` against
`infra/observability/quota-alerts.test.yml`, then uses Prometheus 3.5.1 and
Alertmanager 0.28.1. It preserves the production 1-minute availability hold and
5-minute rejection hold with a 5-minute rate window. Allow up to 15 minutes after
container startup. It changes controlled failure metrics to healthy only after
both real firing notifications arrive, then requires both resolved notifications.
The isolated receiver is named `approved-local-quota-test`. Output includes the
promtool result, original Alertmanager webhook payloads, summary and container logs.
Containers and their private network are removed on normal completion/failure.

Rule tests include unavailability pending/firing/recovery, sustained rejection
firing/recovery, exact 20% threshold without firing, and idle zero-denominator
traffic without firing. The production scrape target uses the exact
`/internal/metrics/quota` endpoint with its dedicated bearer credential; this
rehearsal intentionally uses controlled metrics and does not install a production
receiver or scrape configuration.

Observed rehearsal adjustment: Docker Desktop filesystem/scheduling delays caused
missed 2-second and 10-second scrapes during concurrent test load. The rehearsal
now uses 30-second scrapes with a 25-second timeout. Production rule expressions,
hold durations and rate windows stayed unchanged. Earlier availability resolutions
caused by missing samples are excluded from recovery acceptance; the clean repeat
requires notification receipt after the deliberate healthy transition. Monitoring
complete target disappearance now also fires the availability alert through an
explicit absent-series expression.

## Recorded result (2026-09-17 UTC)

Promtool returned `SUCCESS`. The real Alertmanager receiver delivered:

| Alert | Firing received | Resolved received |
| --- | --- | --- |
| QuotaLimiterUnavailable | 06:02:15.566903 | 06:03:47.927312 |
| QuotaSustainedRejections | 06:00:15.982791 | 06:06:16.584791 |

The deliberate healthy transition was 06:03:35.638 UTC. Both accepted resolved
notifications arrived after that transition. The matching alert fingerprints,
original payloads, receiver name and hashes are retained in
[quota-rehearsal-evidence.json](../infra/observability/quota-rehearsal-evidence.json).
The rule file SHA256 was
`ea92687a99f41de5130f67f085abc5dc0c5fde9949faeaeaac37eb135491047e`.
All three containers and the isolated Docker network were removed after success.

## Provisioned deployment path

Review follow-up wires the checked-in rules into a regional Amazon Managed
Prometheus workspace. A dedicated ECS OpenTelemetry collector discovers every
gateway and agent task through private DNS, scrapes the authenticated
`/internal/metrics/quota` endpoint, and uses SigV4 remote write. Its execution
role can read only the KMS-protected scrape credential. Managed Alertmanager
assumes an IAM role whose trust is bound to the exact quota workspace and whose
policy permits only explicitly configured regional SNS topics.
Staging and production plans fail when no approved receiver is configured.

Terraform 1.15.7 with AWS provider 5.100.0 validated successfully. A synthetic
offline plan with a test SNS receiver was complete and applyable, and the CI
plan assertion verified the workspace, collector, rule namespace, remote-write
policy, exact-workspace role trust, Alertmanager definition, and concrete SNS route.
The native Terraform suite passed all 19 tests, including disabled-observability
and production-like receiver fixtures. See
`evidence/quota/terraform-observability-plan.json`. This plan was not applied;
shared-account apply and SNS subscription delivery remain release evidence.

This proves rule evaluation, sustained hold duration, local notification routing
and resolution using controlled metric input. It does not prove production paging
delivery, deployment scrape installation, or application failure/load behavior.
