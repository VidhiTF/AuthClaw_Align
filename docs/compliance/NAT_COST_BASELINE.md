# NAT Cost Baseline

## Status

Production values are pending because account IDs, regions, billing evidence, budget owner, threshold, and notification destination have not been provided. This document is a production rollout gate, not approval to estimate or apply from placeholder data.

## Required Baseline

| Account | Region | Period | NAT count | NAT gateway-hours | Bytes processed | Hourly cost | Processing cost | Cross-AZ data cost | Total | Evidence URI | Owner | Verified |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| Pending | Pending | Representative 30-day window | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending |

Capture billed values from AWS Cost Explorer or the Cost and Usage Report and reconcile them to CloudWatch `BytesOutToDestination` and `BytesInFromDestination`. Use the actual regional AWS prices effective on the review date; do not copy a price from another region.

## Projection

| Environment | Region | AZ count | Mode | Projected NAT-hours/month | Projected processed bytes | Projected monthly total | Increase over baseline | Acceptable increase | Approver |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Production secondary | Pending | Pending | `per_az` | Pending | Pending | Pending | Pending | Pending | Pending |
| Production primary | Pending | Pending | `per_az` | Pending | Pending | Pending | Pending | Pending | Pending |

Calculate:

- NAT-hours as NAT count multiplied by hours in the billing period.
- Processing cost from observed bytes that remain on NAT after private endpoints are enabled.
- Any cross-AZ transfer visible in the current single-NAT baseline separately; normal `per_az` routing should remove private-subnet-to-NAT cross-AZ traffic.
- Interface endpoint hourly and data-processing costs separately from NAT savings.

## Budget Gate

| Monthly threshold | Notification destination | Budget owner | Finance approver | Operations approver | Approval ticket |
| ---: | --- | --- | --- | --- | --- |
| Pending | Pending | Pending | Pending | Pending | Pending |

Create the AWS Budget only after every field is approved. The budget resource or deployment configuration must not contain a fabricated email address or threshold.

## Acceptance

The cost gate passes only when evidence contains actual billed baseline values, the per-AZ projection includes interface endpoint costs, the acceptable increase is explicit, and the named owner approves the threshold and notification route.
