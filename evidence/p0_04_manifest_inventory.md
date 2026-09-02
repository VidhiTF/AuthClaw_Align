# P0-04 Image Manifest Evidence

- Source: `D:\AUTHCLAW-NEW\AuthClaw`
- Python wheel audit reference: `D:\AUTHCLAW-NEW\AuthClaw\docs\AWS_DEPLOYMENT_READINESS_TASK_LIST.md`
- Current CI build platforms: `linux/amd64, linux/arm64`

## Status summary
- PASS: 0
- FAIL: 0
- LIVE-EVIDENCE-PENDING: 32

## Production runtime image inventory
|service|category|source|image|pinned|amd64|arm64|status|rollback|
|---|---|---|---|---|---|---|---|---|
|agent|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/services/agent/Dockerfile:1|python:3.14.3-slim|no|no|no|LIVE-EVIDENCE-PENDING|no|
|audit_consumer|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/audit_consumer/Dockerfile:1|python:3.14.7-slim|no|no|no|LIVE-EVIDENCE-PENDING|no|
|backend|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/backend/Dockerfile.demo:1|python:3.14.7-slim|no|no|no|LIVE-EVIDENCE-PENDING|no|
|backend|terraform_declared_image|infra/terraform/modules/regional_stack/main.tf|arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.yml|clickhouse/clickhouse-server@sha256:07afc18d8a9706eb9d85c5c5d2752e5270f91bbc2894caeaecb73e4d0f603bf5|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|clickhouse/clickhouse-server@sha256:07afc18d8a9706eb9d85c5c5d2752e5270f91bbc2894caeaecb73e4d0f603bf5|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.yml|docker.redpanda.com/redpandadata/redpanda:v23.2.19|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|docker.redpanda.com/redpandadata/redpanda:v23.2.19|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.audit-e2e.yml|localstack/localstack:3.8|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.yml|mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.demo.yml.disabled|mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.yml|openpolicyagent/opa@sha256:dc009236137bb225a1ef09293bb32f2ee1861cc428870d297bf71412d50221c3|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|openpolicyagent/opa@sha256:dc009236137bb225a1ef09293bb32f2ee1861cc428870d297bf71412d50221c3|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.demo.yml.disabled|openpolicyagent/opa@sha256:dc009236137bb225a1ef09293bb32f2ee1861cc428870d297bf71412d50221c3|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.yml|postgres:17|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|postgres:17|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.demo.yml.disabled|postgres:17|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|python:3.14.3-slim|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.demo.yml.disabled|python:3.14.3-slim|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.yml|redis:7|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.full.yml|redis:7|no|no|no|LIVE-EVIDENCE-PENDING|no|
|compose|compose_runtime_dependency|docker-compose.demo.yml.disabled|redis:7|no|no|no|LIVE-EVIDENCE-PENDING|no|
|console|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/console/Dockerfile:3|base|no|no|no|LIVE-EVIDENCE-PENDING|no|
|console|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/console/Dockerfile:10|base|no|no|no|LIVE-EVIDENCE-PENDING|no|
|console|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/console/Dockerfile:27|base|no|no|no|LIVE-EVIDENCE-PENDING|no|
|console|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/console/Dockerfile:1|node:22.23.1-alpine3.23@sha256:8516dce0483394d5708d4b2ee6cacb79fb1d617ea4e2787c2120bcca92ce372e|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|gateway|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/gateway/Dockerfile.demo:17|alpine:3.24|no|no|no|LIVE-EVIDENCE-PENDING|no|
|gateway|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/gateway/Dockerfile.demo:2|golang:${GO_VERSION}-alpine|no|no|no|LIVE-EVIDENCE-PENDING|no|
|opa|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/infra/opa/Dockerfile:1|golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2|yes|no|no|LIVE-EVIDENCE-PENDING|no|
|opa|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/infra/opa/Dockerfile:19|scratch|no|no|no|LIVE-EVIDENCE-PENDING|no|
|presidio|dockerfile_base_or_build|D:/AUTHCLAW-NEW/AuthClaw/infra/presidio/Dockerfile:1|mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9|yes|no|no|LIVE-EVIDENCE-PENDING|no|

## Blockers

- alpine:3.24
- arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
- base
- clickhouse/clickhouse-server@sha256:07afc18d8a9706eb9d85c5c5d2752e5270f91bbc2894caeaecb73e4d0f603bf5
- docker.redpanda.com/redpandadata/redpanda:v23.2.19
- golang:${GO_VERSION}-alpine
- golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2
- localstack/localstack:3.8
- mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9
- node:22.23.1-alpine3.23@sha256:8516dce0483394d5708d4b2ee6cacb79fb1d617ea4e2787c2120bcca92ce372e
- openpolicyagent/opa@sha256:dc009236137bb225a1ef09293bb32f2ee1861cc428870d297bf71412d50221c3
- postgres:17
- python:3.14.3-slim
- python:3.14.7-slim
- redis:7
- scratch

## ARM64 rollout readiness

- Overall: `LIVE-EVIDENCE-PENDING`

|check|status|detail|
|---|---|---|
|production_services|PASS|agent, audit_consumer, backend, console, gateway, opa, presidio|
|local_arm64_build_smoke|PASS|exactly one successful ARM64/QEMU record per service|
|release_manifest_evidence|LIVE-EVIDENCE-PENDING|supply --release-evidence-dir|
|immutable_terraform_images|LIVE-EVIDENCE-PENDING|supply --terraform-input|
|staged_architecture|LIVE-EVIDENCE-PENDING|supply --terraform-input|
|rollback_architecture|PASS|X86_64|

## AWS deployment evidence

- fargate_placement: `LIVE-EVIDENCE-PENDING`
- image_resolution: `LIVE-EVIDENCE-PENDING`
- task_startup: `LIVE-EVIDENCE-PENDING`
- service_stabilization: `LIVE-EVIDENCE-PENDING`
- health_checks: `LIVE-EVIDENCE-PENDING`
- logs: `LIVE-EVIDENCE-PENDING`
- alarms: `LIVE-EVIDENCE-PENDING`
- deployed_image_digest: `LIVE-EVIDENCE-PENDING`
- live_rollback: `LIVE-EVIDENCE-PENDING`

## Failures requiring rollout/baseline work
- images missing digest pin: none
- services requiring ARM64 remediation/rollback: none

## Next Task 2 follow-up
- Replace or rebuild images that lack ARM64 support.
- Add digest pinned, multi-arch manifest publishing in CI (`platforms: linux/amd64,linux/arm64`) and promote signed manifests per service.
- Re-run this manifest check script and attach artifacts to release evidence.
