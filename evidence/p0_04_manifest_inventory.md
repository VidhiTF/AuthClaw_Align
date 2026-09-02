# P0-04 ARM64 Runtime Image Manifest Evidence

- Source repo: `D:\AUTHCLAW-NEW\AuthClaw`
- Script: `scripts/p0_04_manifest_inventory.py`
- Python wheel compatibility audit reference (existing): `docs/AWS_DEPLOYMENT_READINESS_TASK_LIST.md:182`
- Current CI build platform: `linux/amd64` (release workflow does not set explicit multi-platform build)

## Inventory status
- PASS: `1`
- FAIL: `0`
- LIVE-EVIDENCE-PENDING: `22`

## Runtime / base / external image mapping

|service|category|image|pinned|amd64|arm64|manifest|status|rollback|
|---|---|---|---|---|---|---|---|---|
|backend|dockerfile_runtime_base|python:3.14.7-slim|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|agent|dockerfile_runtime_base|python:3.14.3-slim|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|gateway|dockerfile_builder_base|golang:1.26.5-alpine|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|gateway|dockerfile_runtime_base|alpine:3.24|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|console|dockerfile_build_and_runtime_base|node:22.23.1-alpine3.23@sha256:8516a3f4cf95be5f6bde3fd1f5b8f7f9f4bdf3f5f8b5f1f1d1fcb6bbf9ff4d66|yes|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|audit_consumer|dockerfile_runtime_base|python:3.14.7-slim|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|opa|dockerfile_builder_base|golang:1.26.5-alpine|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|opa|dockerfile_runtime_base|scratch|n/a|-|-|n/a|PASS|no|
|presidio|dockerfile_runtime_base|mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9|yes|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|postgres:17|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|redis:7|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|openpolicyagent/opa@sha256:dc009236137bb225a1ef09293bb32f2ee1861cc428870d297bf71412d50221c3|yes|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9|yes|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|docker.redpanda.com/redpandadata/redpanda:v23.2.19|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|clickhouse/clickhouse-server@sha256:07afc18d8a9706eb9d85c5c5d2752e5270f91bbc2894caeaecb73e4d0f603bf5|yes|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|compose|compose_runtime_dependency|localstack/localstack:3.8|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/agent:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/backend:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/gateway:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/console:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/audit-consumer:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/opa-bundle:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|
|terraform|terraform_runtime_image|ghcr.io/example/authclaw/presidio:ci|no|-|-|pending|LIVE-EVIDENCE-PENDING|yes|

## Evidence notes
- Registry inspection command used for reproducibility: `docker buildx imagetools inspect <image> --format json`
- This host cannot access remote registries (`docker` network blocked) and cannot read Docker config (`DOCKER_CONFIG` restrictions), so all manifest checks are currently `LIVE-EVIDENCE-PENDING`.
- `scratch` is not a registrable external base image and is not assessed for registry manifests.

## Blockers and Task 2 follow-up
- Digest-pinning gaps:
  - All Python runtime bases (`python:3.14.3-slim`, `python:3.14.7-slim`) are not pinned.
  - `alpine:3.24`, `golang:1.26.5-alpine`, external services (`postgres:17`, `redis:7`, `docker.redpanda.com/redpandadata/redpanda:v23.2.19`, `localstack/localstack:3.8`) are not pinned.
  - All Terraform runtime images are pinned to `:ci` tags only and must become digest references.
- CI/platform gaps:
  - No explicit `platforms` declaration in release/build workflows, and no controlled multi-arch publish step.
- Multi-architecture rollbacks required for all non-`scratch` pinned-pending images unless manifest checks confirm `linux/arm64` + `linux/amd64` parity on re-run.
- Task 2 follow-up:
  1. Capture registry access in task environment, rerun `python scripts/p0_04_manifest_inventory.py --output-json evidence/p0_04_manifest_inventory.json --output-md evidence/p0_04_manifest_inventory.md`.
  2. Replace non-digest references (base/runtime) with immutable digests.
  3. Expand CI image build to `platforms: linux/amd64,linux/arm64`, publish multi-arch manifests, and consume digest-pinned images in Terraform `container_images`.
