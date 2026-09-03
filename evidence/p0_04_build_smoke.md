# P0-04 ARM64 build and smoke evidence

- Generated: `2026-09-02T10:14:24.1450807+00:00`
- Command: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/p0_04_build_smoke.ps1 -Platform linux/arm64,linux/amd64 -Service all`
- Task 1 manifest evidence: `evidence/p0_04_manifest_inventory.md`

|service|platform|build|metadata|smoke|QEMU run|status|tag|
|---|---|---|---|---|---|---|---|
|backend|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/backend:local-arm64-20260902101145-21532`|
|agent|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/agent:local-arm64-20260902101145-21532`|
|gateway|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/gateway:local-arm64-20260902101145-21532`|
|console|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/console:local-arm64-20260902101145-21532`|
|audit-consumer|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/audit-consumer:local-arm64-20260902101145-21532`|
|opa|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/opa:local-arm64-20260902101145-21532`|
|presidio|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/presidio:local-arm64-20260902101145-21532`|
|backend|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/backend:local-amd64-20260902101145-21532`|
|agent|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/agent:local-amd64-20260902101145-21532`|
|gateway|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/gateway:local-amd64-20260902101145-21532`|
|console|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/console:local-amd64-20260902101145-21532`|
|audit-consumer|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/audit-consumer:local-amd64-20260902101145-21532`|
|opa|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/opa:local-amd64-20260902101145-21532`|
|presidio|linux/amd64|PASS|linux/amd64|PASS|False|PASS|`authclaw-p0-04/presidio:local-amd64-20260902101145-21532`|

Details and exact command output tails are retained in `evidence/p0_04_build_smoke.json`.
