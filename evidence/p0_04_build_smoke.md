# P0-04 ARM64 build and smoke evidence

- Generated: `2026-09-07T10:11:04.7016778+00:00`
- Command: `pwsh scripts/p0_04_build_smoke.ps1 -Platform linux/arm64 -Service all`
- Task 1 manifest evidence: `evidence/p0_04_manifest_inventory.md`

|service|platform|build|metadata|smoke|QEMU run|status|tag|
|---|---|---|---|---|---|---|---|
|backend|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/backend:local-arm64-20260907100908-17560`|
|agent|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/agent:local-arm64-20260907100908-17560`|
|gateway|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/gateway:local-arm64-20260907100908-17560`|
|console|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/console:local-arm64-20260907100908-17560`|
|audit-consumer|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/audit-consumer:local-arm64-20260907100908-17560`|
|opa|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/opa:local-arm64-20260907100908-17560`|
|presidio|linux/arm64|PASS|linux/arm64|PASS|True|PASS|`authclaw-p0-04/presidio:local-arm64-20260907100908-17560`|

Details and exact command output tails are retained in `evidence/p0_04_build_smoke.json`.
