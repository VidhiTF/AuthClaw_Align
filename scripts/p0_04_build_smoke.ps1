[CmdletBinding()]
param(
    [string]$Platform = "linux/arm64",
    [ValidateSet("all", "backend", "agent", "gateway", "console", "audit-consumer", "opa", "presidio")]
    [string]$Service = "all"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$EvidenceJson = Join-Path $Root "evidence/p0_04_build_smoke.json"
$EvidenceMd = Join-Path $Root "evidence/p0_04_build_smoke.md"
$RunId = "{0}-{1}" -f ([DateTimeOffset]::UtcNow.ToString("yyyyMMddHHmmss")), $PID
$Shell = if ($PSVersionTable.PSEdition -eq "Desktop") { "powershell -NoProfile -ExecutionPolicy Bypass -File" } else { "pwsh" }
$Platforms = @($Platform.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries))
if ($Platforms | Where-Object { $_ -notin @("linux/arm64", "linux/amd64") }) {
    throw "Platform must contain only linux/arm64 and/or linux/amd64"
}
$Definitions = @(
    @{ Name = "backend"; Context = "backend"; Dockerfile = "backend/Dockerfile.demo" },
    @{ Name = "agent"; Context = "services/agent"; Dockerfile = "services/agent/Dockerfile" },
    @{ Name = "gateway"; Context = "gateway"; Dockerfile = "gateway/Dockerfile.demo" },
    @{ Name = "console"; Context = "console"; Dockerfile = "console/Dockerfile" },
    @{ Name = "audit-consumer"; Context = "."; Dockerfile = "audit_consumer/Dockerfile" },
    @{ Name = "opa"; Context = "infra/opa"; Dockerfile = "infra/opa/Dockerfile" },
    @{ Name = "presidio"; Context = "infra/presidio"; Dockerfile = "infra/presidio/Dockerfile" }
)

function Invoke-Docker([string[]]$Arguments, [switch]$Quiet) {
    $log = [System.Collections.Generic.List[string]]::new()
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker @Arguments 2>&1 | ForEach-Object {
            $line = $_.ToString()
            $log.Add($line)
            if (-not $Quiet) { Write-Host $line }
        }
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    [pscustomobject]@{ ExitCode = $exitCode; Output = ($log -join "`n") }
}

function Test-Pending([string]$Output) {
    $Output -match "(?i)(network is unreachable|no such host|i/o timeout|tls handshake timeout|proxyconnect|connection refused|access is denied|permission denied|failed to fetch anonymous token.*timeout)"
}

function Invoke-ConsoleSmoke([string]$Tag, [string]$PlatformName, [string]$ContainerName) {
    $start = Invoke-Docker @("run", "--detach", "--platform", $PlatformName, "--name", $ContainerName, $Tag)
    if ($start.ExitCode -ne 0) { return $start }
    try {
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $probe = Invoke-Docker @("exec", $ContainerName, "node", "-e", "require('http').get('http://127.0.0.1:3001/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))") -Quiet
            if ($probe.ExitCode -eq 0) { return $probe }
            Start-Sleep -Seconds 1
        }
        $logs = Invoke-Docker @("logs", $ContainerName)
        [pscustomobject]@{ ExitCode = 1; Output = "console health timeout`n$($logs.Output)" }
    }
    finally {
        $null = Invoke-Docker @("rm", "--force", $ContainerName) -Quiet
    }
}

function Invoke-Smoke([string]$Name, [string]$Tag, [string]$PlatformName) {
    switch ($Name) {
        "backend" {
            Invoke-Docker @("run", "--rm", "--platform", $PlatformName, "-e", "DATABASE_URL=postgresql+psycopg://authclaw:authclaw@localhost/authclaw", "--entrypoint", "python", $Tag, "-c", "import bcrypt,cryptography,orjson,psycopg,pydantic_core,uvloop; import main; assert main.app")
        }
        "agent" {
            Invoke-Docker @("run", "--rm", "--platform", $PlatformName, "-e", "AUTHCLAW_DISABLE_BACKGROUND_MONITOR=true", "--entrypoint", "python", $Tag, "-c", "import blis,cymem,numpy,spacy,thinc; import main; assert main.app")
        }
        "gateway" {
            $expected = $PlatformName
            $run = Invoke-Docker @("run", "--rm", "--platform", $PlatformName, "--entrypoint", "/app/authclaw-gateway", $Tag, "--version")
            if ($run.ExitCode -eq 0 -and $run.Output -notmatch [regex]::Escape($expected)) {
                return [pscustomobject]@{ ExitCode = 1; Output = "gateway reported '$($run.Output)', expected $expected" }
            }
            $run
        }
        "console" { Invoke-ConsoleSmoke $Tag $PlatformName "authclaw-p0-04-console-$RunId-$($PlatformName.Split('/')[-1])" }
        "audit-consumer" {
            Invoke-Docker @("run", "--rm", "--platform", $PlatformName, "--entrypoint", "python", $Tag, "-c", "import clickhouse_connect,kafka,lz4.frame,consumer,transport; assert transport._bounded_int('AUDIT_SMOKE_VALUE',3,1,5)==3")
        }
        "opa" {
            $version = Invoke-Docker @("run", "--rm", "--platform", $PlatformName, $Tag, "version")
            if ($version.ExitCode -ne 0) { return $version }
            Invoke-Docker @("run", "--rm", "--platform", $PlatformName, $Tag, "check", "/policies/authclaw.rego")
        }
        "presidio" {
            Invoke-Docker @("run", "--rm", "--platform", $PlatformName, "--entrypoint", "poetry", $Tag, "run", "python", "-c", "import presidio_analyzer; assert presidio_analyzer.AnalyzerEngine")
        }
    }
}

$selected = if ($Service -eq "all") { $Definitions } else { @($Definitions | Where-Object Name -eq $Service) }
$results = [System.Collections.Generic.List[object]]::new()
Push-Location $Root
try {
    foreach ($platformName in $Platforms) {
        $architecture = $platformName.Split("/")[-1]
        foreach ($definition in $selected) {
            $name = $definition.Name
            $tag = "authclaw-p0-04/${name}:local-${architecture}-${RunId}"
            Write-Host "[$name][$platformName] BUILD"
            $build = Invoke-Docker @("buildx", "build", "--platform", $platformName, "--load", "--tag", $tag, "--file", $definition.Dockerfile, $definition.Context)
            $record = [ordered]@{
                service = $name; platform = $platformName; dockerfile = $definition.Dockerfile; image_tag = $tag
                build = if ($build.ExitCode -eq 0) { "PASS" } elseif (Test-Pending $build.Output) { "PENDING" } else { "FAIL" }
                image_architecture = $null; image_os = $null; smoke = "PENDING"; qemu_execution = $false; status = "PENDING"; detail = ""
            }
            if ($build.ExitCode -ne 0) {
                $record.status = if ($record.build -eq "PENDING") { "LIVE-EVIDENCE-PENDING" } else { $record.build }
                $record.detail = ($build.Output -split "`n" | Select-Object -Last 8) -join "`n"
                $results.Add([pscustomobject]$record)
                Write-Host "[$name][$platformName] $($record.status)"
                continue
            }

            $inspect = Invoke-Docker @("image", "inspect", "--format", "{{.Architecture}} {{.Os}}", $tag) -Quiet
            if ($inspect.ExitCode -eq 0) {
                $metadata = $inspect.Output.Trim().Split(" ")
                $record.image_architecture = $metadata[0]
                $record.image_os = $metadata[1]
            }
            if ($inspect.ExitCode -ne 0 -or $record.image_architecture -ne $architecture -or $record.image_os -ne "linux") {
                $record.status = "FAIL"
                $record.detail = "image metadata mismatch: $($inspect.Output)"
            }
            else {
                Write-Host "[$name][$platformName] SMOKE"
                $smoke = Invoke-Smoke $name $tag $platformName
                $record.smoke = if ($smoke.ExitCode -eq 0) { "PASS" } elseif (Test-Pending $smoke.Output) { "PENDING" } else { "FAIL" }
                $record.qemu_execution = $platformName -eq "linux/arm64" -and $smoke.ExitCode -eq 0
                $record.status = if ($record.smoke -eq "PENDING") { "LIVE-EVIDENCE-PENDING" } else { $record.smoke }
                $record.detail = if ($smoke.ExitCode -eq 0) { $smoke.Output.Trim() } else { ($smoke.Output -split "`n" | Select-Object -Last 8) -join "`n" }
            }
            $results.Add([pscustomobject]$record)
            Write-Host "[$name][$platformName] $($record.status)"
        }
    }
}
finally { Pop-Location }

$payload = [ordered]@{
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    command = "$Shell scripts/p0_04_build_smoke.ps1 -Platform $($Platforms -join ',') -Service $Service"
    run_id = $RunId
    results = $results
}
$payload | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $EvidenceJson
$markdown = [System.Collections.Generic.List[string]]::new()
$markdown.Add("# P0-04 ARM64 build and smoke evidence")
$markdown.Add("")
$markdown.Add("- Generated: ``$($payload.generated_at)``")
$markdown.Add("- Command: ``$($payload.command)``")
$markdown.Add("- Task 1 manifest evidence: ``evidence/p0_04_manifest_inventory.md``")
$markdown.Add("")
$markdown.Add("|service|platform|build|metadata|smoke|QEMU run|status|tag|")
$markdown.Add("|---|---|---|---|---|---|---|---|")
foreach ($result in $results) {
    $metadata = if ($result.image_architecture) { "$($result.image_os)/$($result.image_architecture)" } else { "-" }
    $markdown.Add("|$($result.service)|$($result.platform)|$($result.build)|$metadata|$($result.smoke)|$($result.qemu_execution)|$($result.status)|``$($result.image_tag)``|")
}
$markdown.Add("")
$markdown.Add("Details and exact command output tails are retained in ``evidence/p0_04_build_smoke.json``.")
$markdown | Set-Content -Encoding utf8 $EvidenceMd

$results | Format-Table service, platform, build, image_architecture, smoke, qemu_execution, status -AutoSize
if ($results.status -contains "FAIL") { exit 1 }
if ($results.status -contains "LIVE-EVIDENCE-PENDING") { exit 2 }
