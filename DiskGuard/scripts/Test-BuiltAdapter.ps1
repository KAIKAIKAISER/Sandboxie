#Requires -Version 7.0
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildRunId,
    [switch]$VerifyColdSession
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Built adapter diagnostics must run on the disposable GitHub-hosted Windows runtime test VM.'
}
if ($BuildRunId -notmatch '^[0-9]+$') { throw 'BuildRunId must be a numeric GitHub Actions run ID.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidenceDirectory = Join-Path $projectRoot 'work/hosted-runtime'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

function Invoke-ApplicationCheck {
    param([string]$Executable, [string]$Mode, [string]$Output)
    if (Test-Path -LiteralPath $Output) { throw "Refusing stale diagnostic evidence: $Output" }
    $arguments = @($Mode, ('"' + $Output + '"'))
    if ($Mode -eq '--ui-smoke-test') { $arguments += '--background' }
    $process = Start-Process -FilePath $Executable -ArgumentList $arguments -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit(60000)) { throw "Built application $Mode timed out." }
        if ($process.ExitCode -ne 0) { throw "Built application $Mode exited with $($process.ExitCode)." }
    }
    finally { $process.Dispose() }
    if (-not (Test-Path -LiteralPath $Output)) { throw "Built application did not write $Mode evidence." }
    return Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json
}

function Assert-UiSmoke {
    param([object]$Result, [bool]$ExpectedMonitoring)
    if (-not $Result.success -or -not $Result.frontend_initialized -or -not $Result.backend_invoked -or -not $Result.runtime.driverAvailable) {
        throw 'Built application frontend did not complete real state retrieval, initialization and native bridge invocation with an available driver.'
    }
    if ($Result.runtime.monitoring -ne $ExpectedMonitoring) {
        throw "Built application UI reported monitoring=$($Result.runtime.monitoring), expected $ExpectedMonitoring for this session state."
    }
}

function Get-CanonicalTestPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    if ($resolved.StartsWith('\\?\')) { $resolved = $resolved.Substring(4) }
    return [IO.Path]::GetFullPath($resolved).TrimEnd('\')
}

function Stop-VerifiedClassicSessionLeader {
    # The script is already restricted to this disposable GitHub-hosted VM.
    # Stop only the official installed Classic UI, never a service, driver,
    # SandMan process or another program claiming the same executable name.
    $serviceImage = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieSvc' -Name ImagePath).ImagePath
    $servicePath = if ($serviceImage.StartsWith('"')) { $serviceImage.Split('"')[1] } else { $serviceImage }
    $runtimeDirectory = Split-Path -Path ([Environment]::ExpandEnvironmentVariables($servicePath)) -Parent
    $expectedPath = Get-CanonicalTestPath (Join-Path $runtimeDirectory 'SbieCtrl.exe')
    $stopped = @()
    foreach ($candidate in @(Get-CimInstance Win32_Process -Filter "Name='SbieCtrl.exe'")) {
        if (-not $candidate.ExecutablePath -or -not [string]::Equals((Get-CanonicalTestPath $candidate.ExecutablePath), $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to terminate a SbieCtrl process outside the verified installed runtime.'
        }
        $process = [Diagnostics.Process]::GetProcessById([int]$candidate.ProcessId)
        try {
            # Retain the handle while verifying its live path and terminating,
            # so a recycled PID cannot select a different process.
            $null = $process.SafeHandle
            $livePath = Get-CanonicalTestPath $process.MainModule.FileName
            if (-not [string]::Equals($livePath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Classic session leader identity changed before termination.'
            }
            $process.Kill()
            if (-not $process.WaitForExit(10000)) { throw 'Verified Classic session leader did not exit.' }
            $stopped += [ordered]@{ pid = $candidate.ProcessId; executable_path = $livePath }
        }
        finally { $process.Dispose() }
    }
    [ordered]@{ timestamp_utc = [DateTime]::UtcNow.ToString('o'); stopped = $stopped; services_or_drivers_stopped = $false; helper_started_by_test = $false } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'cold-session-stopped-processes.json') -Encoding utf8
}

Start-Transcript -LiteralPath (Join-Path $evidenceDirectory 'adapter-transcript.txt') -Force | Out-Null
try {
    $runText = & gh api "repos/$env:GH_REPO/actions/runs/$BuildRunId"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect requested build run.' }
    $run = $runText | ConvertFrom-Json
    if ($run.conclusion -ne 'success' -or $run.name -ne 'DiskGuard Windows x64') { throw 'Requested run is not a successful DiskGuard Windows x64 build.' }
    $downloadDirectory = Join-Path $evidenceDirectory 'ui-artifact'
    & gh run download $BuildRunId --repo $env:GH_REPO --pattern 'diskguard-windows-x64-*' --dir $downloadDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Unable to download requested UI build artifact.' }
    $packages = @(Get-ChildItem -LiteralPath $downloadDirectory -Recurse -Filter '*-portable-ui.zip' -File)
    if ($packages.Count -ne 1) { throw 'Expected exactly one portable UI package.' }
    $extractDirectory = Join-Path $evidenceDirectory 'ui-extracted'
    Expand-Archive -LiteralPath $packages[0].FullName -DestinationPath $extractDirectory
    $application = Join-Path $extractDirectory 'DiskGuard.exe'
    if (-not (Test-Path -LiteralPath $application)) { throw 'Built DiskGuard executable missing from portable package.' }
    $coldResult = $null
    if ($VerifyColdSession) {
        & (Join-Path $PSScriptRoot 'Get-RuntimeProcessEvidence.ps1') -Destination (Join-Path $evidenceDirectory 'processes-before-cold-stop.json')
        Stop-VerifiedClassicSessionLeader
        & (Join-Path $PSScriptRoot 'Get-RuntimeProcessEvidence.ps1') -Destination (Join-Path $evidenceDirectory 'processes-after-cold-stop.json')
        $coldResult = Invoke-ApplicationCheck -Executable $application -Mode '--monitor-unavailable-diagnostics' -Output (Join-Path $evidenceDirectory 'monitor-unavailable-diagnostics.json')
        if (-not $coldResult.success -or -not $coldResult.enforcement_available -or -not $coldResult.monitor_unavailable -or -not $coldResult.policy_roundtrip -or -not $coldResult.status.available -or $coldResult.status.monitoring) {
            throw 'Cold session did not preserve enforcement/policy roundtrip while reporting unavailable monitoring honestly.'
        }
        $coldUi = Invoke-ApplicationCheck -Executable $application -Mode '--ui-smoke-test' -Output (Join-Path $evidenceDirectory 'ui-smoke-cold.json')
        Assert-UiSmoke -Result $coldUi -ExpectedMonitoring $false
        & (Join-Path $PSScriptRoot 'Get-RuntimeProcessEvidence.ps1') -Destination (Join-Path $evidenceDirectory 'processes-after-cold-ui.json')
    }
    $diagnosticsPath = Join-Path $evidenceDirectory 'adapter-diagnostics.json'
    $result = Invoke-ApplicationCheck -Executable $application -Mode '--runtime-diagnostics' -Output $diagnosticsPath
    if (-not $result.success -or -not $result.status.available -or -not $result.monitor_enabled -or -not $result.poll_ok -or $result.records -lt 1 -or $result.attributed_records -lt 1) {
        throw 'Actual Rust adapter did not report successful runtime connection, monitoring, polling and an attributed real file-open record.'
    }
    if (@($result.attribution_sample).Count -lt 1) { throw 'Actual Rust adapter did not provide attributed file-open evidence.' }
    foreach ($record in $result.attribution_sample) {
        if ($record.operation -ne 'file_open' -or [string]::IsNullOrWhiteSpace($record.box_name) -or [string]::IsNullOrWhiteSpace($record.process_name) -or [string]::IsNullOrWhiteSpace($record.path) -or $record.pid -le 0) {
            throw 'Attributed file-open sample lacks a real box, program name, PID or path.'
        }
    }
    & (Join-Path $PSScriptRoot 'Get-RuntimeProcessEvidence.ps1') -Destination (Join-Path $evidenceDirectory 'processes-after-attributed-diagnostics.json')
    $uiSmokePath = Join-Path $evidenceDirectory 'ui-smoke.json'
    $uiResult = Invoke-ApplicationCheck -Executable $application -Mode '--ui-smoke-test' -Output $uiSmokePath
    Assert-UiSmoke -Result $uiResult -ExpectedMonitoring $true
    [ordered]@{
        build_run_id = $BuildRunId
        build_head_sha = $run.head_sha
        build_run_url = $run.html_url
        portable_sha256 = (Get-FileHash -LiteralPath $packages[0].FullName -Algorithm SHA256).Hash
        application_sha256 = (Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash
        cold_session_verified = [bool]$VerifyColdSession
        cold_policy_roundtrip = if ($coldResult) { $coldResult.policy_roundtrip } else { $null }
        attributed_file_open_records = $result.attributed_records
        result = 'PASS: built application runtime adapter connection, monitoring, polling and attributed real file-open event'
        ui_smoke_result = 'PASS: native UI/WebView startup, frontend initialization and backend bridge; visual appearance and user interactions are not assessed'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'adapter-build-provenance.json') -Encoding utf8
}
finally { Stop-Transcript | Out-Null }
