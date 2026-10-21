#Requires -Version 7.0
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BuildRunId)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Built adapter diagnostics must run on the disposable GitHub-hosted Windows runtime test VM.'
}
if ($BuildRunId -notmatch '^[0-9]+$') { throw 'BuildRunId must be a numeric GitHub Actions run ID.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidenceDirectory = Join-Path $projectRoot 'work/hosted-runtime'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
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
    $diagnosticsPath = Join-Path $evidenceDirectory 'adapter-diagnostics.json'
    $process = Start-Process -FilePath $application -ArgumentList @('--runtime-diagnostics', ('"' + $diagnosticsPath + '"')) -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit(60000)) { throw 'Built application adapter diagnostics timed out.' }
        if ($process.ExitCode -ne 0) { throw "Built application adapter diagnostics exited with $($process.ExitCode)." }
    }
    finally { $process.Dispose() }
    if (-not (Test-Path -LiteralPath $diagnosticsPath)) { throw 'Built application did not write adapter diagnostics.' }
    $result = Get-Content -LiteralPath $diagnosticsPath -Raw | ConvertFrom-Json
    if (-not $result.success -or -not $result.status.available -or -not $result.monitor_enabled -or -not $result.poll_ok -or $result.records -lt 1) {
        throw 'Actual Rust adapter did not report successful runtime connection, monitor activation, polling and at least one parsed real event.'
    }
    $uiSmokePath = Join-Path $evidenceDirectory 'ui-smoke.json'
    $uiProcess = Start-Process -FilePath $application -ArgumentList @('--ui-smoke-test', ('"' + $uiSmokePath + '"'), '--background') -WindowStyle Hidden -PassThru
    try {
        if (-not $uiProcess.WaitForExit(60000)) { throw 'Built application native UI/WebView bridge smoke test timed out.' }
        if ($uiProcess.ExitCode -ne 0) { throw "Built application UI smoke test exited with $($uiProcess.ExitCode)." }
    }
    finally { $uiProcess.Dispose() }
    if (-not (Test-Path -LiteralPath $uiSmokePath)) { throw 'Built application did not write native UI smoke test evidence.' }
    $uiResult = Get-Content -LiteralPath $uiSmokePath -Raw | ConvertFrom-Json
    if (-not $uiResult.success -or -not $uiResult.frontend_initialized -or -not $uiResult.backend_invoked) {
        throw 'Built application frontend did not complete real state retrieval, initialization and native bridge invocation.'
    }
    [ordered]@{
        build_run_id = $BuildRunId
        build_head_sha = $run.head_sha
        build_run_url = $run.html_url
        portable_sha256 = (Get-FileHash -LiteralPath $packages[0].FullName -Algorithm SHA256).Hash
        application_sha256 = (Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash
        result = 'PASS: built application runtime adapter connection, monitor enable, poll and parsed real event'
        ui_smoke_result = 'PASS: native UI/WebView startup, frontend initialization and backend bridge; visual appearance and user interactions are not assessed'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'adapter-build-provenance.json') -Encoding utf8
}
finally { Stop-Transcript | Out-Null }
