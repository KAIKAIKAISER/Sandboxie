#Requires -Version 7.0
#Requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildRunId,
    [Parameter(Mandatory)][ValidateSet('installer', 'portable')][string]$PackageMode
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Integrated installation tests run only on a disposable GitHub-hosted Windows VM, never a developer workstation.'
}
if ($BuildRunId -notmatch '^[0-9]+$') { throw 'BuildRunId must be numeric.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidenceDirectory = Join-Path $projectRoot "work/integrated-runtime-$PackageMode"
if (Test-Path -LiteralPath $evidenceDirectory) { throw 'Refusing stale integrated-install evidence.' }
New-Item -ItemType Directory -Path $evidenceDirectory | Out-Null
$sentinelSection = $null
$sbieIni = $null
$finalResult = $null

function Write-Stage {
    param([string]$Name, [string]$State, [object]$Details)
    Write-Host "$Name`: $State"
    [ordered]@{ timestamp_utc = [DateTime]::UtcNow.ToString('o'); stage = $Name; state = $State; details = $Details } |
        ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath (Join-Path $evidenceDirectory 'stages.jsonl') -Encoding utf8
}

function Invoke-TestProcess {
    param([string]$Path, [string[]]$Arguments, [string]$RawArguments, [string]$Stage, [int]$TimeoutSeconds = 300, [switch]$ExpectFailure)
    Write-Stage $Stage 'starting' @{ executable = $Path; arguments = $Arguments; raw_arguments = $RawArguments }
    $start = [Diagnostics.ProcessStartInfo]::new($Path)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    if ($RawArguments) { $start.Arguments = $RawArguments }
    else { foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) } }
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) { throw "Stage $Stage timed out; this disposable VM will be discarded." }
        Write-Stage $Stage 'exited' @{ pid = $process.Id; exit_code = $process.ExitCode }
        if ($ExpectFailure -and $process.ExitCode -eq 0) { throw "Stage $Stage accepted a deliberately damaged test package." }
        if (-not $ExpectFailure -and $process.ExitCode -ne 0) {
            throw "Stage $Stage exited with $($process.ExitCode). Cancellation and reboot-required are not a completed integration test."
        }
    }
    finally { $process.Dispose() }
}

function Read-InstallReport {
    param([string]$Path, [string]$ExpectedOutcome, [string]$EvidenceName)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Native runtime installer did not produce its receipt: $Path" }
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($report.outcome -cne $ExpectedOutcome -or -not $report.driverAvailable -or $report.rebootRequired) {
        throw "Unexpected native runtime installation outcome: $($report.outcome)"
    }
    if ($null -ne $report.exitCode -and $report.exitCode -ne 0) { throw 'Native report contains an unsuccessful official installer exit code.' }
    Copy-Item -LiteralPath $Path -Destination (Join-Path $evidenceDirectory $EvidenceName)
    return $report
}

function Get-RuntimeSnapshot {
    param([string]$EvidenceName)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $service = Get-CimInstance Win32_Service -Filter "Name='SbieSvc'"
        $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='SbieDrv'"
        if ($service -and $service.State -eq 'Running' -and $driver -and $driver.State -eq 'Running') { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'The DiskGuard package did not automatically leave SbieSvc and SbieDrv running. The test will not start them itself.' }
        Start-Sleep -Milliseconds 250
    } while ($true)
    $image = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieSvc' -Name ImagePath).ImagePath
    $servicePath = if ($image.StartsWith('"')) { $image.Split('"')[1] } else { $image }
    $runtimeDirectory = Split-Path -Path ([Environment]::ExpandEnvironmentVariables($servicePath)) -Parent
    $driverPath = [Environment]::ExpandEnvironmentVariables($driver.PathName.Trim('"'))
    if ($driverPath.StartsWith('\??\')) { $driverPath = $driverPath.Substring(4) }
    if ($driverPath.StartsWith('\SystemRoot\')) { $driverPath = Join-Path $env:SystemRoot $driverPath.Substring(12) }
    $signature = Get-AuthenticodeSignature -LiteralPath $driverPath
    if ($signature.Status -ne 'Valid') { throw "Installed driver is not Windows-trusted: $($signature.Status)" }
    $binaryHashes = [ordered]@{}
    foreach ($name in @('SbieSvc.exe', 'SbieDrv.sys', 'SbieDll.dll', 'Start.exe', 'SbieIni.exe', 'SbieCtrl.exe')) {
        $binaryHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $runtimeDirectory $name) -Algorithm SHA256).Hash
    }
    $configuration = Join-Path $env:WINDIR 'Sandboxie.ini'
    $snapshot = [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        runtime_directory = $runtimeDirectory
        service_state = $service.State
        service_pid = $service.ProcessId
        service_image = $image
        driver_state = $driver.State
        driver_path = $driverPath
        driver_signature = $signature.Status.ToString()
        driver_signer = $signature.SignerCertificate.Subject
        binary_sha256 = $binaryHashes
        configuration_sha256 = if (Test-Path -LiteralPath $configuration) { (Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash } else { $null }
    }
    $snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidenceDirectory $EvidenceName) -Encoding utf8
    return $snapshot
}

Start-Transcript -LiteralPath (Join-Path $evidenceDirectory 'transcript.txt') | Out-Null
try {
    & (Join-Path $PSScriptRoot 'Get-RuntimeProcessEvidence.ps1') -Destination (Join-Path $evidenceDirectory 'processes-before-install.json')
    if ((Get-Service -Name SbieSvc -ErrorAction SilentlyContinue) -or (Get-CimInstance Win32_SystemDriver -Filter "Name='SbieDrv'")) {
        throw 'This test requires a fresh VM without any pre-existing Sandboxie service or driver registration.'
    }
    $runText = & gh api "repos/$env:GH_REPO/actions/runs/$BuildRunId"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect requested build run.' }
    $run = $runText | ConvertFrom-Json
    if ($run.name -cne 'DiskGuard Windows x64') { throw 'Requested run is not the DiskGuard build workflow.' }
    if ($BuildRunId -eq $env:GITHUB_RUN_ID) {
        if ($run.head_sha -cne $env:GITHUB_SHA) { throw 'Reusable installation test source differs from the build source.' }
        $jobsText = & gh api "repos/$env:GH_REPO/actions/runs/$BuildRunId/jobs?filter=latest&per_page=100"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect the build job.' }
        $jobs = $jobsText | ConvertFrom-Json
        if (@($jobs.jobs | Where-Object { $_.name -ceq 'build' -and $_.status -eq 'completed' -and $_.conclusion -eq 'success' }).Count -ne 1) {
            throw 'Reusable tests require the build job to have completed successfully.'
        }
    }
    elseif ($run.status -ne 'completed' -or $run.conclusion -ne 'success') {
        throw 'Manually selected build run must have completed successfully.'
    }
    $packageDirectory = Join-Path $evidenceDirectory 'build-artifact'
    & gh run download $BuildRunId --repo $env:GH_REPO --name "diskguard-windows-x64-$($run.head_sha)" --dir $packageDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Build artifact download failed.' }
    foreach ($line in Get-Content -LiteralPath (Join-Path $packageDirectory 'SHA256SUMS.txt')) {
        if ($line -notmatch '^([a-fA-F0-9]{64})  (.+)$') { throw 'Malformed build checksum entry.' }
        $expected = $Matches[1]
        $name = $Matches[2]
        if ([IO.Path]::GetFileName($name) -cne $name) { throw 'Build checksum target escapes the artifact directory.' }
        if ((Get-FileHash -LiteralPath (Join-Path $packageDirectory $name) -Algorithm SHA256).Hash -ine $expected) { throw "Checksum mismatch: $name" }
    }
    $manifest = Get-Content -LiteralPath (Join-Path $packageDirectory 'BUILD-MANIFEST.json') -Raw | ConvertFrom-Json
    if ($manifest.source_commit -cne $run.head_sha -or -not $manifest.runtime_bundled) { throw 'Build manifest is not the selected source with a bundled runtime.' }
    $runtimeLock = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'runtime.lock.json') -Raw | ConvertFrom-Json
    $portablePackages = @(Get-ChildItem -LiteralPath $packageDirectory -Filter '*-portable*.zip' -File)
    $installers = @(Get-ChildItem -LiteralPath $packageDirectory -Filter '*-setup.exe' -File)
    if ($portablePackages.Count -ne 1 -or $installers.Count -ne 1) { throw 'Expected one installer and one portable archive.' }
    $installDirectory = Join-Path $env:RUNNER_TEMP "DiskGuard Integrated $PackageMode"
    $defaultReport = Join-Path $env:LOCALAPPDATA 'DiskGuard/runtime-install.json'
    if (Test-Path -LiteralPath $defaultReport) { throw 'Unexpected pre-existing DiskGuard runtime installation receipt.' }
    if ($PackageMode -eq 'installer') {
        # NSIS requires /D last and unquoted, even when its value has spaces.
        Invoke-TestProcess -Path $installers[0].FullName -RawArguments "/S /D=$installDirectory" -Stage 'install-diskguard-package'
        $application = Join-Path $installDirectory 'diskguard.exe'
        $firstReport = Read-InstallReport -Path $defaultReport -ExpectedOutcome 'installed' -EvidenceName 'first-install-report.json'
    }
    else {
        Expand-Archive -LiteralPath $portablePackages[0].FullName -DestinationPath $installDirectory
        $application = Join-Path $installDirectory 'DiskGuard.exe'
        # Mutate only a disposable copy. The original extracted package stays
        # intact for the positive installation, and no runtime is preinstalled.
        $tamperedDirectory = Join-Path $env:RUNNER_TEMP 'DiskGuard Tampered Portable'
        if (Test-Path -LiteralPath $tamperedDirectory) { throw 'Refusing a stale tamper-test directory.' }
        Copy-Item -LiteralPath $installDirectory -Destination $tamperedDirectory -Recurse
        $tamperedPayload = Join-Path $tamperedDirectory "runtime/$($runtimeLock.asset)"
        $stream = [IO.File]::Open($tamperedPayload, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $originalByte = $stream.ReadByte()
            $stream.Position = 0
            $stream.WriteByte([byte]($originalByte -bxor 1))
        }
        finally { $stream.Dispose() }
        $tamperedReport = Join-Path $evidenceDirectory 'tampered-payload-report.json'
        Invoke-TestProcess -Path (Join-Path $tamperedDirectory 'DiskGuard.exe') -Arguments @('--install-bundled-runtime', '--report', $tamperedReport) -Stage 'reject-tampered-runtime-payload' -ExpectFailure
        $rejection = Get-Content -LiteralPath $tamperedReport -Raw | ConvertFrom-Json
        if ($rejection.outcome -cne 'failed' -or $rejection.driverAvailable -or (Get-Service -Name SbieSvc -ErrorAction SilentlyContinue) -or (Get-CimInstance Win32_SystemDriver -Filter "Name='SbieDrv'")) {
            throw 'The damaged test payload was not rejected before runtime registration.'
        }
        Write-Stage 'tampered-runtime-payload' 'rejected-before-installation' @{ outcome = $rejection.outcome; no_service_or_driver = $true }
        $portableReport = Join-Path $evidenceDirectory 'portable-first-install.json'
        Invoke-TestProcess -Path $application -Arguments @('--install-bundled-runtime', '--report', $portableReport) -Stage 'install-runtime-from-portable'
        $firstReport = Read-InstallReport -Path $portableReport -ExpectedOutcome 'installed' -EvidenceName 'first-install-report.json'
    }
    if (-not (Test-Path -LiteralPath $application)) { throw 'Installed/extracted DiskGuard executable is missing.' }
    $bundledInstaller = Join-Path $installDirectory "runtime/$($runtimeLock.asset)"
    if ((Get-FileHash -LiteralPath $bundledInstaller -Algorithm SHA256).Hash -ine $runtimeLock.sha256) { throw 'Bundled official runtime payload hash mismatch.' }
    $payloadSignature = Get-AuthenticodeSignature -LiteralPath $bundledInstaller
    if ($payloadSignature.Status -ne 'Valid') { throw 'Bundled official installer is not Windows-trusted.' }
    $installedLock = Get-Content -LiteralPath (Join-Path $installDirectory 'runtime/runtime.lock.json') -Raw | ConvertFrom-Json
    if ($installedLock.sha256 -cne $runtimeLock.sha256 -or $installedLock.asset -cne $runtimeLock.asset) { throw 'Installed runtime lockfile does not match the audited build lock.' }
    foreach ($name in @('runtime/NOTICE.md', 'THIRD-PARTY-NOTICES.md', 'README-runtime.md')) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDirectory $name))) { throw "Required installed notice missing: $name" }
    }
    if (-not ((Test-Path -LiteralPath (Join-Path $installDirectory 'LICENSE.txt')) -or (Test-Path -LiteralPath (Join-Path $installDirectory 'LICENSE.GPL-3.0.txt')))) {
        throw 'The package does not contain its GPL license text.'
    }
    $initial = Get-RuntimeSnapshot -EvidenceName 'runtime-after-first-install.json'
    Write-Stage 'automatic-runtime-deployment' 'verified' @{ driver = 'Running'; service = 'Running'; driver_signature = 'Valid'; outcome = $firstReport.outcome }
    & (Join-Path $PSScriptRoot 'Get-RuntimeProcessEvidence.ps1') -Destination (Join-Path $evidenceDirectory 'processes-after-install.json')

    # A harmless unique setting proves reinstallation preserves real shared
    # configuration as well as runtime binaries, rather than merely returning 0.
    $sbieIni = Join-Path $initial.runtime_directory 'SbieIni.exe'
    $sentinelSection = 'DGInstall_' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $sentinel = [Guid]::NewGuid().ToString('N')
    & $sbieIni set $sentinelSection Enabled n
    & $sbieIni set $sentinelSection DiskGuardInstallSentinel $sentinel
    $readback = @(& $sbieIni query $sentinelSection DiskGuardInstallSentinel)
    if ($LASTEXITCODE -ne 0 -or ($readback -join '').Trim() -cne $sentinel) { throw 'Could not verify the configuration preservation fixture.' }
    $beforeRepeat = Get-RuntimeSnapshot -EvidenceName 'runtime-before-repeat.json'
    if ($PackageMode -eq 'installer') {
        Invoke-TestProcess -Path $installers[0].FullName -RawArguments "/S /D=$installDirectory" -Stage 'repeat-diskguard-package-install'
        $repeatReport = Read-InstallReport -Path $defaultReport -ExpectedOutcome 'alreadyInstalled' -EvidenceName 'repeat-install-report.json'
    }
    else {
        $repeatPath = Join-Path $evidenceDirectory 'portable-repeat-install.json'
        Invoke-TestProcess -Path $application -Arguments @('--install-bundled-runtime', '--report', $repeatPath) -Stage 'repeat-portable-runtime-install'
        $repeatReport = Read-InstallReport -Path $repeatPath -ExpectedOutcome 'alreadyInstalled' -EvidenceName 'repeat-install-report.json'
    }
    $afterRepeat = Get-RuntimeSnapshot -EvidenceName 'runtime-after-repeat.json'
    if (($beforeRepeat.binary_sha256 | ConvertTo-Json -Compress) -cne ($afterRepeat.binary_sha256 | ConvertTo-Json -Compress) -or $beforeRepeat.configuration_sha256 -cne $afterRepeat.configuration_sha256 -or $beforeRepeat.service_pid -ne $afterRepeat.service_pid) {
        throw 'Repeating the integrated installation changed existing runtime binaries, configuration, or the primary service process.'
    }
    $readback = @(& $sbieIni query $sentinelSection DiskGuardInstallSentinel)
    if ($LASTEXITCODE -ne 0 -or ($readback -join '').Trim() -cne $sentinel) { throw 'Existing configuration fixture was not preserved.' }
    Write-Stage 'existing-runtime-preservation' 'verified' @{ outcome = $repeatReport.outcome; binary_hashes_unchanged = $true; configuration_unchanged = $true; service_pid_unchanged = $true }

    $diagnosticPath = Join-Path $evidenceDirectory 'application-runtime-diagnostics.json'
    Invoke-TestProcess -Path $application -Arguments @('--runtime-diagnostics', $diagnosticPath) -Stage 'installed-application-native-adapter' -TimeoutSeconds 90
    $diagnostic = Get-Content -LiteralPath $diagnosticPath -Raw | ConvertFrom-Json
    if (-not $diagnostic.success -or -not $diagnostic.status.available -or $diagnostic.attributed_records -lt 1) { throw 'Installed application did not verify its actual native runtime adapter and attributed file-open events.' }
    $uiPath = Join-Path $evidenceDirectory 'ui-smoke.json'
    Invoke-TestProcess -Path $application -Arguments @('--ui-smoke-test', $uiPath, '--background') -Stage 'installed-application-ui' -TimeoutSeconds 90
    $ui = Get-Content -LiteralPath $uiPath -Raw | ConvertFrom-Json
    if (-not $ui.success -or -not $ui.frontend_initialized -or -not $ui.backend_invoked -or -not $ui.runtime.driverAvailable) { throw 'Installed application native UI startup/bridge failed.' }
    $pwshPath = (Get-Process -Id $PID).Path
    Invoke-TestProcess -Path $pwshPath -Arguments @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'Test-Runtime.ps1'), '-AcknowledgeDisposableVm', '-EvidenceDirectory', (Join-Path $evidenceDirectory 'enforcement')) -Stage 'independent-access-control-probe'

    $finalResult = [ordered]@{
        success = $true
        package_mode = $PackageMode
        source_commit = $run.head_sha
        build_run_id = $BuildRunId
        build_run_url = $run.html_url
        os = [Environment]::OSVersion.VersionString
        package_sha256 = (Get-FileHash -LiteralPath $(if ($PackageMode -eq 'installer') { $installers[0].FullName } else { $portablePackages[0].FullName }) -Algorithm SHA256).Hash
        application_sha256 = (Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash
        bundled_runtime_sha256 = (Get-FileHash -LiteralPath $bundledInstaller -Algorithm SHA256).Hash
        payload_signature = $payloadSignature.Status.ToString()
        automatic_deployment = $true
        existing_runtime_preserved = $true
        runtime_preinstalled_by_test = $false
        driver_signing_settings_changed = $false
        validation_scope = 'Fresh hosted Windows Server 2022 package installation, native adapter/UI bridge, idempotence and file-access probes; Windows 10/11 client and interactive UAC acceptance remain separate validation.'
    }
}
finally {
    try {
        if ($sentinelSection -and $sbieIni -and (Test-Path -LiteralPath $sbieIni)) {
            & $sbieIni set $sentinelSection '*'
            $sections = @(& $sbieIni query '*')
            if ($LASTEXITCODE -ne 0 -or $sections -contains $sentinelSection) { throw "Could not remove the dedicated installation test section $sentinelSection" }
        }
    }
    finally { Stop-Transcript | Out-Null }
}
$finalResult | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'RESULT.json') -Encoding utf8
Write-Stage 'integrated-runtime-test' 'passed' $null
