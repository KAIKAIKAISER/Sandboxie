#Requires -Version 7.0
#Requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [switch]$AcknowledgeDisposableVm,
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $AcknowledgeDisposableVm) { throw 'Run only in a disposable Windows 10/11 x64 VM with an installed official signed Sandboxie runtime.' }
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell 7.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $EvidenceDirectory) {
    $EvidenceDirectory = Join-Path $projectRoot ('work/runtime-test-' + [Guid]::NewGuid().ToString('N'))
}
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'EvidenceDirectory must not already exist.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
Start-Transcript -LiteralPath (Join-Path $EvidenceDirectory 'transcript.txt') | Out-Null
$sandboxName = 'DGTest_' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$configCreated = $false
$sbieIni = $null
$sandboxStart = $null
$probe = $null
$runtimeDirectory = $null

function Write-TestStage {
    param([string]$Stage, [string]$State, [object]$Details)
    Write-Host ("STAGE {0}: {1}" -f $Stage, $State)
    [ordered]@{ time_utc = [DateTime]::UtcNow.ToString('o'); stage = $Stage; state = $State; details = $Details } |
        ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath (Join-Path $EvidenceDirectory 'stages.jsonl') -Encoding utf8
}

function Invoke-ProcessChecked {
    param([string]$Path, [string[]]$Arguments, [Parameter(Mandatory)][string]$Stage)
    Write-TestStage -Stage $Stage -State 'starting' -Details @{ executable = $Path; arguments = $Arguments }
    $start = [Diagnostics.ProcessStartInfo]::new($Path)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    try {
        if (-not $process.WaitForExit(120000)) {
            Write-TestStage -Stage $Stage -State 'timeout' -Details @{ pid = $process.Id }
            throw "Stage $Stage timed out waiting for $Path; inspect and stop the test box before retrying."
        }
        $exitCode = $process.ExitCode
        $exitHex = '0x{0:X8}' -f ([long]$exitCode -band 0xFFFFFFFFL)
        Write-TestStage -Stage $Stage -State 'exited' -Details @{ pid = $process.Id; exit_code = $exitCode; exit_hex = $exitHex }
        if ($exitCode -ne 0) { throw "Stage $Stage`: $Path exited with $exitCode ($exitHex)" }
    }
    finally {
        try {
            $stdout = if ($stdoutTask.Wait(3000)) { $stdoutTask.GetAwaiter().GetResult() } else { '[capture incomplete: an inherited pipe remains open]' }
            $stderr = if ($stderrTask.Wait(3000)) { $stderrTask.GetAwaiter().GetResult() } else { '[capture incomplete: an inherited pipe remains open]' }
            Set-Content -LiteralPath (Join-Path $EvidenceDirectory "process-$Stage.stdout.txt") -Value $stdout -Encoding utf8
            Set-Content -LiteralPath (Join-Path $EvidenceDirectory "process-$Stage.stderr.txt") -Value $stderr -Encoding utf8
        }
        finally { $process.Dispose() }
    }
}

function Reset-TestBox {
    param([string]$Stage)
    # The dedicated probe has finished and its parent/child assertions passed.
    # Stop remaining RpcSs/DcomLaunch helpers before changing policy or relaunching:
    # their automatic KillAll shutdown can otherwise catch the next quick launch.
    Invoke-ProcessChecked -Path $sandboxStart -Arguments @("/box:$sandboxName", '/silent', '/terminate') -Stage "$Stage-terminate-helpers"
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $consecutiveEmpty = 0
    do {
        $lines = @(& $sandboxStart "/box:$sandboxName" /silent /listpids | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        $count = -1
        if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 1 -or -not [int]::TryParse($lines[0], [ref]$count) -or $count -lt 0 -or $lines.Count -ne ($count + 1)) {
            throw "Stage $Stage could not reliably enumerate the dedicated test box."
        }
        if ($count -eq 0) { $consecutiveEmpty++ } else { $consecutiveEmpty = 0 }
        if ($consecutiveEmpty -ge 3) {
            Write-TestStage -Stage $Stage -State 'box-stably-empty' -Details @{ box = $sandboxName }
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Stage $Stage`: dedicated test box did not stop before the next policy transition."
}

function Set-VerifiedSetting {
    param([string]$Name, [string[]]$Values)
    & $sbieIni set $sandboxName $Name
    if ($LASTEXITCODE -ne 0) { throw "SbieIni failed clearing $Name" }
    foreach ($value in $Values) {
        & $sbieIni append $sandboxName $Name $value
        if ($LASTEXITCODE -ne 0) { throw "SbieIni failed appending $Name" }
    }
    # SbieIni exits 0 for several service errors: exact readback is mandatory.
    $actual = @(& $sbieIni query $sandboxName $Name | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' })
    if ($LASTEXITCODE -ne 0 -or ($actual -join "`n") -cne ($Values -join "`n")) {
        throw "Configuration readback mismatch: $Name"
    }
    Write-TestStage -Stage 'configuration' -State 'readback-verified' -Details @{ setting = $Name; values = $actual }
}

function Assert-Probe {
    param([string]$ResultPath, [string]$ExpectedBox, [bool]$Denied)
    # ForceProcess may hand off to a separately started sandboxed replacement;
    # the original host process handle can exit before its evidence is written.
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not ((Test-Path -LiteralPath $ResultPath) -and (Test-Path -LiteralPath "$ResultPath.child.json"))) {
        if ([DateTime]::UtcNow -ge $deadline) { throw "Probe parent/child evidence was not produced within 60 seconds: $ResultPath" }
        Start-Sleep -Milliseconds 200
    }
    foreach ($path in @($ResultPath, "$ResultPath.child.json")) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Probe evidence missing: $path" }
        $result = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($result.box_name -cne $ExpectedBox) { throw "Process $($result.pid) ran in '$($result.box_name)', expected '$ExpectedBox'" }
        if (-not $result.allowed_file.open_succeeded -or -not $result.allowed_file.read_succeeded -or $result.allowed_file.bytes_read -ne 1) {
            throw "Allowed fixture read failed: $path"
        }
        if (-not $result.sibling_file.open_succeeded -or -not $result.sibling_file.read_succeeded -or $result.sibling_file.bytes_read -ne 1) {
            throw "An adjacent directory sharing the blacklist path prefix was incorrectly blocked: $path"
        }
        if ($Denied) {
            if ($result.denied_file.open_succeeded -or $result.denied_file.read_succeeded) { throw "Private fixture was readable: $path" }
            if ($result.denied_file.error -notin @('UnauthorizedAccessException', 'FileNotFoundException', 'DirectoryNotFoundException')) {
                throw "Unexpected deny error: $($result.denied_file.error)"
            }
            if ($result.directory_enumeration.succeeded -and $result.directory_enumeration.entry_count -gt 0) {
                throw "Private directory leaked entries: $path"
            }
            if (-not $result.directory_enumeration.succeeded -and $result.directory_enumeration.error -notin @('UnauthorizedAccessException', 'DirectoryNotFoundException')) {
                throw "Unexpected enumeration error: $($result.directory_enumeration.error)"
            }
        }
        elseif (-not $result.denied_file.read_succeeded -or -not $result.directory_enumeration.succeeded -or $result.directory_enumeration.entry_count -lt 1) {
            throw "Baseline fixture operations failed: $path"
        }
        if (-not $result.is_child -and $result.child_exit_code -ne 0) { throw 'Child probe failed.' }
    }
}

try {
    $service = Get-CimInstance Win32_Service -Filter "Name='SbieSvc'"
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='SbieDrv'"
    if (-not $service -or $service.State -ne 'Running' -or -not $driver -or $driver.State -ne 'Running') {
        throw 'A running official signed SbieSvc/SbieDrv installation is required; this is not a skipped/pass result.'
    }
    $serviceImage = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieSvc' -Name ImagePath).ImagePath
    $servicePath = if ($serviceImage.StartsWith('"')) { $serviceImage.Split('"')[1] } else { $serviceImage }
    $runtimeDirectory = Split-Path -Path ([Environment]::ExpandEnvironmentVariables($servicePath)) -Parent
    $sbieIni = Join-Path $runtimeDirectory 'SbieIni.exe'
    $sandboxStart = Join-Path $runtimeDirectory 'Start.exe'
    foreach ($name in @('SbieDll.dll', 'SbieSvc.exe', 'Start.exe', 'SbieIni.exe')) {
        $file = Join-Path $runtimeDirectory $name
        if (-not (Test-Path -LiteralPath $file)) { throw "Missing runtime file $file" }
    }
    $driverPath = [Environment]::ExpandEnvironmentVariables($driver.PathName.Trim('"'))
    if ($driverPath.StartsWith('\??\')) { $driverPath = $driverPath.Substring(4) }
    if ($driverPath.StartsWith('\SystemRoot\')) { $driverPath = Join-Path $env:SystemRoot $driverPath.Substring(12) }
    $signature = Get-AuthenticodeSignature -LiteralPath $driverPath
    if ($signature.Status -ne 'Valid') { throw "Driver signature is not Valid: $($signature.Status). Do not disable Windows signature enforcement." }
    $runtimeEvidence = [ordered]@{
        os = [Environment]::OSVersion.VersionString
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        runtime_directory = $runtimeDirectory
        dll_version = (Get-Item -LiteralPath (Join-Path $runtimeDirectory 'SbieDll.dll')).VersionInfo.FileVersion
        driver_path = $driverPath
        driver_sha256 = (Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash
        driver_signature_status = $signature.Status.ToString()
        driver_signer = $signature.SignerCertificate.Subject
        test_box = $sandboxName
    }
    $runtimeEvidence | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'runtime.json') -Encoding utf8

    $probeDirectory = Join-Path $EvidenceDirectory 'probe'
    & dotnet publish (Join-Path $PSScriptRoot 'probe/RuntimeProbe.csproj') -c Release -r win-x64 --self-contained true -o $probeDirectory --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Probe build failed.' }
    $probe = Join-Path $probeDirectory 'DiskGuardRuntimeProbe.exe'
    $privateDirectory = Join-Path $EvidenceDirectory 'private'
    $siblingDirectory = $privateDirectory + 'Sibling'
    $resultDirectory = Join-Path $EvidenceDirectory 'results'
    New-Item -ItemType Directory -Path $privateDirectory, $siblingDirectory, $resultDirectory | Out-Null
    Set-Content -LiteralPath (Join-Path $privateDirectory 'private.txt') -Value 'private-fixture' -Encoding utf8
    Set-Content -LiteralPath (Join-Path $siblingDirectory 'public.txt') -Value 'sibling-fixture' -Encoding utf8
    $allowedFile = Join-Path $EvidenceDirectory 'allowed.txt'
    Set-Content -LiteralPath $allowedFile -Value 'allowed-fixture' -Encoding utf8
    $baseline = Join-Path $resultDirectory 'baseline.json'
    Invoke-ProcessChecked -Path $probe -Arguments @($privateDirectory, $allowedFile, $baseline) -Stage 'baseline'
    Assert-Probe -ResultPath $baseline -ExpectedBox '' -Denied $false
    Write-TestStage -Stage 'baseline' -State 'assertions-passed' -Details $null

    $configCreated = $true
    Set-VerifiedSetting -Name 'Enabled' -Values @('y')
    Set-VerifiedSetting -Name 'FileRootPath' -Values @((Join-Path $EvidenceDirectory 'sandbox'))
    Set-VerifiedSetting -Name 'FileTrace' -Values @('ad')
    Set-VerifiedSetting -Name 'OpenFilePath' -Values @("|$resultDirectory", "$resultDirectory\*")

    $monitorOnly = Join-Path $resultDirectory 'monitor-only-launch.json'
    Invoke-ProcessChecked -Path $sandboxStart -Arguments @("/box:$sandboxName", '/silent', '/wait', $probe, $privateDirectory, $allowedFile, $monitorOnly) -Stage 'monitor-only'
    Assert-Probe -ResultPath $monitorOnly -ExpectedBox $sandboxName -Denied $false
    Write-TestStage -Stage 'monitor-only' -State 'assertions-passed' -Details $null
    Reset-TestBox -Stage 'after-monitor-only'

    Set-VerifiedSetting -Name 'ClosedFilePath' -Values @("|$privateDirectory", "$privateDirectory\*")

    $explicit = Join-Path $resultDirectory 'explicit-launch.json'
    Invoke-ProcessChecked -Path $sandboxStart -Arguments @("/box:$sandboxName", '/silent', '/wait', $probe, $privateDirectory, $allowedFile, $explicit) -Stage 'blacklist'
    Assert-Probe -ResultPath $explicit -ExpectedBox $sandboxName -Denied $true
    Write-TestStage -Stage 'blacklist' -State 'assertions-passed' -Details $null
    Reset-TestBox -Stage 'after-blacklist'

    Set-VerifiedSetting -Name 'ClosedFilePath' -Values @()
    $disabledRules = Join-Path $resultDirectory 'disabled-rules-launch.json'
    Invoke-ProcessChecked -Path $sandboxStart -Arguments @("/box:$sandboxName", '/silent', '/wait', $probe, $privateDirectory, $allowedFile, $disabledRules) -Stage 'disabled-rules'
    Assert-Probe -ResultPath $disabledRules -ExpectedBox $sandboxName -Denied $false
    Write-TestStage -Stage 'disabled-rules' -State 'assertions-passed' -Details $null
    Reset-TestBox -Stage 'after-disabled-rules'
    Set-VerifiedSetting -Name 'ClosedFilePath' -Values @("|$privateDirectory", "$privateDirectory\*")

    # Upstream treats a full path without a wildcard as a folder; a trailing
    # wildcard selects its full-path pattern matcher for this dedicated probe.
    Set-VerifiedSetting -Name 'ForceProcess' -Values @("$probe*")
    Set-VerifiedSetting -Name 'ForceChildren' -Values @("$probe*")
    $forced = Join-Path $resultDirectory 'forced-launch.json'
    Invoke-ProcessChecked -Path $probe -Arguments @($privateDirectory, $allowedFile, $forced) -Stage 'forced'
    Assert-Probe -ResultPath $forced -ExpectedBox $sandboxName -Denied $true
    Write-TestStage -Stage 'forced' -State 'assertions-passed' -Details $null
    Reset-TestBox -Stage 'after-forced'
}
finally {
    try {
        if ($probe -and (Test-Path -LiteralPath $probe) -and $runtimeDirectory) {
            try {
                $messageReader = Join-Path (Split-Path -Parent $probe) 'DiskGuardMessageReader.exe'
                Copy-Item -LiteralPath $probe -Destination $messageReader
                Invoke-ProcessChecked -Path $messageReader -Arguments @('--messages', (Join-Path $runtimeDirectory 'SbieDll.dll'), (Join-Path $EvidenceDirectory 'sandboxie-messages.json')) -Stage 'collect-sandboxie-messages'
            }
            catch { Write-Warning "Sandboxie message capture failed: $($_.Exception.Message)" }
        }
        if ($configCreated -and $sbieIni) {
            & $sbieIni set $sandboxName '*'
            $remaining = @(& $sbieIni query '*' | ForEach-Object { $_.Trim() })
            if ($LASTEXITCODE -ne 0 -or $remaining -contains $sandboxName) {
                throw "Cleanup could not verify removal of $sandboxName. Remove this test section before reusing the VM."
            }
        }
    }
    finally { Stop-Transcript | Out-Null }
}
'PASS: baseline, monitor-only, deny rules, disabled rules, denied open/read, private enumeration concealment, allowed and sibling-prefix reads, explicit launch, forced launch, child association and test configuration cleanup.' | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'RESULT.txt') -Encoding utf8
Write-Host "PASS. Evidence retained in $EvidenceDirectory"
