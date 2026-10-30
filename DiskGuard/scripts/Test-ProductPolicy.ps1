#Requires -Version 7.0
#Requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Application,
    [Parameter(Mandatory)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Run only on a disposable GitHub-hosted Windows VM.'
}
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Refusing stale product test evidence.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$stateDirectory = Join-Path $env:RUNNER_TEMP "DiskGuard-product-test-$suffix"
$box = "DiskGuard_Test_$suffix"
$image = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieSvc').ImagePath
$servicePath = if ($image.StartsWith('"')) { $image.Split('"')[1] } else { $image }
$runtime = Split-Path ([Environment]::ExpandEnvironmentVariables($servicePath)) -Parent
$ini = Join-Path $runtime 'SbieIni.exe'
$start = Join-Path $runtime 'Start.exe'
$results = Join-Path $EvidenceDirectory 'results'
$private = Join-Path $EvidenceDirectory 'private'
$allowed = Join-Path $EvidenceDirectory 'allowed.txt'
New-Item -ItemType Directory -Path $stateDirectory, $results, $private, ($private + 'Sibling') | Out-Null
Set-Content (Join-Path $private 'private.txt') 'private'
Set-Content (Join-Path ($private + 'Sibling') 'public.txt') 'public'
Set-Content $allowed 'allowed'
$created = $false
$result = $null

function Invoke-CheckedProcess {
    param([string]$Executable, [string[]]$Arguments)
    $info = [Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($info)
    try {
        if (-not $process.WaitForExit(120000)) { throw 'Product test process timed out; discard this VM.' }
        if ($process.ExitCode -ne 0) { throw "Product test process failed: $Executable ($($process.ExitCode))" }
    } finally { $process.Dispose() }
}
function Invoke-Product {
    param([string]$Stage, [string]$Action, [object]$Config)
    $request = Join-Path $EvidenceDirectory "$Stage-request.json"
    $report = Join-Path $EvidenceDirectory "$Stage-report.json"
    @{ directory=$stateDirectory; action=$Action; config=$Config; appId='probe' } | ConvertTo-Json -Depth 10 | Set-Content $request
    Invoke-CheckedProcess $Application @('--product-policy-test', $request, $report)
    $result = Get-Content $report -Raw | ConvertFrom-Json
    if (-not $result.success -or $result.state.configurationError) { throw "Product command failed: $Stage" }
    return $result.state
}
function Assert-Probe {
    param([string]$Name, [bool]$Denied, [bool]$Forced)
    $output = Join-Path $results "$Name.json"
    if ($Forced) { Invoke-CheckedProcess $probe @($private, $allowed, $output) }
    else { Invoke-CheckedProcess $start @("/box:$box", '/silent', '/wait', $probe, $private, $allowed, $output) }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    foreach ($file in @($output, "$output.child.json")) {
        while (-not (Test-Path -LiteralPath $file)) {
            if ([DateTime]::UtcNow -gt $deadline) { throw "Missing product probe evidence: $file" }
            Start-Sleep -Milliseconds 100
        }
        $r = Get-Content $file -Raw | ConvertFrom-Json
        if ($r.box_name -cne $box -or (-not $r.is_child -and $r.child_exit_code -ne 0)) { throw 'Product sandbox/child attribution failed.' }
        foreach ($read in @($r.allowed_file, $r.sibling_file)) {
            if (-not $read.open_succeeded -or -not $read.read_succeeded -or $read.bytes_read -ne 1) { throw 'Product policy overblocked allowed/sibling fixture.' }
        }
        if ($Denied) {
            if ($r.denied_file.open_succeeded -or $r.denied_file.read_succeeded -or ($r.directory_enumeration.succeeded -and $r.directory_enumeration.entry_count -gt 0)) { throw 'Product blacklist leaked private file/directory.' }
            if ($r.denied_file.error -notin @('UnauthorizedAccessException', 'FileNotFoundException', 'DirectoryNotFoundException')) { throw 'Unexpected private-file error.' }
            if (-not $r.directory_enumeration.succeeded -and $r.directory_enumeration.error -notin @('UnauthorizedAccessException', 'DirectoryNotFoundException')) { throw 'Unexpected private-directory error.' }
        } elseif (-not $r.denied_file.read_succeeded -or $r.denied_file.bytes_read -ne 1 -or -not $r.directory_enumeration.succeeded -or $r.directory_enumeration.entry_count -lt 1) { throw 'Product rule removal did not restore access.' }
    }
    # Terminate only this unique fixture box, then require stable emptiness.
    Invoke-CheckedProcess $start @("/box:$box", '/silent', '/terminate')
    $empty = 0
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $lines = @(& $start "/box:$box" /silent /listpids | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 1) { throw 'Cannot inspect dedicated product box.' }
        if ($lines.Count -eq 1 -and $lines[0] -eq '0') { $empty++ } else { $empty = 0 }
        if ($empty -ge 3) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Dedicated product box failed to stop.'
}

Start-Transcript (Join-Path $EvidenceDirectory 'transcript.txt') | Out-Null
try {
    $probeDirectory = Join-Path $EvidenceDirectory 'probe'
    & dotnet publish (Join-Path $PSScriptRoot 'probe/RuntimeProbe.csproj') -c Release -r win-x64 --self-contained true -o $probeDirectory --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Product probe compilation failed.' }
    $probe = Join-Path $probeDirectory 'DiskGuardRuntimeProbe.exe'
    $created = $true
    # Test-only host output exception; NOT a product-generated allow rule.
    & $ini set $box Enabled n
    & $ini set $box FileRootPath (Join-Path $EvidenceDirectory 'sandbox')
    & $ini set $box OpenFilePath "|$results"
    & $ini append $box OpenFilePath "$results\*"
    $readback = @(& $ini query $box OpenFilePath | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' })
    if ($LASTEXITCODE -ne 0 -or ($readback -join "`n") -cne (@("|$results", "$results\*") -join "`n")) { throw 'Test output fixture readback failed.' }
    $app = @{ id='probe'; name='Product probe'; executable=$probe; sandbox=$box; mode='blacklist'; enabled=$true; autoProtect=$true; includeChildren=$true; rules=@(@{id='private';path=$private;enabled=$true;recursive=$true}) }
    $config = @{ version=1; apps=@($app); settings=@{theme='system';closeToTray=$true;autostart=$false} }
    $applied = Invoke-Product 'blacklist' 'apply' $config
    if ($applied.appliedAppIds -notcontains 'probe' -or $applied.pendingAppIds -contains 'probe') { throw 'Product did not record its applied policy.' }
    Assert-Probe 'blacklist-explicit' $true $false
    Assert-Probe 'blacklist-forced' $true $true
    $restarted = Invoke-Product 'restart' 'inspect' $null
    if ($restarted.appliedAppIds -notcontains 'probe' -or $restarted.pendingAppIds.Count -ne 0) { throw 'Product state did not persist across a new process.' }
    $app.rules[0].enabled = $false
    Invoke-Product 'disable-rule' 'apply' $config | Out-Null
    Assert-Probe 'disabled-rule' $false $false
    $config.apps = @()
    $removed = Invoke-Product 'remove-application' 'save' $config
    if ($removed.appliedAppIds.Count -ne 0 -or $removed.config.apps.Count -ne 0) { throw 'Product removal did not clear local state.' }
    $enabled = @(& $ini query $box Enabled | Where-Object { $_ -ne '' })
    if ($LASTEXITCODE -ne 0 -or $enabled.Count -ne 0) { throw 'Product removal left runtime configuration.' }
    $result = @{success=$true;scope='Actual product Backend save/apply, blacklist deny/read/enumeration, sibling boundary, forced launch, child inheritance, process restart, rule disable and application removal';sandbox=$box}
} finally {
    try {
        if ($created) {
            & $ini set $box '*'
            $remaining = @(& $ini query '*' | ForEach-Object { $_.Trim() })
            if ($LASTEXITCODE -ne 0 -or $remaining -contains $box) { throw "Product fixture cleanup failed: $box" }
        }
    } finally { Stop-Transcript | Out-Null }
}
$result | ConvertTo-Json | Set-Content (Join-Path $EvidenceDirectory 'RESULT.json')
Write-Host 'PASS: actual product policy probes and dedicated fixture cleanup.'
