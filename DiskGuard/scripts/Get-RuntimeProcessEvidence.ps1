#Requires -Version 7.0
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$destinationPath = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force | Out-Null
$processNames = @('SbieCtrl.exe', 'SandMan.exe', 'SbieSvc.exe', 'DiskGuard.exe', 'Start.exe', 'SandboxieRpcSs.exe', 'SandboxieDcomLaunch.exe', 'SandboxieCrypto.exe', 'DiskGuardRuntimeProbe.exe')
$filter = ($processNames | ForEach-Object { "Name='$_'" }) -join ' OR '
$processes = @(Get-CimInstance Win32_Process -Filter $filter | Sort-Object Name, ProcessId | ForEach-Object {
    [ordered]@{
        name = $_.Name
        executable_path = $_.ExecutablePath
        pid = $_.ProcessId
        parent_pid = $_.ParentProcessId
    }
})
[ordered]@{ timestamp_utc = [DateTime]::UtcNow.ToString('o'); processes = $processes } |
    ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $destinationPath -Encoding utf8
