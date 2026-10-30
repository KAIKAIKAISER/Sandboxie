#Requires -Version 7.0
# SPDX-License-Identifier: GPL-3.0-or-later
# Read-only environment collection. No driver installation, service control or
# pass/fail inference; operators must perform and document the acceptance steps.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidenceDirectory,
    [string]$Application
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Client acceptance evidence requires Windows.' }
if (-not [IO.Path]::IsPathFullyQualified($EvidenceDirectory)) { throw 'EvidenceDirectory must be absolute.' }
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Refusing to overwrite previous acceptance evidence.' }
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 1) { throw 'A Windows client is required; Server evidence cannot fill the client matrix.' }
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne 'X64') { throw 'Use an x64 client VM, not x86 or ARM64.' }
$build = [int]$os.BuildNumber
if ($build -lt 19041) { throw 'Use a supported Windows 10/11 client build and record its exact version.' }
$applicationEvidence = $null
if ($Application) {
    $file = Get-Item -LiteralPath $Application
    if ($file.PSIsContainer -or $file.Extension -ine '.exe') { throw 'Application must be an existing EXE.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    $applicationEvidence = [ordered]@{
        path = $file.FullName
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        file_version = $file.VersionInfo.FileVersion
        authenticode = $signature.Status.ToString()
    }
}
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
[ordered]@{
    collected_utc = [DateTime]::UtcNow.ToString('o')
    platform = if ($build -ge 22000) { 'Windows 11' } else { 'Windows 10' }
    caption = $os.Caption
    version = $os.Version
    build = $os.BuildNumber
    architecture = $os.OSArchitecture
    process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    application = $applicationEvidence
    services = @(Get-CimInstance Win32_Service -Filter "Name='SbieSvc'" | Select-Object Name, State, StartMode, PathName)
    drivers = @(Get-CimInstance Win32_SystemDriver -Filter "Name='SbieDrv'" | Select-Object Name, State, StartMode, PathName)
    validation_scope = 'Read-only environment collection; no application behavior has been tested.'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'environment.json') -Encoding utf8
$scenarios = @('install-uninstall-webview2', 'portable', 'blacklist-open-read-enumerate', 'forcing-children-restart', 'whitelist-entitlement', 'monitor-disable-persistence', 'logging-filter-export', 'qq-wechat-business', 'standard-user-uac-service-stop', 'unicode-long-reparse-network-paths', 'tray-theme-autostart-performance', 'high-volume-monitor-contention')
[ordered]@{
    schema_version = 1
    source_commit = $null
    tester = $null
    evidence_notice = 'Fill only after executing the documented steps. Do not upload private paths or data.'
    scenarios = @($scenarios | ForEach-Object { [ordered]@{ id=$_; status='not_run'; expected=$null; actual=$null; evidence=@() } })
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'acceptance.json') -Encoding utf8
Write-Host 'Environment and NOT-RUN acceptance template saved. No behavior has been marked passed.'
