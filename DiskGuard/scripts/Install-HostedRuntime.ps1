#Requires -Version 7.0
#Requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This installer is limited to the explicitly requested disposable GitHub-hosted Windows runtime test job. It must not install anything on a developer workstation.'
}
if (Get-Service -Name SbieSvc -ErrorAction SilentlyContinue) { throw 'Unexpected pre-existing Sandboxie installation on hosted runner.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidenceDirectory = Join-Path $projectRoot 'work/hosted-runtime'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
Start-Transcript -LiteralPath (Join-Path $evidenceDirectory 'install-transcript.txt') -Force | Out-Null
try {
    $lock = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'runtime.lock.json') -Raw | ConvertFrom-Json
    if ($lock.repository -cne 'sandboxie-plus/Sandboxie' -or $lock.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Invalid runtime lockfile.' }
    $expectedUrl = "https://github.com/sandboxie-plus/Sandboxie/releases/download/$($lock.release_tag)/$($lock.asset)"
    if ($lock.url -cne $expectedUrl -or $lock.asset -notmatch '^Sandboxie-Classic-x64-v[0-9.]+\.exe$') { throw 'Runtime download is not the pinned official Classic x64 asset.' }
    $metadata = Invoke-RestMethod -Uri "https://api.github.com/repos/sandboxie-plus/Sandboxie/releases/tags/$($lock.release_tag)" -Headers @{Accept='application/vnd.github+json'; 'User-Agent'='DiskGuard-signed-runtime-verification'}
    if ($metadata.draft -or $metadata.prerelease) { throw 'Runtime must be an official stable release.' }
    $assets = @($metadata.assets | Where-Object { $_.name -ceq $lock.asset -and $_.browser_download_url -ceq $expectedUrl })
    if ($assets.Count -ne 1) { throw 'Pinned official release asset was not found.' }
    $installer = Join-Path $evidenceDirectory $lock.asset
    Invoke-WebRequest -Uri $expectedUrl -OutFile $installer
    $hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $lock.sha256) { throw "Runtime SHA256 mismatch. Expected $($lock.sha256), observed $hash" }
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    $installation = [ordered]@{
        repository = $lock.repository
        release_tag = $lock.release_tag
        classic_version = $lock.classic_version
        release_id = $metadata.id
        asset_id = $assets[0].id
        url = $expectedUrl
        expected_sha256 = $lock.sha256
        observed_sha256 = $hash
        authenticode_status = $signature.Status.ToString()
        signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        signer_thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        driver_signing_settings_changed = $false
    }
    $installation | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'installer.json') -Encoding utf8
    if ($signature.Status -ne 'Valid') { throw "Official installer Authenticode signature is not trusted: $($signature.Status). Refusing installation." }
    # NSIS native silent/install switches are verified against SandboxieVS.nsi.
    $process = Start-Process -FilePath $installer -ArgumentList @('/install', '/S') -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit(180000)) { throw 'Official installer timed out; hosted runner will be discarded.' }
        if ($process.ExitCode -ne 0) { throw "Official installer failed with exit code $($process.ExitCode); reboot-dependent installation is not a pass." }
    }
    finally { $process.Dispose() }
    $service = Get-Service -Name SbieSvc -ErrorAction Stop
    if ($service.Status -ne 'Running') { Start-Service -Name SbieSvc -ErrorAction Stop }
    (Get-Service -Name SbieSvc).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='SbieDrv'"
    if (-not $driver -or $driver.State -ne 'Running') { throw 'Official signed driver did not load on hosted Windows. Do not disable signature enforcement; inspect collected system events.' }
    Write-Host 'Official runtime installed and running. Real enforcement probe is the next required step.'
}
finally { Stop-Transcript | Out-Null }
