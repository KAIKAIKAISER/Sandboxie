#Requires -Version 7.0
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$lockPath = Join-Path $PSScriptRoot 'runtime.lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$expectedUrl = "https://github.com/sandboxie-plus/Sandboxie/releases/download/$($lock.release_tag)/$($lock.asset)"
if ($lock.repository -cne 'sandboxie-plus/Sandboxie' -or
    $lock.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $lock.asset -cnotmatch '^Sandboxie-Classic-x64-v[0-9.]+\.exe$' -or
    $lock.url -cne $expectedUrl) {
    throw 'Invalid official Classic runtime lockfile; refusing to bundle an arbitrary executable.'
}
$runtimeDirectory = Join-Path $projectRoot 'runtime'
$logsDirectory = Join-Path $projectRoot 'build-logs'
New-Item -ItemType Directory -Path $runtimeDirectory, $logsDirectory -Force | Out-Null
$destination = Join-Path $runtimeDirectory $lock.asset
if (-not (Test-Path -LiteralPath $destination) -or
    (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $lock.sha256) {
    $temporary = Join-Path $runtimeDirectory ([IO.Path]::GetRandomFileName() + '.download')
    try {
        Invoke-WebRequest -Uri $expectedUrl -OutFile $temporary -MaximumRetryCount 3 -RetryIntervalSec 3 -TimeoutSec 120
        $observed = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($observed -cne $lock.sha256) { throw 'Official runtime download SHA-256 mismatch.' }
        Move-Item -LiteralPath $temporary -Destination $destination -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
$hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
$signature = Get-AuthenticodeSignature -LiteralPath $destination
if ($hash -cne $lock.sha256 -or $signature.Status -ne 'Valid') {
    throw "Bundled runtime verification failed: SHA-256=$hash; Authenticode=$($signature.Status)."
}
Copy-Item -LiteralPath $lockPath -Destination (Join-Path $runtimeDirectory 'runtime.lock.json') -Force
[ordered]@{
    repository = $lock.repository
    release_tag = $lock.release_tag
    classic_version = $lock.classic_version
    asset = $lock.asset
    url = $lock.url
    expected_sha256 = $lock.sha256
    observed_sha256 = $hash
    authenticode_status = $signature.Status.ToString()
    signer = $signature.SignerCertificate.Subject
    signer_thumbprint = $signature.SignerCertificate.Thumbprint
    source_archive = "https://github.com/sandboxie-plus/Sandboxie/archive/refs/tags/$($lock.release_tag).zip"
    installed_on_build_host = $false
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $logsDirectory 'bundled-runtime.json') -Encoding utf8
Write-Host "Verified bundled official Classic $($lock.classic_version): SHA-256 $hash; Authenticode Valid. No installation on build host."
