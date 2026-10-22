# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot '..'))
$logsDirectory = Join-Path $projectRoot 'build-logs'
$distributionDirectory = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Path $logsDirectory, $distributionDirectory -Force | Out-Null
Start-Transcript -LiteralPath (Join-Path $logsDirectory 'build-transcript.txt') -Force | Out-Null

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    Write-Host ("Running {0} {1}" -f $Executable, ($Arguments -join ' '))
    $script:commandIndex++
    $commandLog = Join-Path $logsDirectory ('{0:D2}-{1}.txt' -f $script:commandIndex, [IO.Path]::GetFileNameWithoutExtension($Executable))
    & $Executable @Arguments 2>&1 | Tee-Object -FilePath $commandLog
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE" }
}

$script:commandIndex = 0

try {
    Push-Location $projectRoot
    try {
        Invoke-Checked 'node' @('--version')
        Invoke-Checked 'npm' @('--version')
        Invoke-Checked 'rustc' @('--version')
        Invoke-Checked 'cargo' @('--version')
        Invoke-Checked 'pwsh' @('-NoProfile', '-File', 'scripts/Get-BundledRuntime.ps1')
        Invoke-Checked 'npm' @('--prefix', 'ui', 'ci', '--no-audit', '--no-fund')
        Invoke-Checked 'npm' @('--prefix', 'ui', 'run', 'build')
        Invoke-Checked 'npm' @('--prefix', 'ui', 'run', 'test', '--if-present')
        Invoke-Checked 'cargo' @('fmt', '--manifest-path', 'src-tauri/Cargo.toml', '--all', '--', '--check')
        Invoke-Checked 'cargo' @('clippy', '--manifest-path', 'src-tauri/Cargo.toml', '--locked', '--all-targets', '--', '-D', 'warnings')
        Invoke-Checked 'cargo' @('test', '--manifest-path', 'src-tauri/Cargo.toml', '--locked', '--all-targets')
        Invoke-Checked 'node' @('ui/node_modules/@tauri-apps/cli/tauri.js', 'build', '--target', 'x86_64-pc-windows-msvc', '--bundles', 'nsis', '--ci')

        $config = Get-Content -LiteralPath 'src-tauri/tauri.conf.json' -Raw | ConvertFrom-Json
        $version = $config.version
        $binaryName = (Get-Content -LiteralPath 'src-tauri/Cargo.toml' -Raw | Select-String -Pattern '(?m)^name\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
        $releaseDirectory = Join-Path $projectRoot 'src-tauri/target/x86_64-pc-windows-msvc/release'
        $application = Join-Path $releaseDirectory "$binaryName.exe"
        if (-not (Test-Path -LiteralPath $application)) { throw "Missing built application: $application" }
        $installers = @(Get-ChildItem -LiteralPath (Join-Path $releaseDirectory 'bundle/nsis') -Filter "*_${version}_x64-setup.exe" -File)
        if ($installers.Count -ne 1) { throw 'Expected exactly one NSIS x64 installer' }
        Copy-Item -LiteralPath $installers[0].FullName -Destination (Join-Path $distributionDirectory "DiskGuard_${version}_x64-setup.exe")

        $portableDirectory = Join-Path $projectRoot 'work/portable'
        New-Item -ItemType Directory -Path $portableDirectory -Force | Out-Null
        Copy-Item -LiteralPath $application -Destination (Join-Path $portableDirectory 'DiskGuard.exe')
        Copy-Item -LiteralPath (Join-Path $projectRoot 'docs/RUNTIME.md') -Destination (Join-Path $portableDirectory 'README-runtime.md')
        Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE.Classic') -Destination (Join-Path $portableDirectory 'LICENSE.GPL-3.0.txt')
        if (Test-Path -LiteralPath (Join-Path $projectRoot 'THIRD-PARTY-NOTICES.md')) {
            Copy-Item -LiteralPath (Join-Path $projectRoot 'THIRD-PARTY-NOTICES.md') -Destination $portableDirectory
        }
        $portableRuntime = Join-Path $portableDirectory 'runtime'
        New-Item -ItemType Directory -Path $portableRuntime -Force | Out-Null
        foreach ($runtimeFile in @('runtime.lock.json', 'NOTICE.md', 'Sandboxie-Classic-x64-v5.73.8.exe')) {
            Copy-Item -LiteralPath (Join-Path $projectRoot "runtime/$runtimeFile") -Destination $portableRuntime -Force
        }
        Compress-Archive -LiteralPath @(Get-ChildItem -LiteralPath $portableDirectory | ForEach-Object { $_.FullName }) -DestinationPath (Join-Path $distributionDirectory "DiskGuard_${version}_windows-x64-portable.zip") -Force

        $sourceCommit = (& git -C $repoRoot rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Unable to identify source commit' }
        $manifest = [ordered]@{
            application = 'DiskGuard'
            version = $version
            target = 'x86_64-pc-windows-msvc'
            source_commit = $sourceCommit
            upstream_reviewed_commit = 'c3e59fdb18d50199ebfccf7764e1d6c4e007de96'
            build_utc = [DateTime]::UtcNow.ToString('o')
            node = (& node --version | Out-String).Trim()
            rustc = (& rustc --version | Out-String).Trim()
            app_authenticode = (Get-AuthenticodeSignature -LiteralPath $application).Status.ToString()
            runtime_bundled = $true
            runtime_version = '5.73.8'
            runtime_installer_sha256 = (Get-Content -LiteralPath 'scripts/runtime.lock.json' -Raw | ConvertFrom-Json).sha256
            runtime_installer_authenticode = (Get-AuthenticodeSignature -LiteralPath 'runtime/Sandboxie-Classic-x64-v5.73.8.exe').Status.ToString()
            runtime_source_archive = 'https://github.com/sandboxie-plus/Sandboxie/archive/refs/tags/v1.18.8.zip'
            kernel_driver_built = $false
            driver_test_signing_enabled = $false
            hosted_ci_scope = 'frontend build; Rust format/clippy/unit tests; NSIS and portable UI packaging'
            enforcement_vm_tests = 'not run by this build script; requires separate explicit disposable VM test'
            run_url = if ($env:GITHUB_ACTIONS -eq 'true') { "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID" } else { $null }
        }
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $distributionDirectory 'BUILD-MANIFEST.json') -Encoding utf8
        $checksums = Get-ChildItem -LiteralPath $distributionDirectory -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name | ForEach-Object {
            $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), $_.Name
        }
        $checksums | Set-Content -LiteralPath (Join-Path $distributionDirectory 'SHA256SUMS.txt') -Encoding utf8
        Write-Host "Build completed. Artifacts: $distributionDirectory"
    }
    finally { Pop-Location }
}
finally { Stop-Transcript | Out-Null }
