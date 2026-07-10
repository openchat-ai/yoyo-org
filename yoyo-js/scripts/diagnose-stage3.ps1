param(
    [switch]$RunBootstrap
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$TmpDir = Join-Path $env:TEMP "yoyo-stage3-diag-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$Gen1 = Join-Path $Root 'build\yoyo'
$Gen2 = Join-Path $TmpDir 'gen2.elf'
$Gen3 = Join-Path $TmpDir 'gen3.elf'
$BsCode = 0

try {
    Write-Host '=== diagnose-stage3 ==='

    Write-Host '[build] yoyo-gen + gen1 compile'
    # yoyo-gen.js deleted; yoyo.ty now hand-authored
    & node (Join-Path $Root 'src\yoyo.js') --target=linux `
        (Join-Path $Root 'projects\yoyo.ty') $Gen1

    if ($RunBootstrap) {
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\bootstrap-native.ps1') -Stages 3
        $BsCode = $LASTEXITCODE
    }

    $outputElf = Join-Path $Root 'output'
    if (Test-Path $outputElf) {
        Copy-Item $outputElf $Gen2 -Force -ErrorAction SilentlyContinue
    }

    $diagArgs = @('--gen1', $Gen1)
    if (Test-Path $Gen2) { $diagArgs += @('--gen2', $Gen2) }
    if (Test-Path $Gen3) { $diagArgs += @('--gen3', $Gen3) }

    & node (Join-Path $Root 'scripts\diagnose-stage3.js') @diagArgs
    if ($LASTEXITCODE -ne 0 -and $BsCode -eq 0) { exit $LASTEXITCODE }
    exit $BsCode
}
finally {
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
