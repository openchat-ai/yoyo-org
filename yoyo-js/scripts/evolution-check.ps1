$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host '=== evolution-check ==='

Write-Host '[M1] tir-check'
& node (Join-Path $Root 'scripts\tir-check.js') (Join-Path $Root 'projects\yoyo.ty')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '[M2] compare-backends (x64 vs tir-x64)'
& node (Join-Path $Root 'scripts\compare-backends.js')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$compareA = Join-Path $Root 'build\compare-a.elf'
$compareB = Join-Path $Root 'build\compare-b.elf'
$a = [System.IO.File]::ReadAllBytes($compareA)
$b = [System.IO.File]::ReadAllBytes($compareB)
$diffs = 0
for ($i = 0; $i -lt [Math]::Min($a.Length, $b.Length); $i++) {
    if ($a[$i] -ne $b[$i]) { $diffs++ }
}
$diffs += [Math]::Abs($a.Length - $b.Length)
if ($diffs -ne 0) {
    Write-Host "[M2] FAIL: $diffs byte diffs"
    exit 1
}
Write-Host '[M2] PASS: 0 byte diffs'

$runBootstrap = if ($env:RUN_BOOTSTRAP) { $env:RUN_BOOTSTRAP } else { '0' }
if ($runBootstrap -eq '1') {
    $tirBootstrap = if ($env:TIR_BOOTSTRAP) { $env:TIR_BOOTSTRAP } else { '0' }
    Write-Host "[M3] bootstrap-native.ps1 3 (TIR_BOOTSTRAP=$tirBootstrap)"
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\bootstrap-native.ps1') -Stages 3
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[M3] FAIL (expected until scan path replaced)'
        exit 1
    }
    Write-Host '[M3] PASS'
}

Write-Host 'evolution-check: PASS'
