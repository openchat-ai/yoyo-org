param(
    [int]$Stages = 3
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$TirBootstrap = if ($env:TIR_BOOTSTRAP) { $env:TIR_BOOTSTRAP } else { '0' }
$SrcTy = Join-Path $Root 'projects\yoyo.ty'
$Gen1Exe = Join-Path $Root 'build\yoyo.exe'
$TmpDir = Join-Path $env:TEMP "yoyo-native-win-bs-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

function Compare-FileBytes([string]$PathA, [string]$PathB) {
    $a = [System.IO.File]::ReadAllBytes($PathA)
    $b = [System.IO.File]::ReadAllBytes($PathB)
    if ($a.Length -ne $b.Length) { return @{ ok = $false; diffs = [Math]::Abs($a.Length - $b.Length) } }
    $diffs = 0
    for ($i = 0; $i -lt $a.Length; $i++) {
        if ($a[$i] -ne $b[$i]) { $diffs++ }
    }
    return @{ ok = ($diffs -eq 0); diffs = $diffs }
}

function Invoke-RunGenWindows {
    param(
        [string]$Label,
        [string]$CompilerPath,
        [int]$TimeoutMs = 120000
    )

    Remove-Item (Join-Path $Root 'input.ky') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output.exe') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output') -Force -ErrorAction SilentlyContinue
    Copy-Item $SrcTy (Join-Path $Root 'input.ky') -Force

    Write-Host "[*] $Label`: $CompilerPath"

    if (-not (Test-Path $CompilerPath)) {
        Write-Host "[!] $Label`: compiler not found"
        return $false
    }

    Push-Location $Root
    try {
        & $CompilerPath
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    if ($null -eq $code) { $code = -1 }

    if ($code -ne 0) {
        $hex = if ($code -lt 0) { ('0x{0:X8}' -f ($code -band 0xFFFFFFFF)) } else { $code.ToString() }
        Write-Host "[!] $Label`: compiler exited with code $code ($hex)"
        if ($code -eq -1073741819 -or $hex -eq '0xC0000005') {
            Write-Host '  (ACCESS_VIOLATION — gen1 scan runtime broken, see docs/PENDING.md)'
        }
        return $false
    }

    $outputExe = Join-Path $Root 'output.exe'
    if (-not (Test-Path $outputExe)) {
        Write-Host "[!] $Label`: output.exe not found"
        return $false
    }

    $dest = Join-Path $TmpDir "$Label.exe"
    Copy-Item $outputExe $dest -Force
    $hash = (Get-FileHash $dest -Algorithm SHA256).Hash
    $size = (Get-Item $dest).Length
    Write-Host "  -> output.exe: $size bytes"
    Write-Host "  -> SHA256: $hash"
    return $true
}

try {
    Write-Host "=== yoyo native Windows bootstrap (TIR_BOOTSTRAP=$TirBootstrap) ==="

    Write-Host '[1] node yoyo-gen.js --target=win'
    # yoyo-gen.js deleted; yoyo.ty now hand-authored

    $gen1Backend = 'x64'
    if ($TirBootstrap -eq '1') {
        Write-Host '[!] TIR_BOOTSTRAP=1: tir-x64 is Linux-only today; using x64 for Windows gen1 (Phase 1)'
    }

    Write-Host "[2] node yoyo.js --backend=$gen1Backend --target=win -> build/yoyo.exe (gen1)"
    & node (Join-Path $Root 'src\yoyo.js') "--backend=$gen1Backend" --target=win `
        $SrcTy $Gen1Exe

    if (-not (Test-Path $Gen1Exe)) {
        Write-Host '[!] gen1 build/yoyo.exe not found'
        exit 1
    }
    Write-Host "  gen1: $((Get-Item $Gen1Exe).Length) bytes, SHA256=$((Get-FileHash $Gen1Exe -Algorithm SHA256).Hash)"

    if (-not (Invoke-RunGenWindows -Label 'gen1' -CompilerPath $Gen1Exe)) {
        exit 1
    }

    Copy-Item $Gen1Exe (Join-Path $TmpDir 'gen1.exe') -Force

    if ($Stages -lt 2) {
        Write-Host 'bootstrap-native-windows: stage 1 PASS'
        exit 0
    }

    if (-not (Invoke-RunGenWindows -Label 'gen2' -CompilerPath $Gen1Exe)) {
        exit 1
    }

    if ($Stages -lt 3) {
        Write-Host 'bootstrap-native-windows: stage 2 PASS'
        exit 0
    }

    $gen2Exe = Join-Path $TmpDir 'gen2.exe'
    if (-not (Test-Path $gen2Exe)) {
        Write-Host '[!] gen2 artifact missing'
        exit 1
    }

    if (-not (Invoke-RunGenWindows -Label 'gen3' -CompilerPath $gen2Exe)) {
        exit 1
    }

    $gen3Exe = Join-Path $TmpDir 'gen3.exe'
    if (-not (Test-Path $gen3Exe)) {
        Write-Host '[!] gen3 artifact missing'
        exit 1
    }

    $h2 = (Get-FileHash $gen2Exe -Algorithm SHA256).Hash
    $h3 = (Get-FileHash $gen3Exe -Algorithm SHA256).Hash
    Write-Host "gen2 SHA256: $h2"
    Write-Host "gen3 SHA256: $h3"

    $cmp = Compare-FileBytes $gen2Exe $gen3Exe
    if ($cmp.ok) {
        Write-Host 'gen2 vs gen3: PASS (byte-identical)'
        Write-Host 'bootstrap-native-windows: PASS'
        exit 0
    }

    Write-Host "gen2 vs gen3: FAIL ($($cmp.diffs) differing byte pairs)"
    Write-Host 'bootstrap-native-windows: FAIL (Stage 3 — see docs/PENDING.md)'
    exit 1
}
finally {
    Remove-Item (Join-Path $Root 'input.ky') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output.exe') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output') -Force -ErrorAction SilentlyContinue
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
