param(
    [int]$Stages = 3
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$TirBootstrap = if ($env:TIR_BOOTSTRAP) { $env:TIR_BOOTSTRAP } else { '0' }
$TmpDir = Join-Path $env:TEMP "yoyo-native-bs-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

function ConvertTo-WslPath([string]$Path) {
    if (-not (Test-Path $Path)) { return $Path -replace '\\', '/' }
    $p = (Resolve-Path $Path).Path -replace '\\', '/'
    if ($p -match '^([A-Za-z]):') {
        return '/mnt/' + $Matches[1].ToLower() + $p.Substring(2)
    }
    return $p
}

function Test-WslAvailable {
    try {
        $null = & wsl bash -lc 'echo ok' 2>&1
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

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

function Invoke-RunGenLinux {
    param(
        [string]$Label,
        [string]$CompilerPath
    )

    Remove-Item (Join-Path $Root 'input.ky') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output.exe') -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $Root 'projects\yoyo.ty') (Join-Path $Root 'input.ky') -Force

    Write-Host "[*] $Label`: $CompilerPath"

    if (-not (Test-WslAvailable)) {
        Write-Host "[!] $Label`: WSL not available — cannot execute Linux ELF on native Windows"
        return $false
    }

    $wslRoot = ConvertTo-WslPath $Root
    $wslCompiler = ConvertTo-WslPath $CompilerPath
    $cmd = "cd '$wslRoot' && timeout --foreground 120s '$wslCompiler'"
    & wsl bash -lc $cmd
    $code = $LASTEXITCODE

    if ($code -eq 124) {
        Write-Host "[!] $Label timeout"
        return $false
    }
    if ($code -ne 0) {
        Write-Host "[!] $Label`: compiler exited with code $code"
        return $false
    }

    $outputElf = Join-Path $Root 'output'
    if (-not (Test-Path $outputElf)) {
        Write-Host "[!] $Label`: output not found (exit=$code)"
        return $false
    }

    $dest = Join-Path $TmpDir "$Label.elf"
    Copy-Item $outputElf $dest -Force
    $size = (Get-Item $dest).Length
    Write-Host "  -> output: $size bytes"
    return $true
}

try {
    Write-Host "=== yoyo native Linux bootstrap (TIR_BOOTSTRAP=$TirBootstrap) ==="

    Write-Host '[1] node yoyo-gen.js --target=linux'
    # yoyo-gen.js deleted; yoyo.ty now hand-authored

    $gen1Backend = if ($TirBootstrap -eq '1') { 'tir-x64' } else { 'x64' }
    Write-Host "[2] node yoyo.js --backend=$gen1Backend --target=linux -> build/yoyo (gen1)"
    & node (Join-Path $Root 'src\yoyo.js') "--backend=$gen1Backend" --target=linux `
        (Join-Path $Root 'projects\yoyo.ty') (Join-Path $Root 'build\yoyo')

    $gen1Path = Join-Path $Root 'build\yoyo'
    if (-not (Test-Path $gen1Path)) {
        Write-Host '[!] gen1 build/yoyo not found'
        exit 1
    }

    $wslOk = Test-WslAvailable
    if (-not $wslOk) {
        Write-Host '[!] WSL not available — Node gen1 build OK; ELF stages require WSL'
        Write-Host "  gen1: $gen1Path ($((Get-Item $gen1Path).Length) bytes)"
        Write-Host 'bootstrap-native: SKIP (install WSL for Stage 2/3)'
        exit 1
    }

    if (-not (Invoke-RunGenLinux -Label 'gen1' -CompilerPath $gen1Path)) {
        exit 1
    }

    Copy-Item $gen1Path (Join-Path $TmpDir 'gen1.elf') -Force

    if ($Stages -lt 2) {
        Write-Host 'bootstrap-native: stage 1 PASS'
        exit 0
    }

    if (-not (Invoke-RunGenLinux -Label 'gen2' -CompilerPath $gen1Path)) {
        exit 1
    }

    if ($Stages -lt 3) {
        Write-Host 'bootstrap-native: stage 2 PASS'
        exit 0
    }

    $gen2Elf = Join-Path $TmpDir 'gen2.elf'
    if (-not (Test-Path $gen2Elf)) {
        Write-Host '[!] gen2 artifact missing'
        exit 1
    }
    if (-not (Invoke-RunGenLinux -Label 'gen3' -CompilerPath $gen2Elf)) {
        exit 1
    }

    $gen3Elf = Join-Path $TmpDir 'gen3.elf'
    if (-not (Test-Path $gen3Elf)) {
        Write-Host '[!] gen3 artifact missing'
        exit 1
    }
    $cmp = Compare-FileBytes $gen2Elf $gen3Elf
    if ($cmp.ok) {
        Write-Host 'gen2 vs gen3: PASS (byte-identical)'
        Write-Host 'bootstrap-native: PASS'
        exit 0
    }

    Write-Host "gen2 vs gen3: FAIL ($($cmp.diffs) differing byte pairs)"
    Write-Host 'bootstrap-native: FAIL (Stage 3 — see docs/PENDING.md)'
    exit 1
}
finally {
    Remove-Item (Join-Path $Root 'input.ky') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'output.exe') -Force -ErrorAction SilentlyContinue
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
