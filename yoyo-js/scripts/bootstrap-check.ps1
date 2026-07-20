Write-Host "=== bootstrap-check ==="
$ROOT = (Get-Location).Path
$TMP = Join-Path $env:TEMP "yoyo-bs"
Remove-Item -Recurse -Force "$TMP" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$TMP" -Force | Out-Null

Write-Host "[1/4] gen yoyo.ty (1)"
# yoyo-gen.js deleted post-lockdown (Part 5.6); yoyo.ty now hand-authored
Copy-Item "$ROOT\projects\yoyo.ty" "$TMP\y1.ty" -Force

Write-Host "[2/4] gen yoyo.ty (2)"
# yoyo-gen.js deleted post-lockdown (Part 5.6); yoyo.ty now hand-authored
Copy-Item "$ROOT\projects\yoyo.ty" "$TMP\y2.ty" -Force

Write-Host "[3/4] compile x2"
& node "$ROOT\src\yoyo.js" "$ROOT\projects\yoyo.ty" "$TMP\a.exe" 2>&1 | Out-Null
& node "$ROOT\src\yoyo.js" "$ROOT\projects\yoyo.ty" "$TMP\b.exe" 2>&1 | Out-Null

Write-Host "[4/4] check"
$h1 = (Get-FileHash "$TMP\y1.ty").Hash
$h2 = (Get-FileHash "$TMP\y2.ty").Hash
$ha = (Get-FileHash "$TMP\a.exe").Hash
$hb = (Get-FileHash "$TMP\b.exe").Hash
Write-Host "yoyo.ty 1: $h1"
Write-Host "yoyo.ty 2: $h2"
Write-Host "yoyo.exe a: $ha"
Write-Host "yoyo.exe b: $hb"
if ($h1 -eq $h2 -and $ha -eq $hb) {
    Write-Host "PASS"
} else {
    Write-Host "FAIL"
}