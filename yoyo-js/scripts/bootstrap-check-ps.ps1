$ErrorActionPreference = 'Stop'
Set-Location "F:\yoyo-ide"

$TmpDir = "F:\yoyo-ide\build\bs-check"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

Write-Host '[1/4] yoyo-gen #1'
# yoyo-gen.js deleted; yoyo.ty now hand-authored
Copy-Item "F:\yoyo-ide\projects\yoyo.ty" "$TmpDir\yoyo-1.ty" -Force

Write-Host '[2/4] yoyo-gen #2'
# yoyo-gen.js deleted; yoyo.ty now hand-authored
Copy-Item "F:\yoyo-ide\projects\yoyo.ty" "$TmpDir\yoyo-2.ty" -Force

Write-Host '[3/4] compile x64 #1'
& node "F:\yoyo-ide\src\yoyo.js" "F:\yoyo-ide\projects\yoyo.ty" "$TmpDir\yoyo-a.exe" | Out-Null

Write-Host '[3/4] compile x64 #2'
& node "F:\yoyo-ide\src\yoyo.js" "F:\yoyo-ide\projects\yoyo.ty" "$TmpDir\yoyo-b.exe" | Out-Null

Write-Host '[4/4] compare'

$cmpTy = (Get-FileHash "$TmpDir\yoyo-1.ty" -Algorithm SHA256).Hash -eq (Get-FileHash "$TmpDir\yoyo-2.ty" -Algorithm SHA256).Hash
$cmpExe = (Get-FileHash "$TmpDir\yoyo-a.exe" -Algorithm SHA256).Hash -eq (Get-FileHash "$TmpDir\yoyo-b.exe" -Algorithm SHA256).Hash

Write-Host ("yoyo.ty deterministic: {0}" -f $(if ($cmpTy) {'PASS'} else {'FAIL'}))
Write-Host ("yoyo.exe deterministic: {0}" -f $(if ($cmpExe) {'PASS'} else {'FAIL'}))

Write-Host ''
Write-Host 'SHA256:'
Write-Host "  yoyo.ty:  $((Get-FileHash $TmpDir\yoyo-1.ty -Algorithm SHA256).Hash)"
Write-Host "  yoyo.exe: $((Get-FileHash $TmpDir\yoyo-a.exe -Algorithm SHA256).Hash)"

if (-not ($cmpTy -and $cmpExe)) { exit 1 }

# Cleanup
Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host 'bootstrap-check: PASS'