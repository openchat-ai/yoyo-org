$bytes = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen1.exe')
$bytes2 = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen2.exe')

Write-Host "=== 0x460-0x485 detail ==="
for ($i = 0x460; $i -lt 0x490; $i += 16) {
    $hex = ($bytes[$i..($i+15)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
    $hex2 = ($bytes2[$i..($i+15)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
    Write-Host ("  0x{0:X3}: gen1={1}" -f $i, $hex)
    Write-Host ("         gen2={0}" -f $hex2)
}