$bytes2 = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen2.exe')

Write-Host "=== gen2.exe 0x440-0x4C0 (full H_00 wrapper) ==="
for ($i = 0x440; $i -lt 0x4C0; $i += 16) {
    $hex = ($bytes2[$i..($i+15)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
    Write-Host ("  0x{0:X3}: {1}" -f $i, $hex)
}