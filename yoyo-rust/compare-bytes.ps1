$bytes = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen1.exe')
$bytes2 = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen2.exe')

# .text section starts at 0x400, size 0x8000 = 32768 bytes
# Skip startup blob (assume 0x75 = 117 bytes for Windows, based on earlier)
# H_00 wrapper is 16 bytes (from H_00 wrapper detected: 16)
# So user code starts at 0x440 + 16 = 0x450

Write-Host "gen1 .text (0x400-0x8400): 32768 bytes"
Write-Host "gen2 .text (0x400-0x8400): 32768 bytes"
Write-Host ""
Write-Host "gen1 .text[0x40..0x60] (after startup):"
$hex = ($bytes[0x440..0x460] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  $hex"
Write-Host "gen2 .text[0x40..0x60] (after startup):"
$hex2 = ($bytes2[0x440..0x460] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  $hex2"

Write-Host ""
Write-Host "gen1 first 64 bytes of .text content (0x440 onwards):"
$hex = ($bytes[0x440..0x47F] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  $hex"
Write-Host "gen2 first 64 bytes of .text content:"
$hex2 = ($bytes2[0x440..0x47F] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  $hex2"

# Find first diff in .text
Write-Host ""
Write-Host "First 20 diffs in .text content (after startup):"
$count = 0
for ($i = 0x475; $i -lt 0x8400; $i++) {
    if ($bytes[$i] -ne $bytes2[$i]) {
        Write-Host ("  0x{0:X4}: 0x{1:X2} vs 0x{2:X2}" -f $i, $bytes[$i], $bytes2[$i])
        $count++
        if ($count -ge 20) { break }
    }
}