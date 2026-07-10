$bytes = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen1.exe')
$bytes2 = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen2.exe')

# .rdata section usually at 0x4400 (per yoyo pe-builder)
# But could be different. Look at section table.

# Find the section at 0x400 = .text
# yoyo uses non-standard. Let me just check size differences.
$diff = $bytes2.Length - $bytes.Length
Write-Host "gen1 size: $($bytes.Length) bytes"
Write-Host "gen2 size: $($bytes2.Length) bytes"
Write-Host "Difference: $diff bytes (gen2 is larger)"

# Where's the extra 78KB? Look for any block of 0x00 padding.
$startExtra = -1
$endExtra = -1
$extraLen = 0
for ($i = 0; $i -lt $bytes2.Length; $i++) {
    if ($bytes2[$i] -eq 0 -and ($i -eq 0 -or $bytes2[$i-1] -ne 0)) {
        $startExtra = $i
    }
    if ($bytes2[$i] -ne 0 -and $startExtra -ge 0) {
        $len = $i - $startExtra
        if ($len -gt 1000) {
            Write-Host "  Large zero block: offset 0x$('{0:X}' -f $startExtra) length $len bytes"
            $endExtra = $i
            break
        }
    }
}

# Diff at the .data section boundary
Write-Host ""
Write-Host "Last 32 bytes of each (around .rdata or .data section):"
Write-Host "  gen1: $($bytes[-32..-1] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"
Write-Host "  gen2: $($bytes2[-32..-1] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"