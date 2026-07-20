$bytes = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen1.exe')
$bytes2 = [System.IO.File]::ReadAllBytes('F:\yoyo-ide\build\gen2.exe')

Write-Host "gen1.exe size: $($bytes.Length)"
Write-Host "gen2.exe size: $($bytes2.Length)"
Write-Host ""

# .text section header at 0x1F8
$sh = 0x1F8
$name = [System.Text.Encoding]::ASCII.GetString($bytes[$sh..($sh+7)]).TrimEnd([char]0)
Write-Host "gen1 .text name: '$name'"
$vs = [BitConverter]::ToUInt32($bytes, $sh + 8)
$va = [BitConverter]::ToUInt32($bytes, $sh + 12)
$rs = [BitConverter]::ToUInt32($bytes, $sh + 16)
$rp = [BitConverter]::ToUInt32($bytes, $sh + 20)
Write-Host "gen1 .text: vsize=0x$('{0:X}' -f $vs) vaddr=0x$('{0:X}' -f $va) rawSize=0x$('{0:X}' -f $rs) rawPtr=0x$('{0:X}' -f $rp)"

Write-Host ""
$name2 = [System.Text.Encoding]::ASCII.GetString($bytes2[$sh..($sh+7)]).TrimEnd([char]0)
Write-Host "gen2 .text name: '$name2'"
$vs2 = [BitConverter]::ToUInt32($bytes2, $sh + 8)
$va2 = [BitConverter]::ToUInt32($bytes2, $sh + 12)
$rs2 = [BitConverter]::ToUInt32($bytes2, $sh + 16)
$rp2 = [BitConverter]::ToUInt32($bytes2, $sh + 20)
Write-Host "gen2 .text: vsize=0x$('{0:X}' -f $vs2) vaddr=0x$('{0:X}' -f $va2) rawSize=0x$('{0:X}' -f $rs2) rawPtr=0x$('{0:X}' -f $rp2)"

# Show .text content from each
Write-Host ""
Write-Host "gen1 .text first 24 bytes (from 0x440):"
$hex = ($bytes[0x440..0x457] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  $hex"
Write-Host "gen2 .text first 24 bytes (from 0x440):"
$hex2 = ($bytes2[0x440..0x457] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  $hex2"