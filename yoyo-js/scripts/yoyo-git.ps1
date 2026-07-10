$global:YOYO_GIT = 'C:\Program Files\Git\cmd\git.exe'
function rgit { & $global:YOYO_GIT @args }
Write-Host "rgit loaded"