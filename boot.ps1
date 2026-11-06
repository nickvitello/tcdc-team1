# TCDC Team 1 Windows bootstrap.
# Usage (run as Admin):  iex (irm https://raw.githubusercontent.com/GH_USER/tcdc-team1/main/boot.ps1)
# or with a box name:    $Box='ad'; iex (irm https://raw.githubusercontent.com/GH_USER/tcdc-team1/main/boot.ps1)
$ErrorActionPreference="Stop"
$raw="https://raw.githubusercontent.com/GH_USER/tcdc-team1/main/windows"
$box = if($Box){$Box}else{$env:COMPUTERNAME}
$dir="$env:TEMP\tcdc"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
foreach($f in "harden.ps1","watch-agent.ps1","ad-harden.ps1"){
  try { Invoke-WebRequest "$raw/$f" -OutFile "$dir\$f" -UseBasicParsing; Write-Host "[boot] got $f" }
  catch { Write-Host "[boot] !! failed $f (no egress? stage via jumpbox)" }
}
Write-Host "[boot] running harden.ps1 box=$box"
powershell -ep bypass -File "$dir\harden.ps1" -Box $box
Write-Host "[boot] AD box? then: powershell -ep bypass -File $dir\ad-harden.ps1   (add -Apply when ready)"
