# TCDC Team 1 Windows bootstrap. FAIL-CLOSED: aborts if any module fails to download (review #10).
# Usage (run as Admin):  iex (irm https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.ps1)
# or:                    $Box='ad'; iex (irm https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.ps1)
$ErrorActionPreference="Stop"
# Pin a reviewed revision here (tag or commit SHA) to avoid fetching an unreviewed main. 'main' = latest.
$Ref = if($Ref){$Ref}else{"main"}
$raw = "https://raw.githubusercontent.com/nickvitello/tcdc-team1/$Ref/windows"
$box = if($Box){$Box}else{$env:COMPUTERNAME}
# fresh private staging dir each run so a stale previous module can't execute
$dir = Join-Path $env:TEMP ("tcdc-" + (Get-Date -Format yyyyMMddHHmmss))
if(Test-Path $dir){ Remove-Item $dir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$ok=$true
foreach($f in "harden.ps1","watch-agent.ps1","ad-harden.ps1"){
  try { Invoke-WebRequest "$raw/$f" -OutFile "$dir\$f" -UseBasicParsing
        if(-not (Test-Path "$dir\$f") -or (Get-Item "$dir\$f").Length -eq 0){ throw "empty" }
        Write-Host "[boot] got $f" }
  catch { Write-Host "[boot] !! FAILED $f ($($_.Exception.Message))"; $ok=$false }
}
if(-not $ok){
  Write-Host "[boot] ABORT: not all modules downloaded. No egress? Stage files via jumpbox, then run harden.ps1 directly. Nothing was executed."
  Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
  return
}
Write-Host "[boot] running harden.ps1 box=$box"
& powershell.exe -ep bypass -File "$dir\harden.ps1" -Box $box
if($LASTEXITCODE -ne 0){ Write-Host "[boot] !! harden.ps1 exited $LASTEXITCODE - review $dir and C:\tcdc-baseline\harden-*.log" }
Write-Host "[boot] AD box? then: powershell -ep bypass -File $dir\ad-harden.ps1   (add -Apply when ready)"
