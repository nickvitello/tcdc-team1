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
# review #1: pass the box's scored ports so harden.ps1 can STAGE verified allow rules.
# Firewall is NOT auto-enabled here (enabling can activate a latent Block policy) - the
# Windows lead enables it with -EnableFirewall after validating. Empty map => audit-only.
$tcpMap = @{ mqtt=@(1883); ad=@(389,636,88,445,135,53); dc=@(389,636,88,445,135,53) }
$udpMap = @{ ad=@(53,88,389,123); dc=@(53,88,389,123) }
$bl = $box.ToLower()
$ha = @("-ep","bypass","-File","$dir\harden.ps1","-Box",$box)
if($tcpMap.ContainsKey($bl)){ $ha += "-ScoredPorts"; $ha += $tcpMap[$bl] }
if($udpMap.ContainsKey($bl)){ $ha += "-ScoredUdpPorts"; $ha += $udpMap[$bl] }
Write-Host "[boot] running harden.ps1 box=$box"
& powershell.exe @ha
if($LASTEXITCODE -ne 0){ Write-Host "[boot] !! harden.ps1 exited $LASTEXITCODE - review $dir and C:\tcdc-baseline\harden-*.log" }
# review #6: stage modules at a STABLE path the README can reference (the timestamped $dir is
# unpredictable). C:\tcdc-baseline is created by harden.ps1 above.
$bk = "C:\tcdc-baseline"
if(Test-Path $bk){
  Copy-Item "$dir\ad-harden.ps1" $bk -Force -ErrorAction SilentlyContinue
  Copy-Item "$dir\harden.ps1"   $bk -Force -ErrorAction SilentlyContinue
  Write-Host "[boot] AD DC? modules staged at $bk . Run:"
  Write-Host "         powershell -ep bypass -File $bk\ad-harden.ps1          # report"
  Write-Host "         powershell -ep bypass -File $bk\ad-harden.ps1 -Apply   # safe changes"
} else {
  Write-Host "[boot] AD DC? then: powershell -ep bypass -File $dir\ad-harden.ps1   (add -Apply when ready)"
}
