# TCDC drift watch-agent (Windows). Scheduled every 2 min. Compares live state to baseline.
param([string]$Box=$env:COMPUTERNAME)
$ErrorActionPreference="Continue"
$BK="C:\tcdc-baseline"; $out="$BK\drift.log"
$hook=$env:TCDC_WEBHOOK
function Alert($m){
  $l="[{0}] {1} DRIFT: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Box,$m
  Add-Content $out $l
  if($hook){ try{ Invoke-RestMethod -Uri $hook -Method Post -TimeoutSec 5 -ContentType 'application/json' -Body (@{content=$l}|ConvertTo-Json) }catch{} }
}
if(-not (Test-Path "$BK\services.base.csv")){ "no baseline; run harden.ps1" ; exit 0 }

# 1. new local admins
try {
  $base = (Import-Csv "$BK\admins.base.csv").Name
  Get-LocalGroupMember Administrators | ForEach-Object {
    if($base -notcontains $_.Name){ Alert ("NEW local admin: " + $_.Name) }
  }
} catch {}

# 2. new scheduled tasks outside \Microsoft\
$baseTasks = (Import-Csv "$BK\schtasks.base.csv") | ForEach-Object { $_.TaskPath + $_.TaskName }
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object {
  $id = $_.TaskPath + $_.TaskName
  if($baseTasks -notcontains $id){ Alert ("NEW scheduled task: " + $id) }
}

# 3. new services
$baseSvc = (Import-Csv "$BK\services.base.csv").Name
Get-Service | ForEach-Object { if($baseSvc -notcontains $_.Name){ Alert ("NEW service: " + $_.Name) } }

# 4. new Run-key autoruns
$baseRun = Get-Content "$BK\runkeys.base.txt" -ErrorAction SilentlyContinue
foreach($k in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")){
  if(Test-Path $k){ (Get-Item $k).Property | ForEach-Object {
    $line = "$k :: $_ = $((Get-ItemProperty $k).$_)"
    if($baseRun -notcontains $line){ Alert ("NEW autorun: " + $line) }
  }}
}

# 5. suspicious listeners (common C2 ports)
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in 4444,5555,8081,9001,1337,31337 } |
  ForEach-Object { Alert ("suspicious listener :" + $_.LocalPort + " pid=" + $_.OwningProcess) }
exit 0
