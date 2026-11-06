# TCDC drift watch-agent (Windows). Scheduled every 2 min (as SYSTEM). Compares live state to baseline.
# R23 NOTE: TCDC_WEBHOOK is OFF by default; enabling it exports host data off-box (see linux note). Local log default.
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

# 2. scheduled tasks: NEW task, or CHANGED action/args/principal (review #9). Skip our own TCDC-Watch.
$bt=@{}; Import-Csv "$BK\schtasks.base.csv" | ForEach-Object { $bt[$_.Id] = ("{0}|{1}|{2}" -f $_.Exec,$_.Args,$_.RunAs) }
Get-ScheduledTask | Where-Object { ($_.TaskPath + $_.TaskName) -ne "\TCDC-Watch" } | ForEach-Object {
  $id=$_.TaskPath+$_.TaskName; $a=$_.Actions | Select-Object -First 1
  $cur="{0}|{1}|{2}" -f $a.Execute,$a.Arguments,$_.Principal.UserId
  if(-not $bt.ContainsKey($id)){ Alert ("NEW scheduled task: " + $id + " -> " + $cur) }
  elseif($bt[$id] -ne $cur){ Alert ("CHANGED task action: " + $id + " was[" + $bt[$id] + "] now[" + $cur + "]") }
}

# 3. services: NEW service, or CHANGED image path (review #9)
$bs=@{}; Import-Csv "$BK\services.base.csv" | ForEach-Object { $bs[$_.Name] = $_.PathName }
Get-CimInstance Win32_Service | ForEach-Object {
  if(-not $bs.ContainsKey($_.Name)){ Alert ("NEW service: " + $_.Name + " -> " + $_.PathName) }
  elseif($bs[$_.Name] -ne $_.PathName){ Alert ("CHANGED service image: " + $_.Name + " was[" + $bs[$_.Name] + "] now[" + $_.PathName + "]") }
}

# 4. run-key autoruns across ALL hives (same enumeration as baseline)
$baseRun = Get-Content "$BK\runkeys.base.txt" -ErrorAction SilentlyContinue
$cur=@()
$hklm=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
foreach($k in $hklm){ if(Test-Path $k){ (Get-Item $k).Property | ForEach-Object { $cur += "$k :: $_ = $((Get-ItemProperty $k).$_)" } } }
Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | ForEach-Object {
  $run="Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Run"
  if(Test-Path $run){ (Get-Item $run).Property | ForEach-Object { $p=$_; $cur += "$run :: $p = $((Get-ItemProperty $run).$p)" } }
}
foreach($line in $cur){ if($baseRun -notcontains $line){ Alert ("NEW autorun: " + $line) } }

# 5. AD privileged-group drift (reads snapshots ad-harden.ps1 wrote). DC only.
Get-ChildItem "$BK\grp.*.base.txt" -ErrorAction SilentlyContinue | ForEach-Object {
  $g = ($_.BaseName -replace '^grp\.','' -replace '\.base$','') -replace '_',' '
  $base = Get-Content $_.FullName
  try {
    Get-ADGroupMember $g -ErrorAction Stop | Select-Object -Expand SamAccountName | ForEach-Object {
      if($base -notcontains $_){ Alert ("NEW member of $g : " + $_) }
    }
  } catch {}
}

# 6. suspicious listeners (common C2 ports)
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in 4444,5555,8081,9001,1337,31337 } |
  ForEach-Object { Alert ("suspicious listener :" + $_.LocalPort + " pid=" + $_.OwningProcess) }
exit 0
