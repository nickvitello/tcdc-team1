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

# review #5: refuse to trust an old-format baseline silently - the schema differs, so the
# comparisons below would be meaningless. Make it loud.
$fmt = 0; if(Test-Path "$BK\baseline.fmt"){ try { $fmt = [int](Get-Content "$BK\baseline.fmt" -Raw) } catch {} }
if($fmt -lt 2){ Alert "baseline format v$fmt < v2 (old schema) - drift comparisons UNRELIABLE; re-run harden.ps1 to upgrade baseline" }

# review #7: SAME robust local-admins enumeration as harden.ps1 (Get-LocalGroupMember throws
# Win32Internal on orphaned SIDs in PS5.1). The scheduled watcher is a separate process, so it
# needs its own copy. Alert on enumeration FAILURE instead of swallowing it.
function Get-AdminNames {
  try { return (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object -Expand Name) }
  catch {
    $n = net localgroup Administrators 2>$null |
      Where-Object { $_ -and $_ -notmatch '^(Alias name|Comment|Members|-----|The command)' } |
      ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if($null -eq $n -or @($n).Count -eq 0){ throw "net localgroup returned nothing" }
    return $n
  }
}

# 1. new local admins
try {
  $base = (Import-Csv "$BK\admins.base.csv").Name
  Get-AdminNames | ForEach-Object {
    if($base -notcontains $_){ Alert ("NEW local admin: " + $_) }
  }
} catch { Alert ("local-admin enumeration FAILED - cannot verify Administrators group (" + $_.Exception.Message + ")") }

# 2. scheduled tasks: NEW task, or CHANGED action-list/principal (review #8).
# Compare the COMPLETE ordered action list (not first action) and do NOT exclude our own
# TCDC-Watch - it is in the baseline now, so we verify it against its known definition.
$bt=@{}; Import-Csv "$BK\schtasks.base.csv" | ForEach-Object { $bt[$_.Id] = ("{0}|{1}" -f $_.Actions,$_.RunAs) }
Get-ScheduledTask | ForEach-Object {
  $id=$_.TaskPath+$_.TaskName
  $acts = (@($_.Actions) | ForEach-Object { "{0} {1}" -f $_.Execute,$_.Arguments }) -join " ;; "
  $cur="{0}|{1}" -f $acts,$_.Principal.UserId
  if(-not $bt.ContainsKey($id)){ Alert ("NEW scheduled task: " + $id + " -> " + $cur) }
  elseif($bt[$id] -ne $cur){ Alert ("CHANGED task: " + $id + " was[" + $bt[$id] + "] now[" + $cur + "]") }
}

# 3. services: NEW service, or CHANGED image path / service account / start mode (review #8)
$bs=@{}; Import-Csv "$BK\services.base.csv" | ForEach-Object { $bs[$_.Name] = ("{0}|{1}|{2}" -f $_.PathName,$_.StartName,$_.StartMode) }
Get-CimInstance Win32_Service | ForEach-Object {
  $cur = "{0}|{1}|{2}" -f $_.PathName,$_.StartName,$_.StartMode
  if(-not $bs.ContainsKey($_.Name)){ Alert ("NEW service: " + $_.Name + " -> " + $cur) }
  elseif($bs[$_.Name] -ne $cur){ Alert ("CHANGED service: " + $_.Name + " was[" + $bs[$_.Name] + "] now[" + $cur + "]") }
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
# review #6: if this IS a DC but no group baseline exists, ad-harden.ps1 never ran - the AD
# drift loop would silently do nothing. Surface that as a monitoring failure.
$grpFiles = Get-ChildItem "$BK\grp.*.base.txt" -ErrorAction SilentlyContinue
$isDC = $false; try { $isDC = ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) } catch {}
if($isDC -and -not $grpFiles){ Alert "AD group baseline MISSING on a domain controller - run ad-harden.ps1 (AD drift is NOT being monitored)" }
$grpFiles | ForEach-Object {
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
