# TCDC Team 1 - Windows hardening (AD 2025 / Win11 MQTT). Idempotent. Run as Administrator.
# Usage: powershell -ep bypass -File harden.ps1 -Box mqtt [-ScoredPorts 1883] [-EnableDefaultDeny] [-Rebaseline]
# Does NOT change passwords (funnel those through the vault to keep /team/passwords in sync).
# Does NOT delete users/accounts (R8). Reports + baselines; surgical changes only.
#
# FIREWALL (review #2): default-deny is OFF unless you pass -EnableDefaultDeny. By default
# this only ENABLES the firewall and stages ALLOW rules for mgmt + scored ports, leaving the
# default inbound action unchanged so it CANNOT lock out a scored service or your RDP/WinRM.
# BASELINE (review #11): first run captures the accepted baseline; re-runs keep it and write a
# timestamped forensic snapshot instead. Pass -Rebaseline to deliberately accept current state.
param(
  [string]$Box = $env:COMPUTERNAME,
  [int[]]$ScoredPorts = @(),
  [int[]]$MgmtPorts = @(3389,5985,445,135),
  [switch]$EnableDefaultDeny,
  [switch]$Rebaseline
)
$ErrorActionPreference = "Continue"
$BK = "C:\tcdc-baseline"; New-Item -ItemType Directory -Force -Path $BK | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$log = "$BK\harden-$ts.log"
function Log($m){ $l="[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m; $l | Tee-Object -FilePath $log -Append }

Log "=== TCDC Windows harden box=$Box (DefaultDeny=$EnableDefaultDeny Rebaseline=$Rebaseline) ==="

# --- snapshot helpers (used for baseline AND forensic) ---
function Snap-Services($path){
  Get-CimInstance Win32_Service | Select-Object Name,PathName,StartName,StartMode,State |
    Export-Csv $path -NoTypeInformation
}
function Snap-Tasks($path){
  Get-ScheduledTask | ForEach-Object {
    $t=$_; $a=$t.Actions | Select-Object -First 1
    [pscustomobject]@{
      Id      = $t.TaskPath + $t.TaskName
      Exec    = $a.Execute
      Args    = $a.Arguments
      RunAs   = $t.Principal.UserId
      State   = $t.State
    }
  } | Export-Csv $path -NoTypeInformation
}
function Snap-RunKeys($path){
  $out=@()
  $hklm=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
  foreach($k in $hklm){ if(Test-Path $k){ (Get-Item $k).Property | ForEach-Object { $out += "$k :: $_ = $((Get-ItemProperty $k).$_)" } } }
  # enumerate EVERY loaded user hive (SYSTEM watcher sees HKU, not the operator's HKCU) - review #9
  Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | ForEach-Object {
    $run = "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Run"
    if(Test-Path $run){ (Get-Item $run).Property | ForEach-Object { $p=$_;
      $out += "$run :: $p = $((Get-ItemProperty $run).$p)" } }
  }
  $out | Out-File $path
}

# 1. Baseline (accepted on first run; forensic-only on re-runs unless -Rebaseline)
$firstRun = -not (Test-Path "$BK\services.base.csv")
if($firstRun -or $Rebaseline){
  Log "[1] capturing accepted baseline -> $BK\*.base.*"
  try { Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource |
        Export-Csv "$BK\admins.base.csv" -NoTypeInformation } catch { Log "  (not workgroup local-admins)" }
  Snap-Services "$BK\services.base.csv"
  Snap-Tasks "$BK\schtasks.base.csv"
  Snap-RunKeys "$BK\runkeys.base.txt"
  Log "    baselined admins/services(+path)/schtasks(+actions)/runkeys(all hives)"
} else {
  Log "[1] baseline EXISTS -> forensic snapshot only ($ts). Pass -Rebaseline to replace accepted baseline."
  try { Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource |
        Export-Csv "$BK\admins.forensic-$ts.csv" -NoTypeInformation } catch {}
  Snap-Services "$BK\services.forensic-$ts.csv"
  Snap-Tasks "$BK\schtasks.forensic-$ts.csv"
  Snap-RunKeys "$BK\runkeys.forensic-$ts.txt"
}

# 2. Report local admins (backdoor accounts)
Log "[2] local Administrators members:"
try { Get-LocalGroupMember Administrators | ForEach-Object { Log ("    " + $_.Name) } } catch {}

# 3. Report non-standard scheduled tasks + Run keys (C2 persistence)
Log "[3] scheduled tasks NOT under \Microsoft\ (review):"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.TaskPath -ne "\" } |
  ForEach-Object { Log ("    " + $_.TaskPath + $_.TaskName + "  [" + $_.State + "]") }
Log "[3b] Run-key autoruns:"
Get-Content "$BK\runkeys.base.txt" -ErrorAction SilentlyContinue | ForEach-Object { Log ("    " + $_) }

# 4. Listening ports (review for 4444/beacon)
Log "[4] listeners:"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort -Unique |
  ForEach-Object { Log ("    :" + $_.LocalPort + " pid=" + $_.OwningProcess) }

# 5. Enable auditing / logging (defense visibility) - safe, reversible
Log "[5] enabling audit logging"
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
wevtutil sl Security /ms:134217728 2>$null
Log "    audit policy + Security log size set"

# 6. Firewall - FAIL-SAFE (review #2): no default-deny unless explicitly asked
Log "[6] firewall"
cmd /c "netsh advfirewall export `"$BK\firewall-$ts.wfw`"" | Out-Null
Log "    exported current policy -> $BK\firewall-$ts.wfw (rollback: netsh advfirewall import that file)"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
$allowPorts = @($MgmtPorts + $ScoredPorts | Select-Object -Unique)
foreach($p in $allowPorts){
  New-NetFirewallRule -DisplayName "TCDC-allow-tcp-$p" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $p -ErrorAction SilentlyContinue | Out-Null
}
Log ("    staged inbound ALLOW rules for: " + ($allowPorts -join ", "))
if($EnableDefaultDeny -and $ScoredPorts.Count -gt 0){
  Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
  Log "    DEFAULT-DENY inbound ENABLED. VALIDATE scored service + RDP/WinRM externally NOW."
  Log "    if anything broke: netsh advfirewall import `"$BK\firewall-$ts.wfw`""
} else {
  Log "    default inbound UNCHANGED (no lockout). To default-deny: -ScoredPorts <p> -EnableDefaultDeny after confirming allow rules."
}

# 7. Install drift watch-agent scheduled task (every 2 min)
Log "[7] install watch-agent scheduled task"
$selfDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path $selfDir "watch-agent.ps1"
if(Test-Path $agent){
  Copy-Item $agent "$BK\watch-agent.ps1" -Force
  $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -File `"$BK\watch-agent.ps1`" -Box $Box"
  $trg = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2)
  Register-ScheduledTask -TaskName "TCDC-Watch" -Action $act -Trigger $trg -RunLevel Highest -Force -User "SYSTEM" | Out-Null
  if(Get-ScheduledTask -TaskName "TCDC-Watch" -ErrorAction SilentlyContinue){ Log "    TCDC-Watch task registered (2 min)" }
  else { Log "    !! TCDC-Watch registration not confirmed - run watch-agent manually" }
} else { Log "    !! watch-agent.ps1 not found alongside; copy manually" }

Log "=== harden done. Baselines in $BK ==="
Log "NEXT (via vault): rotate default passwords; AD -> run ad-harden.ps1; mirror to /team/passwords"
