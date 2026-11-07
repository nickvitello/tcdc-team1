# TCDC Team 1 - Windows hardening (AD 2025 / Win11 MQTT). Idempotent. Run as Administrator.
# Usage: powershell -ep bypass -File harden.ps1 -Box mqtt [-ScoredPorts 1883] [-EnableDefaultDeny] [-Rebaseline]
# Does NOT change passwords (funnel those through the vault to keep /team/passwords in sync).
# Does NOT delete users/accounts (R8). Reports + baselines; surgical changes only.
#
# FIREWALL (review #1): AUDIT-ONLY by default. Enabling the firewall at all can activate an
# existing (disabled) Block policy and drop a scored service, so we touch it ONLY when you
# pass -ScoredPorts/-ScoredUdpPorts. Then we CREATE + VERIFY allow rules FIRST, and enable the
# profile only with -EnableFirewall (default-deny only with -EnableDefaultDeny). TCP and UDP.
# BASELINE (review #11): first run captures the accepted baseline; re-runs keep it and write a
# timestamped forensic snapshot instead. Pass -Rebaseline to deliberately accept current state.
param(
  [string]$Box = $env:COMPUTERNAME,
  [int[]]$ScoredPorts = @(),
  [int[]]$ScoredUdpPorts = @(),
  [int[]]$MgmtPorts = @(3389,5985,445,135),
  [switch]$EnableFirewall,
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
  # review #8: capture the COMPLETE ordered action list, not just the first action, so an
  # appended second action (common C2 trick) changes the recorded value.
  Get-ScheduledTask | ForEach-Object {
    $t=$_
    $acts = (@($t.Actions) | ForEach-Object { "{0} {1}" -f $_.Execute,$_.Arguments }) -join " ;; "
    [pscustomobject]@{
      Id      = $t.TaskPath + $t.TaskName
      Actions = $acts
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

# robust local-admins enum (Get-LocalGroupMember throws Win32Internal on orphaned SIDs in PS5.1)
function Get-AdminMembers {
  try { return Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name,PrincipalSource }
  catch {
    net localgroup Administrators 2>$null |
      Where-Object { $_ -and $_ -notmatch '^(Alias name|Comment|Members|-----|The command)' } |
      ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); PrincipalSource = 'net-fallback' } } |
      Where-Object { $_.Name }
  }
}

# 1. Baseline (accepted on first run; forensic-only on re-runs unless -Rebaseline)
# review #5: baseline CSV schema is versioned. An old-format baseline (v<2: schtasks had
# Exec/Args columns, services had no joined compare) is INCOMPATIBLE with the current watcher,
# so re-capture it on upgrade instead of leaving the watcher comparing missing fields.
$BASELINE_FMT = 2
$fmtFile = "$BK\baseline.fmt"
$haveFmt = if(Test-Path $fmtFile){ try { [int](Get-Content $fmtFile -Raw) } catch { 0 } } else { 0 }
$firstRun = -not (Test-Path "$BK\services.base.csv")
$oldFormat = (-not $firstRun) -and ($haveFmt -lt $BASELINE_FMT)
if($firstRun -or $Rebaseline -or $oldFormat){
  if($oldFormat){ Log "[1] OLD baseline format v$haveFmt < v$BASELINE_FMT -> re-capturing baseline (schema upgrade). Forensic snapshots retained." }
  else { Log "[1] capturing accepted baseline -> $BK\*.base.*" }
  try { Get-AdminMembers |
        Export-Csv "$BK\admins.base.csv" -NoTypeInformation } catch { Log "  (not workgroup local-admins)" }
  Snap-Services "$BK\services.base.csv"
  Snap-Tasks "$BK\schtasks.base.csv"
  Snap-RunKeys "$BK\runkeys.base.txt"
  Set-Content $fmtFile $BASELINE_FMT
  Log "    baselined admins/services(+path+acct+startmode)/schtasks(+all actions)/runkeys(all hives) fmt=v$BASELINE_FMT"
} else {
  Log "[1] baseline EXISTS -> forensic snapshot only ($ts). Pass -Rebaseline to replace accepted baseline."
  try { Get-AdminMembers |
        Export-Csv "$BK\admins.forensic-$ts.csv" -NoTypeInformation } catch {}
  Snap-Services "$BK\services.forensic-$ts.csv"
  Snap-Tasks "$BK\schtasks.forensic-$ts.csv"
  Snap-RunKeys "$BK\runkeys.forensic-$ts.txt"
}

# 2. Report local admins (backdoor accounts)
Log "[2] local Administrators members:"
try { Get-AdminMembers | ForEach-Object { Log ("    " + $_.Name) } } catch {}

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

# 6. Firewall - AUDIT-ONLY by default (review #1)
Log "[6] firewall"
cmd /c "netsh advfirewall export `"$BK\firewall-$ts.wfw`"" | Out-Null
Log "    exported current policy -> $BK\firewall-$ts.wfw (rollback: netsh advfirewall import that file)"
# report effective policy so the operator SEES whether a disabled Block policy is lurking
foreach($pr in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)){
  Log ("    profile {0}: Enabled={1} DefaultInbound={2}" -f $pr.Name,$pr.Enabled,$pr.DefaultInboundAction)
}
if($ScoredPorts.Count -eq 0 -and $ScoredUdpPorts.Count -eq 0){
  Log "    AUDIT-ONLY: no -ScoredPorts/-ScoredUdpPorts given, firewall NOT touched. Enabling it can"
  Log "    activate an existing (disabled) Block policy and drop a scored service - so we don't guess."
  Log "    Re-run: harden.ps1 -Box $Box -ScoredPorts <tcp..> [-ScoredUdpPorts <udp..>] [-EnableFirewall] [-EnableDefaultDeny]"
} else {
  # CREATE + VERIFY allow rules FIRST, while the policy is still whatever it was (no window
  # where the profile is on but the rule is missing).
  $tcp = @($MgmtPorts + $ScoredPorts | Select-Object -Unique)
  $udp = @($ScoredUdpPorts | Select-Object -Unique)
  foreach($p in $tcp){
    New-NetFirewallRule -DisplayName "TCDC-allow-tcp-$p" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $p -ErrorAction SilentlyContinue | Out-Null
  }
  foreach($p in $udp){
    New-NetFirewallRule -DisplayName "TCDC-allow-udp-$p" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $p -ErrorAction SilentlyContinue | Out-Null
  }
  $missing = @()
  foreach($p in $tcp){ if(-not (Get-NetFirewallRule -DisplayName "TCDC-allow-tcp-$p" -ErrorAction SilentlyContinue)){ $missing += "tcp/$p" } }
  foreach($p in $udp){ if(-not (Get-NetFirewallRule -DisplayName "TCDC-allow-udp-$p" -ErrorAction SilentlyContinue)){ $missing += "udp/$p" } }
  if($missing.Count -gt 0){
    Log ("    !! allow-rule creation FAILED for: " + ($missing -join ", ") + " -> NOT enabling firewall. Fix and re-run.")
  } else {
    Log ("    verified ALLOW rules: tcp[" + ($tcp -join ",") + "] udp[" + ($udp -join ",") + "]")
    if($EnableFirewall -or $EnableDefaultDeny){
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
      Log "    firewall ENABLED (allow rules verified first)."
      if($EnableDefaultDeny){
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
        Log "    DEFAULT-DENY inbound ENABLED. VALIDATE NOW (externally): scored service, RDP/WinRM,"
        Log "    AND that white/black team + the jumpbox/checker can still reach this box (R8)."
        Log "    Default-deny is port-based (mgmt=$($MgmtPorts -join ',')); it blocks any other inbound port."
      }
      Log "    if anything broke: netsh advfirewall import `"$BK\firewall-$ts.wfw`""
    } else {
      Log "    allow rules STAGED but firewall left as-is (pass -EnableFirewall to turn it on after validating)."
    }
  }
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
  if(Get-ScheduledTask -TaskName "TCDC-Watch" -ErrorAction SilentlyContinue){
    Log "    TCDC-Watch task registered (2 min)"
    # review #8: fold our own task into the task baseline (captured in step 1 BEFORE this task
    # existed) so the watcher verifies TCDC-Watch against its known definition instead of
    # excluding it by name. Only on first/baseline capture, never on a plain re-run.
    if($firstRun -or $Rebaseline -or $oldFormat){ Snap-Tasks "$BK\schtasks.base.csv"; Log "    re-baselined tasks (now includes TCDC-Watch)" }
  }
  else { Log "    !! TCDC-Watch registration not confirmed - run watch-agent manually" }
} else { Log "    !! watch-agent.ps1 not found alongside; copy manually" }

Log "=== harden done. Baselines in $BK ==="
Log "NEXT (via vault): rotate default passwords; AD -> run ad-harden.ps1; mirror to /team/passwords"
