# TCDC Team 1 - Windows hardening (AD 2025 / Win11 MQTT). Idempotent. Run as Administrator.
# Usage: powershell -ep bypass -File harden.ps1 -Box mqtt
# Does NOT change passwords (funnel those through the vault to keep /team/passwords in sync).
# Does NOT delete users/accounts (R8). Reports + baselines; surgical changes only.
param([string]$Box = $env:COMPUTERNAME)
$ErrorActionPreference = "Continue"
$BK = "C:\tcdc-baseline"; New-Item -ItemType Directory -Force -Path $BK | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$log = "$BK\harden-$ts.log"
function Log($m){ $l="[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m; $l | Tee-Object -FilePath $log -Append }

Log "=== TCDC Windows harden box=$Box ==="

# 1. Baseline: local admins, services, scheduled tasks, Run keys
Log "[1] baseline snapshot -> $BK"
try { Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource |
      Export-Csv "$BK\admins.base.csv" -NoTypeInformation } catch { Log "  (not workgroup local-admins)" }
Get-Service | Select-Object Name,Status,StartType | Export-Csv "$BK\services.base.csv" -NoTypeInformation
Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Export-Csv "$BK\schtasks.base.csv" -NoTypeInformation
$runKeys = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
$(foreach($k in $runKeys){ if(Test-Path $k){ Get-Item $k | Select-Object -ExpandProperty Property |
  ForEach-Object { "$k :: $_ = $((Get-ItemProperty $k).$_)" } } }) | Out-File "$BK\runkeys.base.txt"
Log "    baselined admins/services/schtasks/runkeys"

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
# bump Security log size
wevtutil sl Security /ms:134217728 2>$null
Log "    audit policy + Security log size set"

# 6. Firewall ON (do not block the scored service port though)
Log "[6] firewall profiles -> on (default-in-block, out-allow)"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue

# 7. Install drift watch-agent scheduled task (every 2 min)
Log "[7] install watch-agent scheduled task"
$selfDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path $selfDir "watch-agent.ps1"
if(Test-Path $agent){
  Copy-Item $agent "$BK\watch-agent.ps1" -Force
  $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -File `"$BK\watch-agent.ps1`" -Box $Box"
  $trg = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration ([TimeSpan]::MaxValue)
  Register-ScheduledTask -TaskName "TCDC-Watch" -Action $act -Trigger $trg -RunLevel Highest -Force -User "SYSTEM" | Out-Null
  Log "    TCDC-Watch task registered (2 min)"
} else { Log "    !! watch-agent.ps1 not found alongside; copy manually" }

Log "=== harden done. Baselines in $BK ==="
Log "NEXT (via vault): rotate default passwords; AD -> run ad-harden.ps1; mirror to /team/passwords"
