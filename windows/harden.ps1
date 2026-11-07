# Audit, private baseline, logging, and watcher installation. Firewall/SSH/accounts unchanged.
param(
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')][string]$Box=$env:COMPUTERNAME,
  [switch]$Rebaseline,
  # Legacy switches fail explicitly BEFORE any host changes; policy changes now require manual review.
  [switch]$EnableFirewall,[switch]$EnableDefaultDeny,
  [int[]]$ScoredPorts=@(),[int[]]$ScoredUdpPorts=@(),[int[]]$MgmtPorts=@(),
  # Expected account counts (topology: 5 admins + 10 users). WARN only; -1 = skip.
  [int]$ExpectedAdmins=-1,[int]$ExpectedUsers=-1
)
$ErrorActionPreference='Stop'
if($EnableFirewall -or $EnableDefaultDeny){ throw 'Automatic firewall activation removed. See firewall-windows.md; no changes made.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw 'Run as Administrator' }
$selfDir=$PSScriptRoot
foreach($name in 'common.ps1','watch-agent.ps1','ad-harden.ps1'){
  if(-not (Test-Path (Join-Path $selfDir $name))){ throw "Missing module $name; nothing installed" }
}
. (Join-Path $selfDir 'common.ps1')
$BK='C:\tcdc-baseline'
Protect-TcdcDirectory $BK
$ts=Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$log=Join-Path $BK "harden-$ts.log"
function Log($message){ "[$(Get-Date -Format HH:mm:ss)] $message" | Tee-Object -FilePath $log -Append }
$baseline=Join-Path $BK 'integrity.json'
$firstRun=-not (Test-Path $baseline)
$legacy=@(Get-ChildItem $BK -Filter '*.base.*').Count -gt 0
if($firstRun -and $legacy -and -not $Rebaseline){ throw 'Old baseline preserved. Review prior state, then run -Rebaseline. Watcher not replaced.' }
if(-not $firstRun -and -not $Rebaseline){ $accepted=Read-TcdcBaseline $baseline }
if($Rebaseline){ Log ("Previous accepted evidence archived: " + (Backup-TcdcBaseline $BK)) }
Log "=== TCDC audit/install box=$Box ==="
Log 'Firewall is audit-only. No profiles, defaults, or rules are changed.'
Get-NetFirewallProfile | ForEach-Object { Log ("{0}: Enabled={1} Inbound={2} Outbound={3}" -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction) }
Log 'Packet admins: washington, kennedy, teddy, lincoln, ross. Review identities and effective rights, not counts.'
Log 'Retain all packet users; never change blackteam/whiteteam. AD accounts are reported by ad-harden.ps1.'
if((Get-CimInstance Win32_OperatingSystem).ProductType -ne 2){
  Get-LocalUser | ForEach-Object { Log ("User {0}, Enabled={1}" -f $_.Name,$_.Enabled) }
}
# Optional expected-count sanity check (WARN only; never deletes - R8). Topology: 5 admins + 10 users.
# A rogue planted BEFORE audit would otherwise be captured into the accepted baseline as legitimate.
# DCs skip this (no local SAM) - use ad-harden.ps1 -ExpectedDomainAdmins instead.
if(($ExpectedAdmins -ge 0 -or $ExpectedUsers -ge 0) -and (Get-CimInstance Win32_OperatingSystem).ProductType -ne 2){
  $adminCount=@(Get-TcdcAdmins).Count
  $userCount =@(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }).Count
  Log ("account census: local admins={0}, enabled local users={1}" -f $adminCount,$userCount)
  if($ExpectedAdmins -ge 0 -and $adminCount -ne $ExpectedAdmins){ Log ("!! ADMIN COUNT MISMATCH: expected {0}, found {1} - possible pre-existing rogue admin. REVIEW before trusting baseline." -f $ExpectedAdmins,$adminCount) }
  if($ExpectedUsers  -ge 0 -and $userCount  -ne $ExpectedUsers ){ Log ("!! USER COUNT MISMATCH: expected {0}, found {1} - review local accounts." -f $ExpectedUsers,$userCount) }
}
# Report drift before replacing our module files; preserve accepted state on ordinary reruns.
if(-not $firstRun -and -not $Rebaseline){
  $current=Get-TcdcSnapshot $BK
  Write-TcdcJson $current (Join-Path $BK "forensic-$ts.json")
  Compare-TcdcSnapshot $accepted $current | ForEach-Object { Log $_ }
}
foreach($name in 'common.ps1','watch-agent.ps1','ad-harden.ps1'){
  $source=Join-Path $selfDir $name; $destination=Join-Path $BK $name
  if([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($destination)){ Copy-Item $source $destination -Force }
}
# Create only when missing. Never quietly rewrite a changed task into the accepted baseline.
$task=Get-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' -ErrorAction SilentlyContinue
if(-not $task){
  $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$BK\watch-agent.ps1`" -Box $Box"
  $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 2)
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User 'SYSTEM' | Out-Null
}
if($firstRun -or $Rebaseline){
  Write-TcdcJson (Get-TcdcSnapshot $BK) $baseline
  Log 'Baseline captured after installation. Initial state must be reviewed for pre-existing compromise.'
}
# Verify task state without assuming a successful registration proves execution.
if((Get-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\').State -eq 'Disabled'){ throw 'TCDC-Watch is disabled; review task before enabling' }
Start-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\'
Log "Watcher started. Check $BK\drift.log and Task Scheduler LastTaskResult. Baseline unchanged on ordinary reruns."
