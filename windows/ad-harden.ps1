# TCDC Team 1 - Active Directory hardening (Win Server 2025 DC). Run as Domain Admin on the DC.
# SURGICAL: never touches krbtgt, never disables service/computer accounts, never deletes users (R8).
# Reports + light safe changes only. Password rotation is MANUAL via the vault.
param([switch]$Apply,[switch]$Rebaseline,[int]$ExpectedDomainAdmins=-1)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$BK = 'C:\tcdc-baseline'
Protect-TcdcDirectory $BK
if($Rebaseline){ Write-Host ('Previous accepted evidence archived: ' + (Backup-TcdcBaseline $BK)) }
$ts = Get-Date -Format "yyyyMMdd-HHmmss"; $log="$BK\ad-harden-$ts.log"
function Log($m){ ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m) | Tee-Object $log -Append }
Import-Module ActiveDirectory -ErrorAction Stop

Log "=== AD harden (Apply=$Apply) ==="

# 1. Privileged group membership: capture baseline ONCE, then report drift (review #9)
foreach($g in "Domain Admins","Enterprise Admins","Administrators","Schema Admins","Account Operators"){
  try {
    $m = Get-ADGroupMember $g -ErrorAction Stop | Select-Object -Expand SamAccountName
    # Expected-count sanity check (WARN only; never deletes - R8). Topology: 5 Domain Admins.
    if($g -eq 'Domain Admins' -and $ExpectedDomainAdmins -ge 0 -and @($m).Count -ne $ExpectedDomainAdmins){
      Log "[grp] !! DOMAIN ADMINS COUNT MISMATCH: expected $ExpectedDomainAdmins, found $(@($m).Count) - possible pre-existing rogue DA. REVIEW."
    }
    $bf = "$BK\grp.$($g -replace ' ','_').base.txt"
    if((Test-Path $bf) -and -not $Rebaseline){
      $base = Get-Content $bf
      $added = @($m | Where-Object { $base -notcontains $_ })
      $removed = @($base | Where-Object { $m -notcontains $_ })
      if($added.Count -or $removed.Count){
        Log "[grp] $g : DRIFT vs baseline  added[$($added -join ', ')] removed[$($removed -join ', ')]  (current: $($m -join ', '))"
      } else {
        Log "[grp] $g : $($m -join ', ')  (matches baseline)"
      }
    } else {
      $m | Out-File $bf
      Log "[grp] $g : $($m -join ', ')  (baseline captured)"
    }
  } catch { Log "[grp] $g : FAILED: $($_.Exception.Message)"; throw }
}

# 2. Accounts with SPNs (kerberoast targets) + AS-REP-roastable (no preauth)
Log "[2] SPN accounts (kerberoastable):"
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName |
  ForEach-Object { Log ("    " + $_.SamAccountName) }
Log "[2b] DONT_REQ_PREAUTH (AS-REP roastable):"
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' |
  ForEach-Object { Log ("    " + $_.SamAccountName) }

# 3. Stale/suspicious: enabled accounts w/ pwd-never-expires, adminCount=1 not in known groups
Log "[3] adminCount=1 users (review for sneaky privilege):"
Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount |
  ForEach-Object { Log ("    " + $_.SamAccountName) }

# 4. Explicit changes (verify SMBv1 dependencies before using -Apply)
if($Apply){
  Log "[4] APPLY: enable DC audit + disable SMBv1 (operator confirmed dependencies)"
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
  auditpol /set /category:"Account Logon","Logon/Logoff","DS Access" /success:enable /failure:enable | Out-Null
  if($LASTEXITCODE -ne 0){ throw "auditpol failed" }
  Log "    done"
} else {
  Log "[4] report-only. Re-run with -Apply for SMBv1-off + audit."
}

Log "=== AD harden done. DO NOT reset krbtgt or service accounts. ==="
Log "Password resets: ONLY via vault, then update /team/passwords immediately (scored checks use these)."
