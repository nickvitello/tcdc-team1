# TCDC Team 1 - Active Directory hardening (Win Server 2025 DC). Run as Domain Admin on the DC.
# SURGICAL: never touches krbtgt, never disables service/computer accounts, never deletes users (R8).
# Reports + light safe changes only. Password rotation is MANUAL via the vault.
param([switch]$Apply)   # default = report only. -Apply does the safe changes.
$ErrorActionPreference = "Continue"
$BK = "C:\tcdc-baseline"; New-Item -ItemType Directory -Force -Path $BK | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"; $log="$BK\ad-harden-$ts.log"
function Log($m){ ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m) | Tee-Object $log -Append }
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Log "=== AD harden (Apply=$Apply) ==="

# 1. Privileged group membership snapshot + report (backdoors live here)
foreach($g in "Domain Admins","Enterprise Admins","Administrators","Schema Admins","Account Operators"){
  try {
    $m = Get-ADGroupMember $g -ErrorAction Stop | Select-Object -Expand SamAccountName
    $m | Out-File "$BK\grp.$($g -replace ' ','_').base.txt"
    Log "[grp] $g : $($m -join ', ')"
  } catch { Log "[grp] $g : (n/a)" }
}

# 2. Accounts with SPNs (kerberoast targets) + AS-REP-roastable (no preauth)
Log "[2] SPN accounts (kerberoastable):"
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName |
  ForEach-Object { Log ("    " + $_.SamAccountName) }
Log "[2b] DONT_REQ_PREAUTH (AS-REP roastable):"
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol |
  ForEach-Object { Log ("    " + $_.SamAccountName) }

# 3. Stale/suspicious: enabled accounts w/ pwd-never-expires, adminCount=1 not in known groups
Log "[3] adminCount=1 users (review for sneaky privilege):"
Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount |
  ForEach-Object { Log ("    " + $_.SamAccountName) }

# 4. Safe applies (only with -Apply)
if($Apply){
  Log "[4] APPLY: enable DC audit + disable SMBv1 (safe)"
  try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } catch {}
  auditpol /set /category:"Account Logon","Logon/Logoff","DS Access" /success:enable /failure:enable | Out-Null
  Log "    done"
} else {
  Log "[4] report-only. Re-run with -Apply for SMBv1-off + audit."
}

Log "=== AD harden done. DO NOT reset krbtgt or service accounts. ==="
Log "Password resets: ONLY via vault, then update /team/passwords immediately (scored checks use these)."
