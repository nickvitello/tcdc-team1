# Local-only drift watcher. No data export; returns nonzero if collection fails.
param([string]$Box=$env:COMPUTERNAME)
$ErrorActionPreference='Stop'
$BK=$PSScriptRoot
$out=Join-Path $BK 'drift.log'
function Alert($message){
  # Encode messages so a malicious name cannot insert a forged new log line.
  Add-Content $out ("[{0}] {1} DRIFT: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Box,($message | ConvertTo-Json -Compress))
}
try {
  . (Join-Path $BK 'common.ps1')
  $accepted=Read-TcdcBaseline (Join-Path $BK 'integrity.json')
  Compare-TcdcSnapshot $accepted (Get-TcdcSnapshot $BK) | ForEach-Object { Alert $_ }
  if((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2){
    Import-Module ActiveDirectory -ErrorAction Stop
    foreach($group in 'Domain Admins','Enterprise Admins','Administrators','Schema Admins','Account Operators'){
      $file=Join-Path $BK ("grp.{0}.base.txt" -f ($group -replace ' ','_'))
      if(-not (Test-Path $file)){ Alert "AD baseline MISSING: $group"; continue }
      $before=@(Get-Content $file)
      $after=@(Get-ADGroupMember $group -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName)
      foreach($member in $after){ if($before -notcontains $member){ Alert "NEW member of $group : $member" } }
      foreach($member in $before){ if($after -notcontains $member){ Alert "REMOVED member of $group : $member" } }
    }
  }
} catch {
  Alert ("MONITOR ERROR: " + $_.Exception.Message)
  exit 2
}
exit 0
