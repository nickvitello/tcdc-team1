<#
.SYNOPSIS
  Stores (or updates) the SSH password Wazuh uses for each Linux box, then tests the login.

.DESCRIPTION
  Run after setup.ps1, and again every time that account's password is rotated
  (PasswordRotate, rotate_pass/), or the checks start failing. The password is typed hidden and handed
  to the container on stdin, so it never shows up in a command line.

.EXAMPLE
  .\register.ps1 -Team 5 -User washington
  .\register.ps1 -Team 5 -User washington -Boxes ns1,ipcam
#>
param(
  [Parameter(Mandatory)][ValidateRange(1,154)][int]$Team,
  [Parameter(Mandatory)][string]$User,
  [string]$WorkDir = "D:\wazuh-agentless",
  [string[]]$Boxes,
  [switch]$PerBoxPasswords
)
$ErrorActionPreference = "Stop"
if ($User -notmatch '^[a-z_][a-z0-9_.-]*$') { throw "User '$User' doesn't look like a Linux username" }
$SN = [IO.Path]::Combine($WorkDir, "wazuh-docker", "single-node")
if (-not (Test-Path (Join-Path $SN "docker-compose.yml"))) { throw "Run setup.ps1 first (no Wazuh in $WorkDir)" }

$net = 100 + $Team
$hosts = [ordered]@{
  "ns1"             = "10.$net.10.53"
  "ftp-archive"     = "10.$net.10.21"
  "artifactorium"   = "10.$net.10.80"
  "ssh-workstation" = "10.$net.10.22"
  "ipcam"           = "10.150.0.$Team"
}
if ($Boxes) {
  # accept "ns1,ipcam" as one string too (e.g. when launched with powershell -File)
  $Boxes = @($Boxes | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  $unknown = $Boxes | Where-Object { -not $hosts.Contains($_) }
  if ($unknown) { throw "Unknown box(es): $($unknown -join ', '). Known: $($hosts.Keys -join ', ')" }
}

function Read-Secret($prompt) {
  if ($env:TCDC_PASS) { return $env:TCDC_PASS }   # non-interactive use; normally you're prompted
  $s = Read-Host -AsSecureString $prompt
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

$shared = $null
if (-not $PerBoxPasswords) { $shared = Read-Secret "SSH password for $User (same on all boxes; use -PerBoxPasswords if not)" }

Push-Location $SN
$fails = 0
try {
  foreach ($name in $hosts.Keys) {
    if ($Boxes -and ($Boxes -notcontains $name)) { continue }
    $pw = if ($PerBoxPasswords) { Read-Secret "SSH password for $User on $name" } else { $shared }
    Write-Host -NoNewline ("{0,-16} " -f $name)
    $pw | docker compose exec -T wazuh.manager /usr/local/bin/tcdc-register.sh "$User@$($hosts[$name])"
    if ($LASTEXITCODE -ne 0) { $fails++ }
  }
} finally { Pop-Location; $shared = $null; $pw = $null }

Write-Host ""
if ($fails) {
  Write-Host "$fails box(es) failed the login test. Check the VPN is up and the password is current, then re-run for those boxes with -Boxes." -ForegroundColor Yellow
} else {
  Write-Host "All logins work. First results appear after one check interval (5 min by default)." -ForegroundColor Green
}
