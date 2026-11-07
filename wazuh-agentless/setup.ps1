<#
.SYNOPSIS
  Sets up a local, agentless-only Wazuh that watches the team's 5 Linux boxes over SSH.

.DESCRIPTION
  Everything it creates goes in -WorkDir (default D:\wazuh-agentless), outside the repo:
  the official wazuh-docker checkout, TLS certificates and the generated config.
  Docker's own images/volumes live wherever Docker Desktop's disk image is; this
  script refuses to start if that is still on C: (use -AllowCDrive to override).

  Re-run it any time (e.g. to change -User or the check intervals): it is idempotent.

.EXAMPLE
  .\setup.ps1 -Team 5 -User washington
.EXAMPLE
  .\setup.ps1 -Team 5 -User washington -AsRoot
  Checks run through sudo (asks for the password once, hidden). Re-run this whenever
  that account's password is rotated, then run register.ps1 too.
.EXAMPLE
  .\setup.ps1 -Team 5 -User washington -AsRoot -AcceptSyslog -SyslogFrom 10.105.40.1/32
  Also listen for syslog (TCP 514) from OPNsense, e.g. its Suricata alerts and firewall log.
  Re-run without -AcceptSyslog to close the listener again. See opnsense-suricata.md.
.EXAMPLE
  .\setup.ps1 -Team 5 -User washington -AsRoot -AcceptAgents
  Also accept full Wazuh agents (TCP 1514/1515, password-protected enrollment).
  Read wazuh-agents.md FIRST: agents conflict with an organizer agent (R7).
  Re-run without -AcceptAgents to close the ports again.
.EXAMPLE
  .\setup.ps1 -Team 5 -User tester -Hosts @{ testvm = "192.168.56.10" }
  Point it at your own VM(s) instead of the competition boxes, for practice.
#>
param(
  [Parameter(Mandatory)][ValidateRange(1,154)][int]$Team,
  [Parameter(Mandatory)][string]$User,
  [string]$WorkDir = "D:\wazuh-agentless",
  [ValidateRange(60,86400)][int]$FastSeconds = 60,        # services.sh
  [ValidateRange(60,86400)][int]$ActivitySeconds = 120,   # network.sh, activity.sh
  [ValidateRange(60,86400)][int]$DiffSeconds = 300,       # accounts, persistence, logs
  [ValidateRange(60,86400)][int]$SlowSeconds = 900,       # packages.sh
  [ValidateRange(60,86400)][int]$IntegritySeconds = 900,  # file hashes
  [switch]$AsRoot,
  [hashtable]$Hosts,
  [switch]$AcceptSyslog,                 # open TCP 514 for syslog (e.g. from OPNsense)
  [switch]$AcceptAgents,                 # open TCP 1514/1515 for full Wazuh agents (see wazuh-agents.md)
  [string]$SyslogFrom,                   # who may send: one IP/CIDR, e.g. 10.105.40.1/32
  [switch]$AllowCDrive
)
$ErrorActionPreference = "Stop"
$Here = $PSScriptRoot
$WazuhTag = "v4.14.10"

function Run($what, [scriptblock]$cmd) {
  Write-Host "==> $what" -ForegroundColor Cyan
  & $cmd
  if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

if ($User -notmatch '^[a-z_][a-z0-9_.-]*$') { throw "User '$User' doesn't look like a Linux username" }

# --- 1. Docker running? ------------------------------------------------------
$ErrorActionPreference = "Continue"   # PS 5.1 throws on redirected native stderr under "Stop"
docker version --format '{{.Server.Version}}' 2>&1 | Out-Null
$dockerOk = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = "Stop"
if (-not $dockerOk) { throw "Docker isn't running. Start Docker Desktop and wait until it says 'Engine running'." }

# --- 2. Keep Docker's data off C: ---------------------------------------------
$onC = @(
  "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx",
  "$env:LOCALAPPDATA\Docker\wsl\data\ext4.vhdx",
  "$env:LOCALAPPDATA\Docker\wsl\main\ext4.vhdx"
) | Where-Object { Test-Path $_ }
if ($onC -and -not $AllowCDrive) {
  Write-Host ""
  Write-Host "Docker Desktop's disk image is on C: ($($onC -join ', '))." -ForegroundColor Yellow
  Write-Host "Wazuh's images and data (about 4-5 GB) would land there. To move it:" -ForegroundColor Yellow
  Write-Host "  Docker Desktop > Settings > Resources > Advanced > Disk image location > pick a folder on D:" -ForegroundColor Yellow
  Write-Host "  > Apply & restart, then run this script again." -ForegroundColor Yellow
  Write-Host "(Or re-run with -AllowCDrive to install on C: anyway.)" -ForegroundColor Yellow
  exit 1
}
try {
  $freeC = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
  $wdDrive = (Split-Path -Qualifier $WorkDir).TrimEnd(':')
  $freeW = [math]::Round((Get-PSDrive $wdDrive).Free / 1GB, 1)
  Write-Host "Free space: C: $freeC GB, ${wdDrive}: $freeW GB"
} catch { }   # informational only

# --- 3. Official wazuh-docker release, outside the repo -----------------------
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Repo = Join-Path $WorkDir "wazuh-docker"
if (-not (Test-Path (Join-Path $Repo ".git"))) {
  # autocrlf=false: these files are mounted into Linux containers, keep LF endings
  Run "Downloading wazuh-docker $WazuhTag" { git -c core.autocrlf=false clone --quiet --depth 1 --branch $WazuhTag https://github.com/wazuh/wazuh-docker $Repo }
}
$SN = Join-Path $Repo "single-node"

# --- 4. Our compose file, manager image and registration helper ---------------
foreach ($f in "docker-compose.yml", "Dockerfile.manager", "tcdc-register.sh") {
  Copy-Item -Force (Join-Path $Here $f) (Join-Path $SN $f)
}
# the syslog port is published only through this extra compose file, so leaving
# -AcceptSyslog off on a later run closes it again
$syslogCompose = Join-Path $SN "docker-compose.syslog.yml"
"services:`n  wazuh.manager:`n    ports:`n      - `"514:514/tcp`"`n" | Set-Content -NoNewline -Encoding ascii $syslogCompose
$agentsCompose = Join-Path $SN "docker-compose.agents.yml"
"services:`n  wazuh.manager:`n    ports:`n      - `"1514:1514/tcp`"`n      - `"1515:1515/tcp`"`n" | Set-Content -NoNewline -Encoding ascii $agentsCompose
$composeFiles = @("-f", "docker-compose.yml")
if ($AcceptSyslog) { $composeFiles += @("-f", "docker-compose.syslog.yml") }
if ($AcceptAgents) { $composeFiles += @("-f", "docker-compose.agents.yml") }

# --- 5. Agentless checks into the manager config -------------------------------
# Each checks\*.sh: drop comments/blank lines, add a marker line (so logs.sh can
# filter out the checks' own log entries), wrap it, then base64 it. Wazuh splits
# <arguments> on spaces and mangles words containing ; $ or quotes, so the typed
# line is just:  echo <base64> | base64 -d | bash
# The wrapper always ends by SIGKILLing its own login shell, so the command never
# reaches that account's .bash_history.
$sudoPw = $null
if ($AsRoot) {
  if ($env:TCDC_PASS) { $sudoPw = $env:TCDC_PASS } else {
    $sec = Read-Host -AsSecureString "sudo password for $User (checks run through sudo; stored only in this Wazuh's config)"
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { $sudoPw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }
  if (-not $sudoPw -or $sudoPw -match "['`r`n]") { throw "sudo password is empty or contains a quote/newline; not supported" }
}

$checks = @(
  @{ File = "services.sh";    State = "periodic_diff"; Freq = $FastSeconds },
  @{ File = "network.sh";     State = "periodic_diff"; Freq = $ActivitySeconds },
  @{ File = "activity.sh";    State = "periodic_diff"; Freq = $ActivitySeconds },
  @{ File = "accounts.sh";    State = "periodic_diff"; Freq = $DiffSeconds },
  @{ File = "persistence.sh"; State = "periodic_diff"; Freq = $DiffSeconds },
  @{ File = "logs.sh";        State = "periodic";      Freq = $DiffSeconds },
  @{ File = "packages.sh";    State = "periodic_diff"; Freq = $SlowSeconds }
)

function Get-CheckArgs($file) {
  $name  = [IO.Path]::GetFileNameWithoutExtension($file)
  $lines = Get-Content ([IO.Path]::Combine($Here, "checks", $file)) | ForEach-Object { $_.TrimEnd("`r") } |
           Where-Object { $_.Trim() -ne "" -and -not $_.TrimStart().StartsWith("#") }
  $inner = ": tcdc-agentless $name`n" + ($lines -join "`n") + "`n"
  # the log window matches how often logs.sh runs, so lines are seen once
  $inner = $inner.Replace("--since=-5min", "--since=-$($DiffSeconds)s")
  if ($AsRoot) {
    $esc = $inner.Replace("'", "'\''")
    # printf is a shell built-in: the password never appears in a process list
    $wrapper = "printf '%s\n' '" + $sudoPw + "' | sudo -S -p '' bash -c '" + $esc + "' 2>&1`n"
  } else {
    $wrapper = $inner
  }
  $wrapper += "kill -KILL `"`$PPID`"`n"
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($wrapper))
  if ($b64.Length -gt 3800) { throw "checks\$file is too long once encoded ($($b64.Length) chars); trim it" }
  return "echo $b64 | base64 -d | bash"
}

if ($Hosts) {
  $targets = [ordered]@{}; foreach ($k in ($Hosts.Keys | Sort-Object)) { $targets[$k] = [string]$Hosts[$k] }
} else {
  $net = 100 + $Team
  $targets = [ordered]@{
    "ns1"             = "10.$net.10.53"
    "ftp-archive"     = "10.$net.10.21"
    "artifactorium"   = "10.$net.10.80"
    "ssh-workstation" = "10.$net.10.22"
    "ipcam"           = "10.150.0.$Team"
  }
}
foreach ($ip in $targets.Values) { if ($ip -notmatch '^[0-9A-Za-z.-]+$') { throw "bad host '$ip'" } }
if ($AcceptSyslog) {
  if (-not $SyslogFrom) { $SyslogFrom = if ($Hosts) { throw "-AcceptSyslog with -Hosts needs -SyslogFrom" } else { "10.$(100 + $Team).40.1/32" } }
  if ($SyslogFrom -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { throw "-SyslogFrom must be an IPv4 address or CIDR, e.g. 10.105.40.1/32" }
}

$argsByCheck = @{}
foreach ($c in $checks) { $argsByCheck[$c.File] = Get-CheckArgs $c.File }

$sb = New-Object Text.StringBuilder
[void]$sb.AppendLine("  <!-- TCDC-AGENTLESS BEGIN (generated by setup.ps1; re-run it to change) -->")
foreach ($name in $targets.Keys) {
  $ip = $targets[$name]
  [void]$sb.AppendLine("  <!-- $name -->")
  foreach ($c in $checks) {
    [void]$sb.AppendLine("  <agentless>")
    [void]$sb.AppendLine("    <type>ssh_generic_diff</type>")
    [void]$sb.AppendLine("    <frequency>$($c.Freq)</frequency>")
    [void]$sb.AppendLine("    <host>$User@$ip</host>")
    [void]$sb.AppendLine("    <state>$($c.State)</state>")
    [void]$sb.AppendLine("    <arguments>$($argsByCheck[$c.File])</arguments>")
    [void]$sb.AppendLine("  </agentless>")
  }
  [void]$sb.AppendLine("  <agentless>")
  [void]$sb.AppendLine("    <type>ssh_integrity_check_linux</type>")
  [void]$sb.AppendLine("    <frequency>$IntegritySeconds</frequency>")
  [void]$sb.AppendLine("    <host>$User@$ip</host>")
  [void]$sb.AppendLine("    <state>periodic</state>")
  [void]$sb.AppendLine("    <arguments>/etc /usr/bin /usr/sbin /usr/local /var/www</arguments>")
  [void]$sb.AppendLine("  </agentless>")
}
if ($AcceptSyslog) {
  [void]$sb.AppendLine("  <!-- syslog listener (setup.ps1 -AcceptSyslog); only $SyslogFrom may send -->")
  [void]$sb.AppendLine("  <remote>")
  [void]$sb.AppendLine("    <connection>syslog</connection>")
  [void]$sb.AppendLine("    <port>514</port>")
  [void]$sb.AppendLine("    <protocol>tcp</protocol>")
  [void]$sb.AppendLine("    <allowed-ips>$SyslogFrom</allowed-ips>")
  [void]$sb.AppendLine("  </remote>")
}
[void]$sb.AppendLine("  <!-- TCDC-AGENTLESS END -->")
$sudoPw = $null

$conf = [IO.Path]::Combine($SN, "config", "wazuh_cluster", "wazuh_manager.conf")
$text = [IO.File]::ReadAllText($conf).Replace("`r`n", "`n")
$text = [regex]::Replace($text, '(?s)\s*<!-- TCDC-AGENTLESS BEGIN.*?<!-- TCDC-AGENTLESS END -->\n?', "`n")
# Agent enrollment always requires a password (Wazuh's default is open enrollment).
# Harmless when -AcceptAgents is off: the enrollment port isn't published then.
$text = $text.Replace("<use_password>no</use_password>", "<use_password>yes</use_password>")
if ($text -notmatch "<use_password>yes</use_password>") { throw "could not require an enrollment password in $conf" }
$at = $text.LastIndexOf("</ossec_config>")
if ($at -lt 0) { throw "can't find </ossec_config> in $conf" }
$text = $text.Substring(0, $at) + $sb.ToString().Replace("`r`n", "`n") + $text.Substring($at)
[IO.File]::WriteAllText($conf, $text, (New-Object Text.UTF8Encoding $false))
$mode = if ($AsRoot) { "through sudo (root)" } else { "as $User (no root)" }
Write-Host "==> $($checks.Count + 1) agentless checks per box written for: $($targets.Keys -join ', '), $mode"

# --- 6. Certificates (first run only) ------------------------------------------
Push-Location $SN
try {
  if (-not (Test-Path ([IO.Path]::Combine($SN, "config", "wazuh_indexer_ssl_certs", "root-ca.pem")))) {
    Run "Generating TLS certificates" { docker compose -f generate-indexer-certs.yml run --rm generator }
  }
  # --- 7. Start (or update) the stack ------------------------------------------
  Run "Building and starting Wazuh (first time downloads ~4 GB, be patient)" { docker compose @composeFiles up -d --build }
  # enrollment password: generated once, kept in the work dir (outside the repo), and
  # copied into the manager every run. Without it nobody can enroll an agent.
  $enrollFile = Join-Path $WorkDir "agent-enrollment-password.txt"
  if (-not (Test-Path $enrollFile)) {
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    -join (1..24 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] }) | Set-Content -NoNewline -Encoding ascii $enrollFile
  }
  $enrollPw = (Get-Content -Raw $enrollFile).Trim()
  $null = $enrollPw | docker compose @composeFiles exec -T wazuh.manager sh -c 'tr -d "\r" > /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass'
  if ($LASTEXITCODE -ne 0) { throw "could not store the agent enrollment password in the manager" }
  # the manager copies its config at start-up, so restart it to pick up changes
  Run "Restarting manager to load the agentless config" { docker compose @composeFiles restart wazuh.manager }
} finally { Pop-Location }

Write-Host ""
Write-Host "Done. Next:" -ForegroundColor Green
$hostArg = if ($Hosts) { " -Hosts <same as above>" } else { "" }
Write-Host "  1. Store the SSH password for '$User':   .\register.ps1 -Team $Team -User $User$hostArg"
if ($AsRoot) { Write-Host "     After any rotation of that password, re-run this script with -AsRoot AND register.ps1." -ForegroundColor Yellow }
if ($AcceptAgents) {
  Write-Host "  Agent ports open: TCP 1514/1515 on this machine. Enrollment password is in:" -ForegroundColor Yellow
  Write-Host "     $enrollFile"
  Write-Host "     Before installing any agent, follow wazuh-agents.md (check for an organizer agent FIRST, R7)." -ForegroundColor Yellow
  Write-Host "     To close the ports: re-run this script without -AcceptAgents."
}
if ($AcceptSyslog) {
  Write-Host "  Syslog listener: TCP 514 on this machine, accepting only $SyslogFrom." -ForegroundColor Yellow
  Write-Host "     Windows may ask to allow Docker through the firewall; allow it on the network the VPN uses." -ForegroundColor Yellow
  Write-Host "     To close it again: re-run this script without -AcceptSyslog."
}
Write-Host "  2. Dashboard (give it 2-3 minutes to come up): https://localhost:8443  (admin / SecretPassword)"
Write-Host "     Your browser will warn about the self-signed certificate; that's expected."
