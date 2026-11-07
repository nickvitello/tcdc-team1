# TCDC Team 1 Toolkit

Defensive tooling for TCDC SMC F26 (attack/defense, Sat Nov 7 2026). Public per rule R20.
All tools are plain scripts — **no AI, no network callbacks to us** (R21/R23 compliant).
Scoring is 80% uptime + 20% injects, so everything here serves **keep-services-up + catch-persistence**.

> **Setup once:** replace `nickvitello` everywhere with the real GitHub owner:
> `grep -rl nickvitello . | xargs sed -i '' 's/nickvitello/youruser/g'` (macOS) then push.

## What's here
| tool | runs where | does |
|------|-----------|------|
| `boot.sh` + `linux/` | each Linux box | baseline, audit keys/sudo/services, harden sshd, install drift watcher |
| `boot.ps1` + `windows/` | each Windows box | baseline admins/tasks/runkeys, audit, enable logging, firewall, drift watcher |
| `windows/ad-harden.ps1` | the DC only | surgical AD audit (SPNs, admin groups); `-Apply` for SMBv1-off + audit |
| `watchtower/monitor.py` | your laptop (over VPN) | poll 8 boxes q15s (7 scored + OPNsense reach-only), live dashboard, Discord alert, password vault |
| `watchtower/vault.py` | your laptop | the ONE funnel for password changes (keeps /team/passwords in sync) |
| `firewall-opnsense.md` | network lead | OPNsense playbook (no script — it's GUI) |

## Roles & the EXACT commands to paste (Discord-ready)
**Everyone runs their box one-liner in the first 10 minutes. Nick starts Watchtower.**

### Nick — Ops (laptop, over VPN)
```
git clone https://github.com/nickvitello/tcdc-team1 && cd tcdc-team1/watchtower
cp config.example.json config.json   # edit: set dns query name (webhook optional; see R23 note)
python3 monitor.py                    # open http://127.0.0.1:8787
```

### Linux-A — ssh-workstation + artifactorium
```
curl -sSL https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.sh | sudo bash -s ssh-workstation
curl -sSL https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.sh | sudo bash -s artifactorium
```

### Linux-B — ns1 (DNS) + ftp-archive
```
curl -sSL https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.sh | sudo bash -s ns1
curl -sSL https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.sh | sudo bash -s ftp-archive
```

### Network/cloud — opnsense (follow firewall-opnsense.md) + ipcam
```
curl -sSL https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.sh | sudo bash -s ipcam
```

### Windows lead — AD DC + MQTT (run in an Admin PowerShell)
```
# MQTT (Win11):
iex (irm https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/boot.ps1)
# AD DC (Win2025): run boot.ps1 (it stages modules at C:\tcdc-baseline), then:
powershell -ep bypass -File C:\tcdc-baseline\ad-harden.ps1          # report
powershell -ep bypass -File C:\tcdc-baseline\ad-harden.ps1 -Apply   # safe changes
```
> **Firewall is audit-only by default** (enabling it blindly can activate a latent Block policy and
> drop a scored service). `boot.ps1` STAGES verified allow rules for the box's scored ports but does
> not turn the firewall on. After confirming the scored service still answers, enable it:
> `harden.ps1 -Box mqtt -ScoredPorts 1883 -EnableFirewall` (add `-EnableDefaultDeny` only once validated).

## Account census (catch a rogue admin planted BEFORE you harden)
Baseline accepts whatever accounts exist at capture time. Our topology has **5 admins + 10 regular
users** per box — pass those so harden warns if the counts are already wrong (a 6th admin already
present would otherwise be blessed as legit):
```
sudo bash harden.sh <box> --expect-admins 5 --expect-users 10          # linux
powershell -ep bypass -File harden.ps1 -Box <box> -ExpectedAdmins 5 -ExpectedUsers 10   # windows
powershell -ep bypass -File ad-harden.ps1 -ExpectedDomainAdmins 5      # DC (Domain Admins)
```
WARN only — never deletes (R8). Adjust the numbers if a box's legit count differs.

## Password rule (read twice — this is where teams lose uptime)
NEVER change a password by hand. Always:
```
python3 watchtower/vault.py set <box> <user> '<newpass>'            # linux
python3 watchtower/vault.py set <box> <user> '<newpass>' --win      # windows local
python3 watchtower/vault.py set <box> <user> '<newpass>' --ad       # AD account
# it prints the box command. run it. update /team/passwords. then:
python3 watchtower/vault.py sync <box> <user>
```
Watchtower's vault tab flags anything NOT synced in red.

### The actual box-side command (what `vault.py set` prints)
Each resets a password **interactively** — it prompts for the new password, hides
your typing, and (Linux + `net user`) asks you to confirm. The secret never lands on
a command line, in shell history, or in `ps` output. Run these ON the box after you've
recorded the change in the vault:

| where | command | prompts |
|-------|---------|---------|
| **Linux** | `sudo passwd <user>` | New password → Retype |
| **Windows (local)** | `net user <user> *` | Type a password → Retype (hidden) |
| **AD (on the DC)** | `net user <user> * /domain` | Type a password → Retype (hidden) |
| **AD (PowerShell)** | `$p = Read-Host -AsSecureString "New password"`<br>`Set-ADAccountPassword -Identity <user> -Reset -NewPassword $p` | one prompt, **no** confirm (AD limitation — type carefully) |

> Prefer the interactive form over `vault.py set <box> <user> '<pass>'`: the inline form
> puts the secret in your shell history. If you use the inline form, record it then clear
> history. Either way, after the box change: update `/team/passwords`, then
> `python3 watchtower/vault.py sync <box> <user>`.

## Drift / persistence detection
Both watch-agents re-check their baseline on a timer (Linux 60s, Windows 2min) and alert on:
new authorized_keys, new UID0 user, new/changed services, new systemd timers / scheduled tasks,
new Run-key autoruns, and listeners on common C2 ports (4444/5555/9001/1337/31337) — the
Metasploit/Sliver footprint. Alerts go to a LOCAL log (`/root/tcdc-baseline/drift.log`, `C:\tcdc-baseline\drift.log`). A `TCDC_WEBHOOK` hook exists but is OFF and NOT recommended: enabling it exports host-derived data (paths, account/service names, listeners) off-box, which R23 does not exempt. Do not enable without explicit staff approval.

## Rules compliance
- Scoped to our 9 topology boxes only (R6): 7 scored services (ns1-dns, ipcam-http, ftp-archive,
  artifactorium, ssh-wkstn, ad-dc, mqtt) + OPNsense firewall + the jumpbox/gateway (both unscored,
  defend-only — the jumpbox is ours alone; outsiders cannot address it). No attacks on competition
  infra / test box (R7/R9).
- R8: NEVER change, disable, or delete blackteam/whiteteam (or root). Scripts here report+back up
  only; they never delete users, and the authorized_keys clear-hint explicitly excludes protected
  users. Firewall rules are port-based, never source-blocking the jumpbox/teams.
- No DoS/ARP spoof (R19). Tools report to a LOCAL log only; off-box webhook OFF by default (R23).
- Tested in good faith pre-event on local VMs (R24). Free + public (R20). No AI at runtime (R21).

## Submit before Sat 08:00
Push public, then paste the repo URL into the TCDC **Tool Links** form.
