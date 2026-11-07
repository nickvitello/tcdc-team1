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
| `watchtower/monitor.py` | your laptop (over VPN) | poll all 8 services q15s, live dashboard, Discord alert, password vault |
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

## Drift / persistence detection
Both watch-agents re-check their baseline on a timer (Linux 60s, Windows 2min) and alert on:
new authorized_keys, new UID0 user, new/changed services, new systemd timers / scheduled tasks,
new Run-key autoruns, and listeners on common C2 ports (4444/5555/9001/1337/31337) — the
Metasploit/Sliver footprint. Alerts go to a LOCAL log (`/root/tcdc-baseline/drift.log`, `C:\tcdc-baseline\drift.log`). A `TCDC_WEBHOOK` hook exists but is OFF and NOT recommended: enabling it exports host-derived data (paths, account/service names, listeners) off-box, which R23 does not exempt. Do not enable without explicit staff approval.

## Rules compliance
- Scoped to our 8 boxes only (R6). No attacks on competition infra / test box (R7/R9).
- No DoS/ARP spoof (R19). Tools report to a LOCAL log only; off-box webhook OFF by default (R23).
- Tested in good faith pre-event on local VMs (R24). Free + public (R20). No AI at runtime (R21).

## Submit before Sat 08:00
Push public, then paste the repo URL into the TCDC **Tool Links** form.
