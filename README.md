# TCDC Team 1 Toolkit

Preparation tools for TCDC SMC F26, November 7, 2026. Scoring: **80% service uptime, 20% injects**. The official packet permits reversible purple teaming; see [the attack playbook](purple-team.md). `toolsList.txt` is a reference catalog, not a list of installed, approved, or tested tools.

## What runs where

| Component | Purpose |
|---|---|
| `linux/harden.sh` | Local account audit, private file-integrity baseline, systemd watcher installation |
| `windows/harden.ps1` | Local account/firewall audit, private baseline, scheduled watcher installation |
| `windows/ad-harden.ps1` | DC group baseline and drift audit; optional explicit SMBv1/audit changes |
| `watchtower/monitor.py` | Service protocol checks and local dashboard; never a scorer guarantee |
| `watchtower/vault.py` | Local password records and manual dashboard-sync attestation |
| `firewall-opnsense.md`, `firewall-windows.md` | Manual policy review and recovery procedures |
| `purple-team.md` | Scope, permitted attack preparation, verification, and undo workflow |
| `blue-team-playbook.md` | Blue-team competition-day playbook: roles, timeline, Linux/Windows/AD/MQTT hardening, Wazuh triage, incident response |
| `linux/timecapsule.sh`, `linux/fleet.sh`, `linux/aide.sh` | Snapshot/diff/rollback and AIDE checks, run on every Linux box from the jumpbox (see `linux/TIMECAPSULE.md`) |
| `rotate_pass/` | PasswordRotate: Linux OS password rotation over SSH, logged to the team Sheet |
| `wazuh-agentless/` | Local agentless Wazuh: read-only SSH checks with a dashboard |

**Installers do not change SSH login settings, passwords, or firewall policy.** They install monitoring and capture the state that exists at installation. Review that state: a first baseline can already contain a compromise. Existing accepted baselines are preserved on reruns. A schema upgrade requires explicit `--rebaseline` / `-Rebaseline`, and archives the old evidence first.

## Install from a reviewed revision

Prefer staging a complete checkout via the permitted access path. Pin the same reviewed commit for every box; do not mix modules from different revisions. Do not log into personal GitHub accounts on competition infrastructure.

```sh
# Preparation, on your laptop:
git clone https://github.com/nickvitello/tcdc-team1
cd tcdc-team1
git checkout <reviewed-commit-sha>
python3 tests/regression_round2.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

On an in-scope Linux box, after staging `linux/` together:

```sh
sudo bash linux/harden.sh ssh-workstation
# Use ns1, ftp-archive, artifactorium, or ipcam as appropriate.
sudo /usr/local/sbin/tcdc-watch
sudo tail /root/tcdc-baseline/drift.log
```

Requires Python 3, Bash, systemd, and coreutils on the documented Ubuntu boxes. It writes local snapshots under `/root/tcdc-baseline`, installs two watcher files and a service/timer, and checks every minute. File bytes, modes, owners, symlink destinations and regular-file target bytes are compared. Directory symlink destinations are recorded, but arbitrary trees outside the configured roots are not recursively inventoried. This is a drift detector, not comprehensive endpoint protection. It does not replace or modify Wazuh/auditd.

On Windows, stage **all four files in `windows/` together**, then use an Administrator Windows PowerShell:

```powershell
& .\windows\harden.ps1 -Box mqtt
# On the DC instead:
& .\windows\harden.ps1 -Box ad
& C:\tcdc-baseline\ad-harden.ps1
Get-Content C:\tcdc-baseline\drift.log -Tail 30
Get-ScheduledTaskInfo -TaskName TCDC-Watch
```

The Windows watcher runs as SYSTEM every two minutes. It compares administrator SIDs, service configuration, exported scheduled-task definitions, loaded-user Run/RunOnce keys, and monitor-module hashes. AD group additions/removals and collection failures are reported. Unloaded user hives are outside this coverage. An attacker who disables the watcher can prevent its own alerts: check task/timer health independently.

`boot.sh` and `boot.ps1` remain download helpers. Set `TCDC_REF` (Linux) or `$Ref` (PowerShell) to a reviewed SHA and fetch the bootstrap at that **same SHA**. They default to `main` for compatibility; a local pinned checkout is the documented deployment path. Windows uses native PowerShell script invocation, with no `powershell.exe -File` array boundary.

## Review accounts by identity

The packet lists admins `washington`, `kennedy`, `teddy`, `lincoln`, `ross`; employees `streep`, `franklin`, `parks`, `armstrong`, `hamilton`, `mlk`, `tubman`, `manziel`, `deniro`, `bush`. Built-in/service/staff accounts can also exist. Five named admins plus ten employees does **not** mean every machine should contain exactly five administrator-group entries and ten enabled users. Audit names and effective rights, not only totals. Do not delete packet users; never change, disable, or remove `blackteam` or `whiteteam`.

Before accepting a new baseline, review current drift and the preserved evidence. Rebaseline only when the specific current state is approved:

```sh
sudo bash linux/harden.sh ssh-workstation --rebaseline
```
```powershell
& .\windows\harden.ps1 -Box mqtt -Rebaseline
# Separate acceptance for AD group membership:
& C:\tcdc-baseline\ad-harden.ps1 -Rebaseline
```

## Watchtower and passwords

The packet says to use the provided jumpbox for infrastructure access. Use only the staff-approved access path; do not assume direct laptop-to-service VPN routing is available or permitted. Watchtower needs network access to the eight listed endpoints; running it on a laptop is conditional on that access being allowed. Do not harden the jumpbox or use it to host attack infrastructure.

```sh
cd watchtower
cp config.example.json config.json
# Set the actual DNS query and service expectations; verify addresses against staff topology.
python3 monitor.py
# Dashboard: http://127.0.0.1:8787 (contains local passwords; do not expose its bind address).
```

Seven scored targets plus OPNsense reachability are configured. HTTP without an expected body and SSH banners show reachability only. LDAP anonymous refusal is degraded, not proof credentials work. DNS truncation is reported as unverified/down; there is no TCP fallback. No check substitutes for the official scorer's transactions. Webhooks should remain empty: host-derived data export needs staff authorization under R23.

From the repository root:

```sh
python3 watchtower/vault.py set <box> <user>        # hidden password prompt; Linux reset instruction
python3 watchtower/vault.py set <box> <user> --win  # local Windows
python3 watchtower/vault.py set <box> <user> --ad   # AD
# Run the printed reset command on the correct box, then update /team/passwords manually:
python3 watchtower/vault.py sync <box> <user>
# Monitor service credentials are separate; update them when that credential changes:
python3 watchtower/vault.py svc ftp-archive <user>
```

The box-side reset commands are interactive. Run them on the correct box after recording the same password in the vault; the generated instructions quote the actual username for you.

| Where | Example command | Prompts |
|---|---|---|
| Linux | `sudo passwd -- USERNAME` | Password and confirmation |
| Windows local | `net user USERNAME *` | Hidden password and confirmation |
| AD domain account | `net user USERNAME * /domain` | Hidden password and confirmation |
| AD PowerShell | `$p = Read-Host -AsSecureString "New password"`, then `Set-ADAccountPassword -Identity 'USERNAME' -Reset -NewPassword $p` | One hidden prompt; no confirmation |

Replace `USERNAME` with the intended account, preserve staff accounts, and update `/team/passwords` immediately after a successful reset. Prefer the vault's hidden prompt over a positional password; deleting history afterward does not guarantee removal of copies.

`sync` is your attestation, not an API integration or scorer verification. The vault is plaintext. Unix files are mode 0600; on Windows use a private user-profile directory with an appropriate NTFS ACL. Hidden prompts avoid secrets in command history. Staff accounts are rejected by the reset workflow.

## Packet scope and validation

Source: **TCDC SMC F26 Official Packet**, local Nov 3 copy, pp. 9–16. R6 and the service table list eight boxes (seven scored services and OPNsense); the p. 14 diagram also shows the access jumpbox at both `10.99.X.2` and `10.(100+X).40.22`. R16 protects it against use for attack infrastructure. Official Discord updates have equal authority; reconcile any announced changes with Black Team before acting. No later nine-box update was supplied for this audit.

- R6–R9: only the listed boxes; staff users, Wazuh/auditd, guest tools, dashboards and other infrastructure are out of scope for attack.
- R10: hands-on periods only, subject to staff updates.
- R11–R19: reversible purple teaming; no lockouts, destructive loss, infrastructure impersonation, DoS, or ARP spoofing. No C2 on the jumpbox.
- R20–R25: public custom tools submitted through Tool Links; free tools, no AI use during competition; no artifact/data export except screenshots/passwords; test outside competition infrastructure; no personal accounts on infrastructure.

CI runs Python/Bash fixtures on Ubuntu and Python plus PowerShell 5.1 parsing/helper/bootstrap fixtures on Windows, followed by actual installer and scheduled-watcher smoke tests on those disposable runners. It does not test a full Windows 11/DC/OPNsense deployment or the competition network. See [VALIDATION.md](VALIDATION.md) for checks and limits. Submit the public repository link through Tool Links before use; publication alone is not submission or approval.
