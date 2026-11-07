# Blue team playbook: competition day

Companion to [purple-team.md](purple-team.md), which covers attacking other teams.

What to do, in what order, and how to respond. Detailed tool usage lives
elsewhere; this links to it rather than repeating it:

| need | doc |
|---|---|
| harden/audit scripts, Watchtower, password vault and reset commands | [README.md](README.md) |
| snapshots, diffs, rollback, `fleet.sh`, AIDE, etckeeper | [linux/TIMECAPSULE.md](linux/TIMECAPSULE.md) |
| Linux password rotation | [rotate_pass/README.md](rotate_pass/README.md) |
| agentless Wazuh setup | [wazuh-agentless/README.md](wazuh-agentless/README.md) |
| firewall changes | [firewall-opnsense.md](firewall-opnsense.md), [firewall-windows.md](firewall-windows.md) |

## 1. Ground rules (read once, follow all day)

- **Uptime is 80% of the score.** A service that's up but imperfect beats a
  hardened one that's down. Every change follows one loop: back up, change,
  syntax-check, reload, test it yourself, then watch one scoreboard tick (30 s)
  before the next change.
- **Never touch** `blackteam` or `whiteteam`, Wazuh/auditd, `xe-guest-utilities`
  or cloud-init (R7, R8). Don't delete packet users; rotate their passwords.
- **Hands-on only 08:00-12:00 and 13:00-16:00** (R10). That includes automated
  tools: stop Wazuh during lunch.
- **Every password change also goes to** https://dash.playtcdc.org/team/passwords.
  Checks may log in as any packet user, and we aren't told which.
- **No AI during the event** (R21). **No box data off competition
  infrastructure,** except screenshots and passwords (R23).
- **Firewall rules** (R18): an inbound block must apply to all sources, and an
  outbound block must name one IP and one port. No fail2ban, no default-deny
  outbound.
- **When unsure, ask Black Team before acting** (R17).

## 2. Roles

| role | owns | also |
|---|---|---|
| Linux A | ns1, ftp-archive | snapshots for all Linux boxes (`fleet.sh`) |
| Linux B | artifactorium, ssh-workstation, ipcam | Wazuh dashboard watch |
| Windows | ad, mqtt | AD password resets |
| Network + passwords | opnsense | password master list and dashboard updates |
| Injects | all injects (20% of score) | second pair of eyes on any risky change |

One person owns the **password list**. Nobody changes a password without
telling them.

## 3. Timeline

### Night before
- [ ] VPN, SSO, Xen Orchestra and the jumpbox work for everyone.
- [ ] Repo pushed, link submitted through the Tool Links form (R20).
- [ ] New passwords prepared (PasswordRotate generates its own).
- [ ] Wazuh tested end to end against a local VM (R24).
- [ ] Ask Black Team in writing about AI-assisted prep code (R21).

### 08:00-08:15: lock the doors
Rival teams know every default password, so speed matters.
1. **Snapshot first** (Linux A): `./fleet.sh snap start` then `./fleet.sh pull`
   on the jumpbox. Windows: run `windows/harden.ps1` (see README) for its
   baseline.
2. **Rotate passwords**, admins first:
   - Linux, in `rotate_pass/`, in this order:
     `python3 rotate.py rotate --users washington --same-across-boxes`, then
     `--users kennedy,teddy,lincoln,ross`, then `--users employees`. Never use
     `--users admins` or `all` after the first step: they would re-rotate
     washington with a different password per box, and `fleet.sh` and Wazuh
     need it identical everywhere.
   - Windows and AD: commands in README's reset table
   - OPNsense: GUI root/admin password

   Each new password goes on the dashboard immediately.
3. **OPNsense** (Network): restrict the web GUI to the management subnet, then
   block unused inbound ports for all sources. Keep the scored ports (53, 21, 80,
   22, AD's ports, 1883) and your own management access open.

### 08:15-09:00: hunt and harden
Work the first-pass lists in section 4 (Linux) and section 5 (Windows), one
change at a time. When done, record the known-good state four ways:
- `./fleet.sh snap hardened` then `./fleet.sh pull` (timecapsule)
- `./fleet.sh etckeeper install` then `./fleet.sh etckeeper commit hardened`
  (git history of `/etc`)
- `./fleet.sh aide install` then `./fleet.sh aide init` (AIDE file baseline)
- a store snapshot of the most critical boxes, if the team decides to spend on
  it (section 7)

etckeeper and AIDE need `apt` access on the boxes; if `apt` fails, skip them,
since timecapsule covers the same ground. Then start Wazuh (section 6).

### Steady state (09:00 onward)
Every 30 minutes, each owner runs:
- `./fleet.sh diff hardened now` (Linux A runs it for all Linux boxes)
- `./fleet.sh etckeeper diff hardened`: a second, independent view of `/etc`
- `./fleet.sh aide check` every hour or so. It's slower, but hashes far more
  files. After reviewing a change you made on purpose, run `./fleet.sh aide accept`
  and `./fleet.sh etckeeper commit <new-label>`.
- a quick Windows check: section 5's persistence and event commands
- a scoreboard look: anything red gets section 7, immediately

Between rounds: Wazuh alerts (Linux B), injects, deeper service hardening.

### 11:55 and 15:55
Finish the current change, verify the service, and stop Wazuh
(`docker compose stop`). Hands off at 12:00. At 13:00, start Wazuh
(`docker compose start`), run a diff against `hardened` on every box, then
resume.

## 4. Linux boxes

### First pass on every box (about 5 minutes)
```
ss -tulpn                                  # what's listening, and which program
passwd -S root                             # L = locked (good); P or NP = lock it: passwd -l root
awk -F: '$3==0' /etc/passwd                # any UID 0 besides root = backdoor
cat /etc/sudoers /etc/sudoers.d/*;  getent group sudo adm
cat /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys
ls /etc/cron* /var/spool/cron/crontabs; systemctl list-timers --all
cat /etc/ld.so.preload; grep -rn pam_exec /etc/pam.d
systemctl list-units --type=service --state=running
debsums -c 2>/dev/null                     # replaced binaries (if installed)
```
Then:
- Take employees out of `sudo`/`adm`.
- Clear unknown keys, cron jobs and timers. Remove a UID 0 account with
  `userdel` after checking it isn't a packet user.
- Don't change login shells or lock packet users: checks may log in as them.

### Per service
**ns1 (DNS).** Find the zone in `named.conf.local` and keep a copy of the zone
file; the checker queries those records. In `named.conf.options`, set
`allow-transfer { none; };` and `allow-recursion { none; };` (or limit recursion
to your subnets). Then `named-checkconf && rndc reload` and test with
`dig @localhost <record>.<zone>`.

**ftp-archive (FTP).** If `anonymous_enable=YES`, leave it on (the checker may
use it) but set `anon_upload_enable=NO`, `anon_mkdir_write_enable=NO` and
`chroot_local_user=YES`. Look for FTP-writable directories that are also served
by the web server. Test with `curl ftp://user:pass@localhost/` and anonymously.

**artifactorium (HTTP).**
- Hunt webshells:
  `grep -rlE 'eval\(|base64_decode|shell_exec|system\(|passthru' /var/www`
  and `find /var/www -newer /etc/hostname -type f`
- Block PHP execution in upload directories.
- Change any default admin login on the app itself (a service password, so
  update the dashboard).
- `www-data` must not be in any privileged group.
- Test: `curl -s localhost/ | head`, plus `apachectl configtest` or `nginx -t`.

**ssh-workstation (SSH).** `PermitRootLogin no`. Keep password authentication
on and don't add `AllowUsers` (the checker's user is unknown). Check
`sshd -T | grep -i authorizedkeysfile` for a redirected key file. Run `sshd -t`
before reloading, and **keep a second session open**.

**ipcam (HTTP, in the cloud subnet).** OPNsense doesn't protect it, so use the
host firewall. Allow rules first, then default deny:
`ufw allow 22; ufw allow 80; ufw default deny incoming; ufw enable`.
Confirm the real HTTP port with `ss -tulpn` first.

## 5. Windows: ad and mqtt

Baseline and audit with `windows/harden.ps1` and `windows/ad-harden.ps1`
(README). Change firewall policy only per firewall-windows.md.

### Both boxes
```powershell
Get-LocalGroupMember Administrators                       # mqtt; on the DC use AD groups below
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select LocalAddress,LocalPort,OwningProcess
Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' | Select TaskPath,TaskName,State
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run, HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'Windows\\|Program Files' } | Select Name,PathName,StartName
Get-MpComputerStatus | Select RealTimeProtectionEnabled; Get-MpPreference | Select ExclusionPath,ExclusionProcess
Get-LocalUser | Select Name,Enabled                       # Guest should be disabled
```
- An exclusion in Defender that you didn't add is an attacker hiding a tool.
- Sysinternals Autoruns shows all persistence in one place, if you've staged it.

**Events to watch.** Security log: 4720 (user created), 4728/4732/4756 (added
to a group), 4698 (scheduled task created), 1102 (log cleared), 4625 (failed
logon). System log: 7045 (service installed).
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732,4756,4698,1102} -MaxEvents 30 | Format-List TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 10 | Format-List TimeCreated,Message
```

### ad (domain controller)
```powershell
Get-ADGroupMember "Domain Admins"; Get-ADGroupMember "Enterprise Admins"; Get-ADGroupMember "Administrators"
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName   # kerberoastable
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}                                  # AS-REP roastable
Get-ADComputer -Filter {TrustedForDelegation -eq $true}                               # unconstrained delegation (DCs are expected)
Get-SmbServerConfiguration | Select EnableSMB1Protocol,RequireSecuritySignature
```
- Remove unexpected members of the admin groups. Keep packet admins and staff
  accounts, and confirm a name with the team before removing it.
- Turn off "do not require Kerberos preauthentication" on users that have it.
- `Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force`
- Disable the print spooler on the DC if nothing needs it:
  `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`
- **Don't reset krbtgt** or computer/service accounts: it can break the domain,
  and the AD check with it.
- Domain password resets go on the dashboard like any other.

### mqtt (Windows 11, Mosquitto)
- The config is usually `C:\Program Files\mosquitto\mosquitto.conf`. Before
  changing anything, check how the broker is used: whether a `password_file`
  exists and whether `allow_anonymous` is set. The checker may connect
  anonymously or with a user.
- If it uses a password file, rotate those users with `mosquitto_passwd` and
  record them on the dashboard.
- Restart with `Restart-Service mosquitto`, then test:
  `mosquitto_sub -h 127.0.0.1 -t '#' -C 1 -W 5 -v`, adding `-u`/`-P` if needed.
- Disable LLMNR (registry `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`,
  `EnableMulticast` = 0), and check RDP requires Network Level Authentication.

## 6. Wazuh (agentless)

Set up per wazuh-agentless/README.md. Run it on the jumpbox, or on a laptop only
with Black Team's OK (R23).

Each box gets 8 checks on their own schedules: services every minute; network
and activity every 2 minutes; accounts, persistence and logs every 5 minutes;
packages and file hashes every 15 minutes. Run it with `-AsRoot` so it can see
sudoers, password changes, every user's SSH keys and the system logs.

**Daily rhythm.** Start it at 08:15, after passwords are rotated and you've run
`register.ps1`. Stop it at 11:55 and 15:55; start it again at 13:00 (R10).
After any rotation of the account it logs in as, re-run `setup.ps1 -AsRoot` and
`register.ps1`, or every check reports "incorrect password".

**Triage.** Open Threat Hunting > Events and search `agentless`. Each alert names
the box and shows the changed lines.

| alert shows | likely meaning | do |
|---|---|---|
| `==SERVICES==` shows a service not `running`, or `==LOCAL-PORTS==` shows a scored port `closed` | service down | section 7 now: `systemctl status`, restore config, restart |
| sudo "incorrect password attempt" on every check | stored sudo password is stale | re-run `setup.ps1 -AsRoot` and `register.ps1` |
| new line under `==UID0==` | backdoor root account | `userdel`, then hunt for how it got there |
| new line in `==USERS==` | new account | if not yours: remove, check sudo and keys |
| `==SUDOERS==` change | someone granted sudo | remove the line or file (`visudo -c` after) |
| `==PASSWORD-CHANGES==` change | a password changed | ours? fine (and on the dashboard?). Not ours: rotate it now and update the dashboard |
| `==SSH-KEYS==` change | key added to an account | remove it unless a teammate added it |
| `==SSHD==` change | SSH settings weakened | restore `sshd_config` (timecapsule or etckeeper), `sshd -t`, reload |
| new `==OUTBOUND==` address | the box is connecting out: possible C2 | `ss -tnp` to find the program, kill it, remove its persistence |
| new `==LOGGED-IN==` user or source | someone is on the box | not a teammate? kill the session (`pkill -KILL -t <tty>`), rotate that password |
| new `==TMP-EXECUTABLES==` file | dropped payload | check what runs it (`ps`, cron, timers), then delete it |
| new `==WEB-SCRIPTS==` file | possible webshell | read it; remove it if it isn't part of the site |
| new `==UNIT-FILES==` hash or `==SERVICES-ENABLED==` entry | systemd persistence | `systemctl cat <unit>`, disable it, remove it |
| `==PAM==` change | password-stealing module | restore from timecapsule or etckeeper; tell Black Team |
| `==KERNEL-MODULES==` change | possible rootkit | escalate to the team; snapshot revert may be needed |
| `==CAPABILITIES==` change | privilege escalation | `setcap -r <file>` unless it's a package default |
| `packages` change | new tool installed (netcat, nmap, gcc) | ours? fine. Not ours: hunt for what it was used for |
| `logs` alerts (SSH brute force, sudo, new user) | Wazuh's own rules fired on system logs | check the source IP and account; rotate if anything got in |
| new `==LISTENERS==` port | backdoor or bind shell | `ss -tulpn` on the box, kill and remove the program |
| new `==CRON==` or `==TIMERS==` entry | persistence | remove it; check `fleet.sh diff` for its payload |
| new `==SUID==` file | privilege escalation backdoor | `chmod u-s`, then remove it if it's not a package file |
| `==PRELOAD==` not empty | library injection | empty `/etc/ld.so.preload`, find the library |
| `==PROCESSES==` change | often noise (someone ran a program) | glance; act only if it's unfamiliar and stays |
| integrity: file changed | config edit or replaced binary | `fleet.sh diff hardened now` or `fleet.sh aide check`, then restore (section 7) |

If an alert is our own change, note it so nobody chases it.

## 7. When something breaks or gets popped

1. **Detect:** the scoreboard is red, a diff or AIDE check shows a change, or
   Wazuh alerts.
2. **Restore service first, investigate second:**
   - service down: `systemctl status <svc>` and `journalctl -u <svc> -n 50`;
     on Windows `Get-Service`.
   - config tampered with: `./fleet.sh restore <box> hardened <path>`, then
     syntax-check and reload. For files under `/etc`, an independent second
     option is `./fleet.sh etckeeper restore <box> hardened <path>`; use it if
     the timecapsule copy is missing, or looks wrong.
   - account files can't be restored (by design); fix accounts with
     `userdel`, `usermod` and `gpasswd -d`.
3. **Evict:**
   - rotate the password of any account involved, and update the dashboard
   - remove keys, cron jobs, timers, services and webshells
   - kill the processes
4. **Verify:** service test, one green scoreboard tick, and a clean
   `fleet.sh diff hardened now`.
5. **Record it** in team chat: time, box, what happened, what you changed. Some
   injects ask for exactly this.
6. **Last resort:** a store snapshot revert (below).

### Store snapshots and reverts
The store at https://dash.playtcdc.org/team/store sells box snapshots and
reverts. Currency is fixed and can't be earned back, so plan before spending.

- **What it is:** a hypervisor-level copy of the whole VM, outside anything red
  team can reach from inside the box. It's the most independent layer we have.
- **When to buy:** right after hardening (once `snap hardened` is taken), for the
  boxes that would hurt most to rebuild. Suggested order: **ad**, then
  **artifactorium**, then whatever has needed the most repair by midday.
- **When to revert:** only when the box is unrecoverable by other means:
  timecapsule and etckeeper restores failed, or the box won't boot or accept
  logins. Revert costs downtime too.
- **After a revert, everything since the snapshot is undone**, passwords
  included:
  1. Re-enter that box's passwords on the dashboard as they were at snapshot time
     (the password master list's history has them). PasswordRotate's
     `state.json` and Sheet will also be ahead of the box, so note it in the
     Sheet.
  2. Re-run `register.ps1` for that box if Wazuh uses a rotated password.
  3. Take fresh baselines: `snap`, `etckeeper commit` and `aide accept` with a new
     label, and re-pull.
  4. Re-check for anything red team planted before the snapshot was taken.
- **Store disputes go to Black Team.**

## 8. Passwords: one master list

PasswordRotate logs Linux passwords to the team Google Sheet. The README's
`vault.py` keeps its own local list. Pick **one master list** for the team
(suggested: the Sheet), and add Windows, AD, OPNsense and app passwords to it as
they change, so nobody has to check two places. The dashboard must match it.

## 9. Injects (20%)

The injects owner reads each one as it arrives, sets a timer for its deadline,
pulls in whoever owns the box, and submits at
https://dash.playtcdc.org/team/injects. Read the rubric and answer exactly what
it asks; a timely, complete answer beats a perfect late one.
