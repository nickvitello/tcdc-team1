# Blue team tabletop: attack, detection, response

A walk through what Red Team and rival teams are likely to try, phase by phase,
against our museum. For each step: how we see it, how we fix it, how an attacker
could get around that, and what we do about the workaround. Read it once tonight;
section numbers refer to [blue-team-playbook.md](blue-team-playbook.md).

What we have, referred to by name below:

| name | what it is |
|---|---|
| **fleet diff** | `./fleet.sh diff hardened now`, a timecapsule comparison against the hardened state |
| **AIDE** | `./fleet.sh aide check` |
| **etckeeper** | `./fleet.sh etckeeper diff hardened` |
| **Wazuh** | the agentless checks, if it's running |
| **Suricata** | OPNsense's alert-only IDS |
| **NetFlow** | OPNsense's flow reporting |
| **scoreboard / Watchtower** | uptime |

## Phase 0: the first minutes (08:00-08:15)

Every team and Red Team know the default passwords and the user list.

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| Password spray with the defaults across all teams' boxes | Suricata (SSH and web brute-force alerts); Wazuh `logs`; `last -a` | rotate every password in the first 15 minutes, admins first (PasswordRotate), then update the dashboard | log in **before** rotation and plant persistence in the first 2-5 minutes | `snap start` at 08:00 captures it; the first-pass hunt (section 4) looks for keys, cron jobs, UID 0 accounts and sudoers; review `fleet.sh diff start hardened` |
| Stay logged in through rotation (an existing SSH session doesn't care about a new password) | `who` / Wazuh `==LOGGED-IN==` | after rotating, kill sessions you don't recognize: `pkill -KILL -t <tty>`. Leave the scorer's short sessions alone | add an **SSH key**, which survives any password change | first-pass hunt of every `authorized_keys`, and Wazuh `==SSH-KEYS==` in root mode |
| Change *our* admin password first, to lock us out | rotation fails for that account; `fleet.sh` can't log in | Xen Orchestra console, then reset it; R12 forbids rivals locking us out, so report it to Black Team | they also change the other admins | rotate **all** admins in the first pass, and keep one known-good login per box written down |

## Phase 1: initial access through a scored service

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| Upload a webshell to artifactorium (an upload form, or FTP into the web root) | Suricata web alerts; Wazuh `==WEB-SCRIPTS==`; fleet diff / AIDE (new file) | delete it; block PHP execution in upload directories; close anonymous FTP **upload** (keep anonymous login if the scorer needs it) | **inject the code into an existing PHP file** instead of adding a new one, and reset the modified time so it doesn't look new | fleet diff and AIDE compare **content hashes**, so a changed file shows as `changed` whatever its timestamp; restore the web root: `fleet.sh restore artifactorium hardened /var/www` |
| Read a DNS zone transfer for a map of the network | Suricata (zone transfer alerts) | `allow-transfer { none; };` | query names one by one | nothing to stop; it only reveals what the packet already published |
| Anonymous MQTT publish to tamper with telemetry | Mosquitto log | password file plus ACLs, **only if** the scorer doesn't need anonymous access | if anonymous must stay open, they keep publishing | ACLs that limit anonymous users to the topics the scorer reads; ask Black Team what the check needs |
| Exploit an unpatched service | Suricata exploit alerts; then everything in phases 3-4 | upgrade just that package (`apt install --only-upgrade <pkg>`) after testing the service | a vulnerability without a signature | rely on host-side detection of what they do **next**: persistence and outbound connections |

## Phase 2: privilege escalation

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| Employees in `sudo`/`adm`, `NOPASSWD` sudo rules | first-pass hunt; Wazuh `==SUDOERS==` | remove from groups; delete the rules (`visudo -c` afterwards) | abuse a binary already allowed through sudo (see GTFOBins) | review `sudo -l -U <user>` for every packet user once; nobody needs more than the scorer does |
| A setuid binary that hands out a shell (GTFOBins) | `find / -perm -4000`; Wazuh `==SUID==`; AIDE | `chmod u-s` on anything that isn't a package default | use an existing one, so nothing new appears | compare the list against GTFOBins in the first pass, not just against our baseline |
| A writable cron script or service file run by root | fleet diff / AIDE (it changes) | fix ownership and permissions (root-owned, not world-writable); restore the file | modify it and restore it between our checks | the effect (a new key, user or listener) still shows in the next diff; check permissions in the first pass |

## Phase 3: persistence (where most of the game is)

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| New UID 0 or sudo user | Wazuh `==UID0==`/`==USERS==`; fleet diff | `userdel` (never a packet user, never blackteam/whiteteam) | give an **existing** packet user extra rights instead | `==SUDOERS==`, the groups section and password changes all show it |
| SSH key in someone's `authorized_keys` | Wazuh `==SSH-KEYS==` (root mode); fleet diff | delete the line | change `AuthorizedKeysFile` in sshd to a hidden file | Wazuh `==SSHD==` shows the effective setting; etckeeper / fleet diff show the sshd config change |
| Cron job, systemd timer or service | Wazuh `==CRON==`/`==TIMERS==`/`==UNIT-FILES==`; fleet diff | disable it, delete it, kill the process | **edit an existing unit** with an override file, or name it like a system service | unit files are hashed, so an edit shows as changed; check `systemctl cat <unit>` for override files |
| User-level systemd units (`~/.config/systemd/user`), shell startup files (`.bashrc`, `/etc/profile.d`) | `/etc/profile.d` and root's `.bashrc` were covered; per-user units and other users' `.bashrc` were **not** (fixed tonight, see "Gaps") | remove the entry | Python startup files (`*.pth`, `sitecustomize`) | rarely used in these events; AIDE covers `/usr/local`; accept the remaining risk |
| `ld.so.preload` or a PAM module that captures passwords | Wazuh `==PRELOAD==`/`==PAM==`; AIDE (PAM modules are hashed) | empty `ld.so.preload`; restore the PAM file and module; **rotate every password typed on that box since** | — | treat it as a full compromise of that box's credentials; tell Black Team |
| Replace a system binary (a backdoored `sshd` or `ps`) | AIDE; `debsums -c` | reinstall the package (`apt install --reinstall <pkg>`) | — | debsums compares against package checksums, so it catches this even if the replacement was in place before our baseline |

## Phase 4: disruption (going after our uptime)

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| Stop or kill a service | Wazuh `services` (1 min); Watchtower; scoreboard | `systemctl start`, then hunt for how they did it (cron? a timer?) | a timer that keeps stopping it | the persistence diff finds the timer; remove it first, then restart the service |
| **Change a packet user's password**, so the scorer's login fails | Wazuh `==PASSWORD-CHANGES==`; scoreboard red with the service otherwise healthy | reset it to the value on the dashboard (the password master list), or set a new one and update the dashboard | do it repeatedly | find **how** they get in (phases 1-3); rotate the account they're using |
| Subtle breakage: the service is up but wrong (a DNS record edited, a web page altered, an FTP file gone) | the scoreboard (the only true signal); fleet diff on zone files and the web root | restore from `hardened` | edit content the scorer checks but our diffs don't cover | the scoreboard is the referee: a check failing while the port is open means a content problem; compare against the hardened snapshot |
| Firewall rule on the box (`ufw deny 80`) or a changed OPNsense rule | scoreboard; fleet diff (`firewall.txt`); OPNsense audit log | remove the rule | — | the OPNsense owner checks rules against the 08:00 screenshot whenever scoring dips |
| Fill the disk | services start failing; `df -h` | delete their files (check `/tmp`, `/var/tmp`, the web root) | — | — |

## Phase 5: lateral movement

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| Reuse a password from one box on another | Wazuh `logs`; `last` on the other boxes | PasswordRotate gives **every box a different password** by default | target **washington**, which we deliberately keep the same everywhere for `fleet.sh` | accepted trade-off. If washington's password may have leaked (a PAM backdoor, a webshell reading files), rotate it everywhere at once and re-run `setup.ps1 -AsRoot` / `register.ps1` |
| Pivot from a compromised box to the jumpbox | Suricata; NetFlow | **block the server subnets (DMZ .10, internal .20, users .30) from reaching the management subnet (.40)** in OPNsense; R18 allows rules between our own subnets | — | the jumpbox and OPNsense GUI stay reachable only from management and the VPN |
| Pivot to AD with domain credentials found on a Linux box | AD events 4624/4625 | rotate domain passwords; see the Windows track below | — | — |

## Phase 6: hiding (defense evasion)

| attacker step | we see it with | we respond | attacker's workaround | our counter |
|---|---|---|---|---|
| Clear logs or shell history | a gap in the logs; Wazuh `logs` already shipped earlier lines off the box | — | — | that's the value of logs leaving the box: the jumpbox (or your PC) keeps what was already sent |
| Stop or tamper with **auditd or the organizers' Wazuh agent** | — | **don't fix it yourself** (R7): tell Black Team immediately | — | — |
| Edit or delete **our** baselines on the box (`/root/timecapsule`, `/root/aide`, `/etc/.git`) | diffs suddenly look clean, or a baseline is missing | restore the baseline from the jumpbox copy (`fleet.sh pull` keeps timecapsule snapshots, and now AIDE's database too) and re-run the check | — | three independent baselines (timecapsule, AIDE, etckeeper) are much harder to fake all at once; a missing baseline is itself an alert |
| **Replace `ps`, `ss`, `find` or `sha256sum`** so our checks see a fake picture (a userland rootkit) | `debsums -c`; AIDE (it uses its own hashing, not `sha256sum`) | reinstall the packages | a **kernel rootkit**, which hides files, processes and ports from everything on the box | the network can't be fooled: Suricata and NetFlow on OPNsense see the box's real traffic, and `==KERNEL-MODULES==` may catch it loading. If a box talks to an address nothing on it explains, assume a rootkit: store snapshot revert, and tell Black Team |
| Act between our checks, or during lunch | our checks compare **state**, not events | the 13:00 diff against `hardened` catches anything that is still there | do something and undo it before we look | only lasting changes matter for scoring and access; brief actions show up in shipped logs and Suricata |

## Phase 7: the store

| attacker step | we see it with | we respond |
|---|---|---|
| A rival buys a Xen Orchestra console lockout against us | consoles stop working | VPN plus SSH/RDP to every box; keep one known-good login per box written down |
| A rival points Red Team at us | more alerts | nothing different; the playbook still applies |
| We spend on a snapshot | — | buy one per critical box after hardening; it's the last-resort undo for a kernel rootkit or wrecked box |

## Windows track (ad, mqtt)

| attacker step | we see it with | we respond | workaround | counter |
|---|---|---|---|---|
| Password spray against domain users | 4625 bursts | rotate domain users early; update the dashboard | slow spraying | review 4625 events every round, not just bursts |
| Kerberoasting (cracking service-account passwords offline) | hard to see | long random passwords on every account with an SPN (`ad-harden.ps1` lists them) | — | rotate SPN accounts after rotating the admins |
| Add a user to Domain Admins | 4728/4732/4756; `ad-harden.ps1` drift | remove them | nest a group inside an admin group | review **nested** membership: `Get-ADGroupMember "Domain Admins" -Recursive` |
| Scheduled task, service, Run key | 4698, 7045; `harden.ps1` baseline | remove it | **WMI event subscription** (not covered by our scripts) | check `Get-CimInstance -Namespace root\subscription -ClassName __EventFilter` and `CommandLineEventConsumer` in the 30-minute round (section 5) |
| Disable Defender, or add an exclusion | `Get-MpPreference` exclusions | remove the exclusion, re-enable Defender | — | check every round |

## Gaps this exercise found, and what changed tonight

1. **Per-user systemd units and shell startup files** weren't checked by Wazuh.
   The `persistence` check now covers both.
2. **AIDE's database lived only on the box,** where an attacker could replace it.
   `fleet.sh pull` now copies it to the jumpbox too.
3. **Sessions that existed before a password rotation** survive it. The playbook's
   first 15 minutes now say to kill unknown sessions after rotating.
4. **Nothing stopped a compromised box from reaching the jumpbox.** The playbook
   now has the OPNsense rule (server subnets to management, blocked).
5. **Windows WMI persistence** wasn't checked. The playbook's Windows round now
   includes it.

**Accepted risks** (cheaper to live with than to fix tonight):
- washington's password is shared across boxes for `fleet.sh`
- a kernel rootkit blinds every on-box check; only the network side, and a
  store revert, can answer it
- Python startup-file persistence isn't checked
