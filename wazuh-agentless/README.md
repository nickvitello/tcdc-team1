# Agentless Wazuh for the Linux boxes

A local Wazuh (in Docker) that logs into each of the 5 Linux boxes over SSH on a
schedule, runs read-only checks, and raises an alert in the Wazuh dashboard when
something changes. It's one of several overlapping layers; the others are
`linux/timecapsule.sh`, AIDE, etckeeper and Watchtower. If one misses something
or stops working, the rest still cover it.

## What it checks

Each box gets 8 checks. The check scripts are in `checks/`; read them, they're
short.

| check | every | what it watches | needs root for |
|---|---|---|---|
| `services` | 1 min | scored and support services up or down; local ports 21/22/53/80/443/1883 open or closed | nothing |
| `network` | 2 min | listening ports (and which program), **outbound** connections (C2), `/etc/hosts`, DNS servers | program names on listeners |
| `activity` | 2 min | who is logged in and from where, executables in `/tmp`, `/var/tmp`, `/dev/shm`, script files in the web roots, running programs | some `/tmp` subfolders |
| `accounts` | 5 min | users, groups, UID 0 accounts, sudoers, **password changes**, **every user's SSH keys**, effective sshd settings | sudoers, password changes, keys, sshd |
| `persistence` | 5 min | cron (incl. per-user), timers, enabled services, unit files, `ld.so.preload`, PAM modules, `rc.local`, `profile.d`, setuid/setgid files, capabilities, kernel modules, apt sources | per-user cron |
| `logs` | 5 min | the last 5 minutes of system logs, **analyzed by Wazuh's ruleset** (SSH brute force, new users, sudo use, service errors) | reading other users' logs |
| `packages` | 15 min | installed packages (new tools like netcat or compilers) | nothing |
| file integrity | 15 min | hashes of readable files in `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local`, `/var/www` | always runs without root |

Every check except `logs` alerts on **changes**. Its first run only records a
baseline.

## Root or not: `-AsRoot`

Without `-AsRoot`, checks run as the account you register, so the root-only parts
above are empty. With `-AsRoot`, each check runs through `sudo` using that
account's password, as you would by hand.

- **The password never touches the box's disk or process list.** It's piped into
  `sudo` with a shell built-in.
- **It's stored in this Wazuh's config,** on the machine running Wazuh, next to the
  SSH password it already stores.
- **After rotating that account's password,** re-run `setup.ps1 -AsRoot` **and**
  `register.ps1`. Until you do, every check's output turns into sudo's "incorrect
  password" message (an alert within a minute), and each failed attempt is logged
  on the box.
- **No passwordless-sudo rule is ever added to the boxes:** that would be a
  standing weakness anyone in that account could use.

## What it does and doesn't do on the boxes

- **It logs in as the account you register,** normally your own. It never touches
  blackteam or whiteteam.
- **It installs nothing and writes nothing.** Each check is sent as
  `echo <base64> | base64 -d | bash`, and its session is ended in a way that keeps
  it out of `.bash_history`. The traces are normal SSH logins, plus sudo log
  entries in root mode. Those entries are tagged `tcdc-agentless` and the `logs`
  check filters them out.
- **It's a separate Wazuh** on your PC or the jumpbox. It doesn't touch or imitate
  the organizers' Wazuh or their agents (R7, R15).

## Rules

- **R23:** it pulls box data onto the machine running it. Run it on the jumpbox, or
  get Black Team's OK before running it on a personal laptop.
- **R10:** it logs in on a schedule, so **stop it during hands-off time**: run
  `docker compose stop` at 11:55 and 15:55, and `docker compose start` at 13:00.

## Requirements

- Windows with **Docker Desktop**, roughly 6 GB of free RAM for Docker, and about
  5 GB of disk space
- `git`, and the competition VPN connected
- **Docker's disk image off C:**. `setup.ps1` stops if it's still on C:. Move it in
  Docker Desktop > Settings > Resources > Advanced > Disk image location.

## Setup

PowerShell, from this folder:

```
Set-ExecutionPolicy -Scope Process Bypass        # if scripts are blocked
.\setup.ps1 -Team <X> -User <linux-user> -AsRoot  # or without -AsRoot
.\register.ps1 -Team <X> -User <linux-user>
```

`setup.ps1` puts everything (the official wazuh-docker release, certificates,
generated config) in `D:\wazuh-agentless`, outside this repo. The first run
downloads about 4 GB.

`register.ps1` stores the SSH password inside the container and tests the login
to each box. If boxes have different passwords, add `-PerBoxPasswords`; to redo
some boxes, use `-Boxes ns1,ipcam`.

**Practice against your own VM tonight:** add `-Hosts @{ testvm = "192.168.56.10" }`
to both commands, in place of the competition boxes.

**OPNsense logs into Wazuh (optional):** `-AcceptSyslog` opens a TCP 514 syslog
listener that accepts only OPNsense's address (`-SyslogFrom` to override).
Re-running setup without it closes the listener. The OPNsense steps, a
reachability test and the rollback are in `../opnsense-suricata.md`.

**Full agents (optional):** `-AcceptAgents` opens the agent ports with
password-protected enrollment. Read `wazuh-agents.md` first: agents can conflict
with an organizer agent (R7), and need Black Team's OK.

**Change how often checks run** by re-running setup with `-FastSeconds`,
`-ActivitySeconds`, `-DiffSeconds`, `-SlowSeconds` or `-IntegritySeconds` (all in
seconds).

## Viewing alerts

Open the dashboard at https://localhost:8443 and log in as `admin` /
`SecretPassword`. It's only reachable from this PC, and the browser warning about
its self-signed certificate is expected. Go to **Threat Hunting > Events** and
search for `agentless`. Each change alert names the box and check and shows the
changed lines under `==SECTION==` headings. See section 6 of
`blue-team-playbook.md` for what each section means and what to do about it.

## Troubleshooting

All commands below are run from `D:\wazuh-agentless\wazuh-docker\single-node`:

```
docker compose ps                                            # all 3 containers Up?
docker compose exec wazuh.manager grep -i agentless /var/ossec/logs/ossec.log | Select-Object -Last 20
docker compose logs --tail 50 wazuh.indexer
```

- **Indexer keeps restarting with `vm.max_map_count`:** run
  `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then
  `docker compose restart wazuh.indexer`.
- **register.ps1 says FAIL:** check the VPN is up. Test the network path from
  inside the container with
  `docker compose exec wazuh.manager ssh -o ConnectTimeout=5 <user>@<box-ip> exit`.
  A password prompt means routing works and the problem is the password.
- **Every alert says "incorrect password attempt":** the sudo password is stale.
  Re-run `setup.ps1 -AsRoot`.

## Stopping it

| command (in `single-node`) | effect |
|---|---|
| `docker compose stop` / `start` | pause and resume; keeps everything |
| `docker compose down` | remove the containers; data and passwords kept |
| `docker compose down -v` | remove everything, including stored passwords |

Delete `D:\wazuh-agentless` afterwards to clean up completely.
