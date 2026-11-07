# Agentless Wazuh for the Linux boxes

A local Wazuh (in Docker) that logs into each of the 5 Linux boxes over SSH on a
schedule, runs read-only checks, and raises an alert in the Wazuh dashboard when
something changes:

- **every 5 min:** users and groups, UID 0 accounts, listening ports, enabled
  services, timers, cron, `/etc/sudoers.d`, `ld.so.preload`, setuid/setgid files,
  running programs (see `checks.sh`)
- **every 15 min:** file hashes of `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local`
  and `/var/www` (files the login user can read)

## What it does and doesn't do on the boxes

- **It logs in as the account you register** (normally your own), like you doing
  it by hand. It never uses sudo or su and never touches blackteam or whiteteam.
- **It installs nothing and writes nothing.** The checks are sent as
  `echo <base64> | base64 -d | bash`; decode it in `checks.sh`. Its shell
  session is ended in a way that keeps it out of `.bash_history`. The only trace
  is a normal SSH login entry.
- **It's a separate Wazuh** on your PC. It doesn't touch or imitate the
  organizers' Wazuh (R7, R15).
- **It doesn't run as root,** so it can't see `/etc/shadow`, other users'
  `authorized_keys`, `/etc/sudoers` or root's cron. Cover those with
  `linux/fleet.sh diff`.

**R23 caution:** this pulls box data (process lists, file diffs) onto the PC
running it. If that PC is a personal laptop rather than the jumpbox, get Black
Team's OK first.

## Requirements

- Windows with **Docker Desktop**, roughly 6 GB of free RAM for Docker, and about
  5 GB of disk space for images and data
- `git`, and the competition VPN connected
- **Docker's disk image off C:**. `setup.ps1` stops if it's still on C:. Move it in
  Docker Desktop > Settings > Resources > Advanced > Disk image location.

## Setup

PowerShell, from this folder:

```
.\setup.ps1 -Team <X> -User <your-linux-username>
.\register.ps1 -Team <X> -User <your-linux-username>
```

`setup.ps1` puts everything (the official wazuh-docker release, certificates,
generated config) in `D:\wazuh-agentless`, outside this repo, so nothing secret is
ever committed. The first run downloads about 4 GB.

`register.ps1` stores the SSH password inside the container and tests the login
to each box. Run it again whenever that account's password changes. If boxes have
different passwords, add `-PerBoxPasswords`. To redo specific boxes, use
`-Boxes ns1,ipcam`.

If PowerShell refuses to run the scripts, run this once for the current window:
`Set-ExecutionPolicy -Scope Process Bypass`.

## Viewing alerts

Open the dashboard at https://localhost:8443 and log in as `admin` /
`SecretPassword`. It's only reachable from this PC, and the browser warning about
its self-signed certificate is expected. Go to **Threat Hunting > Events** and
search for `agentless`.

- The first check on each box only records a baseline; alerts start from the
  second run.
- Process-list alerts are noisier than the rest.
- To check more or less often, re-run `setup.ps1` with `-DiffSeconds` and
  `-IntegritySeconds`.

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

## Stopping it

| command (in `single-node`) | effect |
|---|---|
| `docker compose stop` | pause; keeps everything |
| `docker compose down` | remove the containers; data and passwords kept |
| `docker compose down -v` | remove everything, including stored passwords |

Delete `D:\wazuh-agentless` afterwards to clean up completely.
