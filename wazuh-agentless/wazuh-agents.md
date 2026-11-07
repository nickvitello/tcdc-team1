# Full Wazuh: our own agents on the Linux boxes (optional)

Everything else in this folder is **agentless**: Wazuh logs in over SSH and runs
checks. A full **agent** runs on each box all the time and adds:
- **real-time** file integrity monitoring (seconds, not 15 minutes)
- continuous log collection, analyzed by Wazuh's rules
- rootkit and anomaly checks, CIS configuration scoring
- package inventory with vulnerability (CVE) matching

**Default: don't use this.** It's an option kept ready in case Black Team allows
it and the conditions below hold. The agentless setup, timecapsule, AIDE and
etckeeper already cover the box side without anything running on the boxes.

## Before anything: the three conditions

1. **No organizer agent on the box.** R7 puts the organizers' Wazuh and auditd out
   of scope. A box can only run one Wazuh agent (same `/var/ossec`, same service),
   so installing ours over theirs would break theirs. Check every box:
   ```
   ./fleet.sh wazuh-agent check
   ```
   Any box reporting **OTHER** is off limits. Don't install, stop, edit or remove
   anything there. The install command also refuses on its own.
2. **Black Team says yes, in writing.** Ask: *"May we install our own Wazuh agent on
   Linux boxes that have no Wazuh agent, reporting to our own Wazuh server on the
   jumpbox? It installs a package and runs continuously, including during
   hands-off periods. Is that OK under R7, R10 and R23?"*
3. **The boxes can reach our Wazuh server** on TCP 1514 and 1515. From a laptop over
   the VPN they almost certainly can't, so in practice this means the server runs
   on the **jumpbox**. Our setup is a Windows PowerShell script, and doesn't run on
   a Linux jumpbox yet. The install step tests reachability itself and stops if
   the server can't be reached.

## How

1. On the Wazuh server: re-run setup with `-AcceptAgents` (keep your other
   switches). This opens TCP 1514/1515 and requires an enrollment password, which
   is generated once and saved outside the repo:
   ```
   .\setup.ps1 -Team X -User <user> -AsRoot -AcceptAgents
   type D:\wazuh-agentless\agent-enrollment-password.txt
   ```
2. On the jumpbox:
   ```
   ./fleet.sh wazuh-agent check                                  # every box must say NONE
   ./fleet.sh wazuh-agent install <wazuh-server-ip> <enrollment-password>
   ./fleet.sh wazuh-agent status
   ```
   The install, per box:
   - **refuses** if any agent exists
   - tests the connection to the server
   - adds Wazuh's apt repository, installs the pinned version 4.14.10, then
     **removes the repository again**, so an `apt upgrade` can't change the agent
   - names the agent `<hostname>-tcdc`, so nobody mistakes it for an organizer
     agent (R15)
   - tags the install with `/var/ossec/.tcdc-ours`
3. In the dashboard, open **Agents**: each box should appear as `<hostname>-tcdc`
   and **Active** within a minute or two.

## Risks, and what limits each one

| risk | mitigation |
|---|---|
| Breaking the organizers' agent (R7) | the `check` step; `install` refuses on any box with an agent; `remove` only touches installs tagged as ours |
| Agent runs as root: a new process and package an attacker could abuse | Wazuh's remote-command features are off by default and we don't enable them; **active response is off** in our server config (it can block IPs, which R18 forbids inbound); the enrollment password stops strangers enrolling |
| Uptime: CPU or disk load on a scored box | the agent is light, but watch the scoreboard for 15 minutes after installing; real-time file monitoring on busy directories is the usual culprit |
| Runs during hands-off periods (R10) | part of the Black Team question; if they say it must stop, `remove` it before 12:00, or don't use it |
| Box data leaving infrastructure (R23) | run the server on the jumpbox, not a laptop |
| The install needs internet on the box | `install` stops cleanly with an error if the repository can't be reached |
| The enrollment password appears briefly in the box's process list during install | it only allows enrolling an agent to *our* server; after all agents are enrolled, close the enrollment port by re-running setup without `-AcceptAgents` (enrolled agents need TCP 1514; check they stay **Active**, and if not, re-open with `-AcceptAgents`) |
| An attacker stops our agent | it shows as **Disconnected** in the dashboard within minutes, which is itself an alert; the agentless checks keep running independently |

## Rollback

- **One box, or all of them:** `./fleet.sh wazuh-agent remove` (use
  `BOXES=ns1 ./fleet.sh ...` for one). It stops and purges our agent and deletes
  `/var/ossec` **only if** our tag is there, plus our repository files.
- **The server side:** re-run `setup.ps1` without `-AcceptAgents` to close the
  ports.
- **Check afterwards:** `./fleet.sh wazuh-agent check` should say NONE everywhere,
  and the scoreboard should be unaffected.
