# Purple-team preparation and operating playbook

The official packet permits attacking other teams' matching topology boxes, with reasonably reversible actions (pp. 6, 9–10). Scoring is uptime 80% and injects 20%; the packet does not specify separate attack points. Protect your own uptime and inject deadlines first.

## What this repository supplies

`toolsList.txt` is a broad discovery catalog. It includes free, paid, hosted, and offensive products; inclusion is not approval. This repository supplies **no tested exploit, persistence, C2, password-spray, or sabotage automation**. The defensive scripts must not be run on another team's boxes. This playbook provides preparation, scope tracking, low-impact discovery, and an undo process.

Free tools worth rehearsing in your own disposable lab: Nmap for limited service identification, curl for HTTP, standard DNS clients, and protocol-native clients for SSH/FTP/LDAP/MQTT. Read their options and test them on local fixtures first. Use only locally operated tools and staff-authorized access paths; do not upload competition artifacts to hosted analysis sites.

## Scope worksheet

Before an operation, record locally: operator, target team, exact hostname/IP, matching packet box, service, planned action, expected effect, rollback, and stop condition. Resolve addresses from the staff-provided topology. Do not guess a team range, scan subnets, or include the jumpbox, scoring/dashboard, Discord, Xen Orchestra, cloud-init/guest utilities, Wazuh/auditd, or staff accounts.

Matching boxes listed in the packet:

| Host | Service | Address template |
|---|---|---|
| ns1 | DNS | 10.(100+X).10.53 |
| ipcam | HTTP | 10.150.0.X |
| ftp-archive | FTP | 10.(100+X).10.21 |
| artifactorium | HTTP | 10.(100+X).10.80 |
| ssh-workstation | SSH | 10.(100+X).10.22 |
| ad | AD | 10.(100+X).20.88 |
| mqtt | MQTT | 10.(100+X).30.49 |
| opnsense | Firewall | 10.(100+X).40.1 |

Hostnames use `<hostname>.teamX.playtcdc.org`. Firewall work can affect many services and recovery paths; no automated firewall attack is supplied. Discord rulings supersede this worksheet when announced.

## Low-impact discovery examples

Run only during hands-on time, against one confirmed in-scope box, using an allowed origin. These commands are templates, not a target list or unattended job. Keep output on the permitted host; R23 excludes artifact export except screenshots/passwords.

```sh
# Replace HOST with ONE approved service hostname/IP; select its relevant port.
nmap -sT -sV --version-light -T2 --max-rate 10 --max-retries 1 -p 80 HOST
curl --connect-timeout 3 --max-time 5 -I http://HOST/
# Query only a known competition record, not zone transfer or arbitrary names:
dig @DNS_HOST KNOWN_RECORD A +time=2 +tries=1
```

Service detection sends protocol probes and is not perfectly passive. Stop on unexpected behavior or service degradation. No broad NSE/vulnerability/exploit script set is enabled here. A banner suggests what to investigate; it does not prove exploitability.

## Demonstration and undo

1. Reproduce a candidate issue on a disposable local service first. Identify exactly which file, setting, account, or service would change.
2. Prefer a non-mutating proof. If a reversible write demonstration is appropriate, use a uniquely named harmless canary in a noncritical, authorized location; verify it did not previously exist. Never overwrite an existing object merely to prove write access.
3. Record the original state locally and define the exact undo before the change. Preserve service data and all access paths. Do not rotate rival passwords, disable access, delete accounts, replace critical files, or weaken the protected monitoring/guest components.
4. Execute one bounded action, verify its effect, remove only your canary or restore only the state you changed, and verify recovery. Stop and notify Black Team if it behaves unexpectedly.
5. If reversibility, scope, or staff access is uncertain, obtain a Black Team ruling before acting (R17). Do not use the jumpbox for attack infrastructure (R16).

Publicly publish and submit any custom tool before use (R20), use free tiers only, and do not use AI during the event (R21). This preparation document does not grant permission beyond the official rules and staff directives.
