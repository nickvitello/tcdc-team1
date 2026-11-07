# Preparation and first-contact procedure

Assume opponents can read every line of this public repository. Script names and baseline paths are not secrets. A process with root/SYSTEM authority can disable or falsify local monitoring; a second local health check reduces operational blind spots but does not defeat a compromised operating system.

## Before the event

- Choose a reviewed full commit SHA with passing checks. Save a clean checkout on the operator laptop and stage that same revision on each authorized box. Download helpers reject branch names and require a 40-character SHA; fetch the helper itself at that same SHA.
- Confirm staff scope, access path, hands-on windows, and protected accounts/components. Do not harden the jumpbox, Wazuh/auditd, or guest tools based on this repository.
- Assign an uptime operator and an inject owner. Keep a local change log: box, actor, planned change, undo, service test, scorer result. Do not put secrets in public issues, commits, screenshots shared outside the allowed process, or chat.
- Prepare independent recovery access and any permitted snapshots/backups. A local accepted baseline is evidence, not a clean image or a backup.

## Review before accepting the first baseline

Use the approved console/SSH/RDP path, during hands-on time. Inspect state before running an installer with `--accept-initial-state` / `-AcceptInitialState`.

**Linux:** inspect login identities and UID0 entries (`getent passwd`), sudo/wheel groups, explicit sudoers rules, SSH authorized keys and configuration, cron directories, enabled units/timers, service configuration and listening sockets. Check file owners/modes and unexpected symlinks. Use targeted reads, not blanket deletion. Account membership is not the only route to elevated privileges. Keep packet users and never alter staff accounts.

**Windows:** inspect local Administrators membership, local/domain identities, service image paths/accounts, scheduled-task definitions, loaded-user and relevant unloaded-user autoruns, listeners, and applicable policy. On the DC, inspect privileged-group membership and service/SPN accounts before capturing AD group baselines. Keep existing protected monitoring intact. Unexpected or unresolvable identities require review, not automatic removal.

Initial capture accepts what exists. If the review finds suspicious state, retain local evidence, identify its owner/dependencies, and follow staff incident guidance. Do not call the current state clean merely because the baseline command succeeds.

```sh
sudo bash linux/harden.sh BOX --accept-initial-state
sudo python3 linux/health.py
```
```powershell
& .\windows\harden.ps1 -Box BOX -AcceptInitialState
& .\windows\health.ps1
# DC group review/capture is separate:
& C:\tcdc-baseline\ad-harden.ps1 -AcceptInitialState
```

The first health check may report no completed run yet; wait for the scheduled run and check again. Do not suppress a persistent failure. Existing accepted baselines require explicit reviewed `--rebaseline` / `-Rebaseline`; old evidence is archived.

## Credential rotation: one change, then verify

1. Confirm the intended account is not staff, identify services that depend on it, and establish recovery access. Do not reset krbtgt or service identities as a generic cleanup step.
2. Use the vault's hidden prompt and printed interactive command, or Chronolock for a single configured Linux account with verified SSH host keys. Avoid passwords in process arguments/history and avoid sharing one password across boxes.
3. Check a NEW authentication attempt. Update `/team/passwords` immediately and observe the official scoring ticks. If verification is uncertain, preserve both the candidate and evidence; do not assume the old password remains active.
4. Synchronize the private operator records. Chronolock uses its own journal and `ack`; Watchtower uses `vault.py set`, separate `svc` entries, and `sync`. Neither updates the dashboard for you. Copy the verified value to the relevant records without unnecessarily resetting the box again.
5. Continue to the next account only after access and dashboard status are confirmed. Do not rotate a whole fleet and defer dashboard updates until the end.

## Service patching: inspect versions, then one component

Patching needs the actual installed package/application versions and scorer dependencies. This repository cannot infer those from a banner. Do not run a blanket upgrade or reboot across the team.

- On Ubuntu, inspect the running service and package version (`systemctl status SERVICE`, `dpkg-query -W PACKAGE`), refresh approved repository metadata if allowed, inspect available updates, and simulate the exact package operation with `apt-get -s install --only-upgrade PACKAGE`. Review changed dependencies and restart requirements before applying that exact reviewed update.
- For Windows/AD, inspect OS build, installed updates, and the application vendor's security guidance. Separate application fixes from OS updates/reboots. Schedule and test any restart with recovery access and scoring observation.
- For OPNsense and application-managed services, use the corresponding supported update mechanism only after confirming configuration backup/recovery and dependencies. Do not modify protected guest/monitoring components.
- Test changes on disposable preparation images when possible. In competition, take permitted local recovery measures, change one component, verify its actual transaction and fresh management access, observe the scorer, and roll back on failure. Record expected file drift; accept only the reviewed differences through the explicit baseline process.

## Ongoing independent checks

Run `linux/health.py` or `windows/health.ps1` from the trusted checkout via a separate operator session. These commands do not import or execute the installed watcher. They check scheduler availability, recent execution, and installed module hashes against that checkout. Linux uses completed monotonic execution timestamps; Windows uses task state, last run time and result. Also read the local drift log and inspect protected monitoring through staff-approved interfaces.

Check after deployment, after each change/reboot, and regularly during hands-on time. Keep service checks and the official scorer visible from the approved access path. A stopped watcher may produce no new drift log: silence is not evidence of health. If the host OS itself is compromised, independently established service behavior, staff monitoring, and trusted recovery are necessary; local hash comparisons cannot prove the host trustworthy.
