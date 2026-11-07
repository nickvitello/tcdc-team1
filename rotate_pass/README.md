# Chronolock: deliberate Linux password rotation

Runs from a private operator workstation through a staff-approved access path. It never updates the scoring dashboard automatically. **Rotate one account on one box, verify access, update `/team/passwords`, then acknowledge before continuing.** Windows/AD rotation remains the interactive workflow in the root README.

## Preparation

1. Install `requirements.txt` in a virtual environment. Keep configuration, journal, state, and any cloud credentials private. Unix writes use 0600; Windows requires a private NTFS directory ACL.
2. Copy `config.example.json` to `config.json`; verify the team, exact own-box addresses, allowed users, and login account. Do not use staff accounts. The sample password is a placeholder.
3. Populate `ssh.known_hosts_file` with host keys **verified through an independent trusted channel**, such as the authorized console/staff. SSH refuses unknown or changed host keys. `ssh-keyscan` alone collects a key; it does not authenticate the host. Never delete a mismatch just to get past it.
4. Test on a disposable local Linux VM before the event. Direct laptop VPN access is conditional on staff routing/access rules; the packet requires the provided jumpbox access path. This tool does not create a tunnel for you.
5. Review [readiness.md](../readiness.md), confirm hands-on time, and have recovery access. Do not use AI during the competition.

```sh
python3 rotate.py rotate --dry-run                   # offline plan, no SSH or writes
python3 rotate.py check --boxes ns1                  # read-only SSH/sudo check; needs verified keys
python3 rotate.py rotate --boxes ns1 --users kennedy  # changes exactly this one account
# Verify the new credential works and update /team/passwords immediately.
python3 rotate.py ack --boxes ns1 --users kennedy     # explicit manual attestation
python3 rotate.py show                              # LOCAL secrets; do not screen-share casually
```

Bulk `admins`, `employees`, and `all` selections remain available for offline planning, but live rotation requires one box and one username. CLI usernames must belong to the configured allowlist. Shared passwords across boxes are refused. `--yes` bypasses only the pre-change prompt; it does not bypass the outstanding-change gate or the dashboard acknowledgment.

## Recovery and verification

Each candidate is flushed and fsynced to `passwords-log.jsonl` **before** the remote change. A process lock prevents simultaneous local operators, and administrator state uses atomic replacement. No software can guarantee recovery after disk loss: protect the private operator machine and an authorized password backup.

- `changed`: the remote password hash changed successfully. This is not proof that every service accepts the credential. Verify access and scoring, then `ack`.
- `pending` / `unknown` / legacy `FAILED`: the candidate **may already be active**. The tool never asserts that a failed verification means the old password still works. Use `show`, test the candidate through the authorized access path, or use independent recovery access to deliberately set that recorded candidate. Update `/team/passwords`, then `ack` only after it works.
- `synced`: the operator attested that the candidate works and the dashboard was updated. It is not an automated scoreboard check.

Do not delete an uncertain journal entry to unblock rotation. A corrupt journal is refused for recovery, not skipped. A failed administrator change can leave `state.json` stale; after you verify/apply the recorded candidate, `ack` updates the cached administrator credential. Keep an independent recovery session available, but do not assume an old session proves a new login will work.

Sudo authentication and command input use separate prompt/readiness stages, including NOPASSWD policy. Secrets travel on SSH stdin, not command arguments. Shadow hashes are compared on the target and are not returned to the laptop. The tool does not change sudo policy or enable SSH password authentication.

## Watchtower and optional Sheets

Chronolock's journal and Watchtower's vault are separate. After rotation, record the verified credential with `watchtower/vault.py set`, update any corresponding `vault.py svc` entry, and mark `vault.py sync` only after the dashboard update. Do not run the printed reset a second time unnecessarily. The root readiness guide lists this handoff.

Google Sheets logging is **off by default**. Passwords are an R23 export exception, but that does not authorize arbitrary host artifacts or personal account login on competition infrastructure. Use any private Sheet/service account only from your own authorized operator machine and restrict sharing. If enabled, install gspread, enable the Sheets/Drive APIs, share your private Sheet with the service-account identity, and configure its URL, worksheet, and private JSON key. The Sheet is a copy; a failed write must never cause another password reset. `python3 rotate.py resync` copies missing changed/acknowledged password entries; it does not perform a remote reset or update the scorer.

No live competition targets were used for preparation tests. CI uses mocks plus disposable loopback SSH/sudo accounts, covering passworded/NOPASSWD sudo, actual password changes, fresh logins, administrator rotation, and rejection of unknown host keys.
