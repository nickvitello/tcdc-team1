# Snapshot / diff / rollback runbook (Linux boxes)

Two files, both in `linux/`:

- `timecapsule.sh` runs on a box. It snapshots state, diffs two snapshots, and
  restores files from a snapshot.
- `fleet.sh` runs on the **jumpbox**. It streams `timecapsule.sh` (or any command)
  to every Linux box over SSH. Nothing is installed or scheduled on the boxes.

Run `fleet.sh` from the jumpbox, never a personal laptop. `diff` and `pull` bring
box data back, and R23 forbids taking that off competition infrastructure.

## Setup (once, on the jumpbox)

```
mkdir -p ~/tc && cd ~/tc      # put fleet.sh and timecapsule.sh here
chmod +x fleet.sh
sudo apt install -y sshpass   # optional: without it you type the password once per box
export TEAM=<your team number>
```

Windows line endings in the copied files are fine: `fleet.sh` strips them before
sending.

**Passwords.** `fleet.sh` logs in as `washington` with one password for all boxes.
When PasswordRotate (`rotate_pass/`) rotates `washington`, keep it the same on every box:

```
python3 rotate.py rotate --users washington --same-across-boxes
```

Then rotate the others without touching washington again:
`--users kennedy,teddy,lincoln,ross`, then `--users employees` (not `admins` or `all`).

To skip the prompt each run, set
`export FLEET_PASS='<washington password>'`.

## Competition day

| when | command | why |
|---|---|---|
| 08:00, before touching anything | `./fleet.sh snap start` then `./fleet.sh pull` | records what you were given, including anything pre-planted. **Read it.** |
| right after hardening | `./fleet.sh snap hardened` then `./fleet.sh pull` | your known-good state |
| every 30-60 min | `./fleet.sh diff hardened now` | what changed since you hardened |
| after each check | `./fleet.sh pull` | copies survive if red team wipes `/root` |

`diff ... now` also saves the current state as a snapshot named `auto`, so you
keep a history.

Limit any command to some boxes with `BOXES=ns1,ipcam ./fleet.sh ...`.

## When something breaks or a diff shows a change

1. **Look:** `BOXES=artifactorium ./fleet.sh diff hardened now`
2. **Roll back** only the paths involved:
   ```
   ./fleet.sh restore artifactorium hardened /var/www/html
   ./fleet.sh restore ns1 hardened /etc/bind
   ```
   It saves the current version first and prints the command to undo the restore.
3. **Delete by hand** the files it lists as not in the snapshot. A restore puts
   files back, but never deletes, so a dropped webshell stays until you remove it.
4. **Syntax-check and reload** the service, e.g.
   `./fleet.sh run "apachectl configtest && systemctl reload apache2"`
5. **Watch one scoreboard tick.**

Restorable paths: `/etc`, `/var/www`, `/srv`, `/var/lib/bind`, `/var/cache/bind`,
`/var/ftp`, `/root/.ssh`.

Accounts are changed with commands, not files. If a diff shows a new UID 0 user, a
new sudoer or a new SSH key, fix it with `userdel`, `visudo` or by editing
`authorized_keys`, then confirm with another diff.

## Rollback options, in the order to try them

| # | tool | restores | survives an attacker who… |
|---|---|---|---|
| 1 | `./fleet.sh restore <box> <label> <path>` | files under `/etc`, `/var/www`, `/srv`, the BIND dirs, `/var/ftp`, `/root/.ssh`, from the box's own snapshot | edits files |
| 2 | `./fleet.sh restore-copy <box> <label> <path>` | the same paths, from the copy **pulled to the jumpbox** | also deletes or edits `/root/timecapsule` on the box (run `./fleet.sh pull` after every snapshot) |
| 3 | `./fleet.sh etckeeper restore <box> <label> <path>` | anything under `/etc`, from `/etc/.git`; a completely separate implementation | breaks or fools timecapsule itself |
| 4 | `apt install --reinstall <package>` (via `./fleet.sh run`) | replaced binaries and library files that `debsums -c` or AIDE flag | replaces system binaries |
| 5 | the `.bak` copy you made before each change (playbook ground rules) | that one file | — |
| 6 | store snapshot revert (playbook section 7) | the whole VM, at a currency cost | anything, including a kernel rootkit; undoes **every** change since the snapshot, passwords included |

What none of them do:
- **They never restore accounts.** `/etc/passwd`, `shadow`, `group` and `gshadow`
  are refused on purpose, because restoring them would revert blackteam/whiteteam
  (R8) and every password you've rotated. Fix accounts with `userdel`, `usermod`
  and `gpasswd -d`, and passwords from the master list.
- **They never restore organizer tooling** (`/etc/audit`, `/etc/cloud`), per R7.
- **They never delete files added after the snapshot,** such as a webshell. They
  list them; delete those by hand.

Every restore saves the current version first and prints how to undo it.

## Premade tools through the same runner

```
./fleet.sh aide install; ./fleet.sh aide init   # AIDE baseline after hardening (TCDC-safe config in aide.sh)
./fleet.sh aide check                            # what changed since; 'aide accept' after reviewing your own changes
./fleet.sh run "debsums -c"                      # files that don't match their package (replaced binaries)
./fleet.sh run "lynis audit system --quick"      # needs lynis installed
./fleet.sh etckeeper install                     # git history of /etc (needs apt); no scheduled jobs
./fleet.sh etckeeper commit hardened             # label the current /etc
./fleet.sh etckeeper diff hardened               # an independent second view of /etc changes
./fleet.sh etckeeper restore <box> hardened /etc/ssh/sshd_config   # independent second restore path
./fleet.sh run "find /var/www -name '*.php' -newer /etc/hostname"
```

## Known limits

- A snapshot is a point in time: anything added and removed between two
  snapshots is never seen.
- Root on a box can tamper with that box's copies. Compare against the pulled
  copies in `capsules/` if a diff looks suspiciously clean.
- `/home` (apart from SSH keys) and most of `/usr/lib` are not hashed. The PAM
  module directory is.
- The processes section is noisy, so treat it as a hint.
