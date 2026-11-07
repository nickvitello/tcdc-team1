# Chronolock

Rotates OS passwords on the team's Linux boxes over SSH and logs each new
password to a Google Sheet the team shares. Runs on a laptop connected to the
competition VPN. Nothing is installed on the boxes.

**It does not update the scoring dashboard.** Every password it prints must
still be entered at https://dash.playtcdc.org/team/passwords, or the uptime
checks that use that account will fail.

## Setup (do this tonight)

1. Install the libraries:
   ```
   pip install -r requirements.txt
   ```
2. Create the Google credentials:
   1. In the Google Cloud console, create a project, then enable the
      **Google Sheets API** and the **Google Drive API** for it.
   2. Under IAM & Admin > Service Accounts, create a service account, then
      add a JSON key under its Keys tab.
   3. Save the key next to `rotate.py` as `service-account.json`.
3. Create a Google Sheet and share it with the service account's email
   (`...@...iam.gserviceaccount.com`) as **Editor**. Share it with your
   teammates, and with **nobody else**: it will hold every password.
4. Copy `config.example.json` to `config.json` and fill in:
   - `team`: your team number
   - `ssh.admin_password`: the default password from Discord
   - `sheet.url`: your Sheet's URL
5. Test it against a local Ubuntu VM before the event (rule R24).

`config.json`, `service-account.json`, `state.json` and `passwords-log.jsonl`
are gitignored. Never commit them. The tool itself must go in the team's
public repo and be submitted through the Tool Links form (rule R20).

## Competition day

```
python3 rotate.py check                      # SSH + sudo works on every box?
python3 rotate.py rotate --users admins      # admins first
#   -> enter the printed passwords at /team/passwords
python3 rotate.py rotate --users employees   # then everyone else
#   -> enter those too
python3 rotate.py show                       # current password for every box/user
```

Useful options:

| option | what it does |
|--------|--------------|
| `--boxes ns1,ipcam` | limit to some boxes |
| `--users kennedy,streep` | limit to specific users |
| `--dry-run` | show what would change, change nothing |
| `--same-across-boxes` | one password per user on every box: fewer dashboard entries, but one leak opens every box |
| `--yes` | skip the confirmation prompt |

If the Sheet was unreachable during a run, the passwords are still in the local
log. Run `python3 rotate.py resync` once it is back.

## How it stays safe

- **blackteam and whiteteam are never touched (R8),** even if they are listed in the config.
- **Each new password is saved to `passwords-log.jsonl` before it is applied,**
  so a crash or a dropped connection can never lose one. `show` marks an
  unconfirmed change as PENDING, so you know to test that account.
- **Each change is verified:** the user's `/etc/shadow` hash is compared before
  and after, inside the same `sudo` call as the change.
- **The admin account the tool logs in with is rotated last on each box.** Its
  new password is saved to `state.json`, which the next run uses to log in.
- Passwords are 16 letters and digits, always with an upper case letter, a
  lower case letter and a digit. They avoid characters that break shells or
  checkers, and the look-alikes l, I, O and 0.

## Limits

- Linux boxes only. Windows and AD accounts are not covered.
- OS accounts only. App and service passwords (a web app's admin or database
  login) are not covered.
- If someone changes a password by hand, the tool doesn't know about it. If
  that was the admin it logs in with, edit `state.json`.
