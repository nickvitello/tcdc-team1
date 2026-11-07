#!/usr/bin/env python3
"""Chronolock - rotate OS passwords on the team's Linux boxes and log them to a Google Sheet.

Runs on YOUR laptop over the VPN. Nothing is installed on the boxes.

  python3 rotate.py check                          test SSH + sudo on every box
  python3 rotate.py rotate --dry-run               show what would change, change nothing
  python3 rotate.py rotate                         rotate every listed user on every box
  python3 rotate.py rotate --boxes ns1 --users admins
  python3 rotate.py show                           print the latest password per box/user
  python3 rotate.py resync                         push any log entries the Sheet missed

Safety rules built in:
  * blackteam / whiteteam are never touched (R8), whatever the config says.
  * Every new password is written to the LOCAL log BEFORE it is applied, so a crash
    or dropped connection can never lose a password. The Sheet is a copy, not the source.
  * Each change is verified by comparing the user's /etc/shadow hash before and after.
  * The admin account the tool logs in with is rotated LAST on each box, and the
    tool remembers its new password for the next run.
  * It does NOT update the scoring dashboard. Every row it prints must still be
    entered at /team/passwords by hand.
"""
import argparse, datetime, json, os, re, secrets, string, sys, time

try:
    import paramiko
except ImportError:
    sys.exit("paramiko missing:  pip install -r requirements.txt")

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "config.json")
LOG = os.path.join(HERE, "passwords-log.jsonl")      # source of truth, never delete during the event
STATE = os.path.join(HERE, "state.json")            # current admin login password per box
NEVER_TOUCH = {"blackteam", "whiteteam"}
SHEET_HEADER = ["time", "box", "host", "user", "password", "status", "dashboard updated?"]


# ---------------------------------------------------------------- helpers
def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def private_write(path, text, mode="w"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC), 0o600)
    with os.fdopen(fd, mode) as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def gen_password(length):
    """Letters + digits only: no quotes, $, \\, : or spaces that could break chpasswd,
    a shell, or a scoring checker. Always has upper, lower and digit (meets AD rules too)."""
    alphabet = string.ascii_letters + string.digits
    alphabet = "".join(c for c in alphabet if c not in "lIO0")   # avoid misreads when typing
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw

def log_event(entry):
    private_write(LOG, json.dumps(entry) + "\n", mode="a")

def read_log():
    out = []
    if os.path.exists(LOG):
        with open(LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    return out


# ---------------------------------------------------------------- config
def load_config():
    cfg = load_json(CONFIG, None)
    if cfg is None:
        die("no config.json - copy config.example.json to config.json and fill it in")
    team = int(cfg["team"])
    net = 100 + team
    for b in cfg["boxes"]:
        b["host"] = b["host"].format(team=team, net=net)
    for u in cfg["users"] + cfg.get("admins", []):
        if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", u):
            die("bad username in config: %r" % u)
    users = [u for u in cfg["users"] if u not in NEVER_TOUCH]
    admins = [u for u in cfg.get("admins", []) if u not in NEVER_TOUCH]
    cfg["users"], cfg["admins"] = users, admins
    return cfg

def admin_password(cfg, box):
    state = load_json(STATE, {})
    return state.get(box["name"], box.get("admin_password") or cfg["ssh"]["admin_password"])

def save_admin_password(box_name, pw):
    state = load_json(STATE, {})
    state[box_name] = pw
    private_write(STATE, json.dumps(state, indent=2))


# ---------------------------------------------------------------- SSH box session
class Box:
    def __init__(self, cfg, box):
        self.name, self.host = box["name"], box["host"]
        self.port = int(box.get("port", cfg["ssh"].get("port", 22)))
        self.admin = box.get("admin_user", cfg["ssh"]["admin_user"])
        self.pw = admin_password(cfg, box)
        self.nopasswd = False
        self.c = paramiko.SSHClient()
        self.c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        self.c.connect(self.host, port=self.port, username=self.admin, password=self.pw,
                       timeout=8, banner_timeout=8, auth_timeout=8,
                       look_for_keys=False, allow_agent=False)
        # Detect passwordless sudo: if we fed a password to `sudo -S` there, it would be
        # read by the command itself (e.g. chpasswd would treat it as a bad line).
        _, out, _ = self.c.exec_command("sudo -n true 2>/dev/null && echo NOPASSWD", timeout=10)
        self.nopasswd = "NOPASSWD" in out.read().decode()

    def sudo(self, cmd, stdin_text=""):
        """Run cmd as root. Returns (exit_code, stdout, stderr)."""
        full = "sudo -S -p '' " + cmd
        i, o, e = self.c.exec_command(full, timeout=20)
        payload = ("" if self.nopasswd else self.pw + "\n") + stdin_text
        if payload:
            i.write(payload)
        i.channel.shutdown_write()
        out, err = o.read().decode(), e.read().decode()
        return o.channel.recv_exit_status(), out, err

    def check_sudo(self):
        code, out, err = self.sudo("id -u")
        return code == 0 and out.strip() == "0", (err or out).strip()

    def user_exists(self, user):
        code, out, _ = self.sudo("getent passwd " + user)
        return code == 0 and out.strip() != ""

    def change_and_verify(self, user, pw):
        """Read the shadow hash, run chpasswd, read it again - all inside ONE sudo call.
        (Separate sudo calls break when the user is the admin we log in with: after
        chpasswd, sudo would demand the NEW password and the check would wrongly fail.)
        Returns (changed: bool, detail: str)."""
        script = ("getent shadow %s | cut -d: -f2; chpasswd; rc=$?; "
                  "getent shadow %s | cut -d: -f2; exit $rc") % (user, user)
        code, out, err = self.sudo("sh -c '%s'" % script, stdin_text="%s:%s\n" % (user, pw))
        lines = out.strip().splitlines()
        if len(lines) < 2:
            return False, (err or "no output").strip()
        before, after = lines[0].strip(), lines[-1].strip()
        if code == 0 and after and after != before:
            return True, ""
        return False, (err.strip() or "hash unchanged (rc=%d)" % code)

    def close(self):
        try:
            self.c.close()
        except Exception:
            pass


# ---------------------------------------------------------------- Google Sheet
class Sheet:
    def __init__(self, cfg):
        s = cfg.get("sheet", {})
        self.ws = None
        self.enabled = bool(s.get("enabled"))
        if not self.enabled:
            return
        try:
            import gspread
        except ImportError:
            print("!! gspread missing - Sheet logging OFF (local log still works)")
            self.enabled = False
            return
        try:
            key = os.path.join(HERE, s["service_account_file"])
            gc = gspread.service_account(filename=key)
            sh = gc.open_by_url(s["url"])
            name = s.get("worksheet", "Passwords")
            try:
                self.ws = sh.worksheet(name)
            except gspread.WorksheetNotFound:
                self.ws = sh.add_worksheet(title=name, rows=500, cols=len(SHEET_HEADER))
            if self.ws.row_values(1) != SHEET_HEADER:
                self.ws.insert_row(SHEET_HEADER, 1)
        except Exception as ex:
            print("!! cannot open Google Sheet (%s) - Sheet logging OFF, local log still works" % ex)
            self.enabled = False

    @staticmethod
    def _row(e):
        return [e["time"], e["box"], e["host"], e["user"], e["password"], e["status"], ""]

    def append_many(self, entries):
        """One API call for a whole box (Sheets allows ~60 writes/min)."""
        if not self.enabled or not entries:
            return True
        try:
            self.ws.append_rows([self._row(e) for e in entries], value_input_option="RAW")
            return True
        except Exception as ex:
            print("   !! Sheet write failed (%s) - passwords are safe in the local log; "
                  "run `rotate.py resync` later" % ex)
            return False


# ---------------------------------------------------------------- commands
def select(cfg, args):
    boxes = cfg["boxes"]
    if args.boxes:
        want = set(args.boxes.split(","))
        boxes = [b for b in boxes if b["name"] in want]
        missing = want - {b["name"] for b in boxes}
        if missing:
            die("unknown box(es): " + ", ".join(sorted(missing)))
    if args.users == "all":
        users = cfg["users"]
    elif args.users == "admins":
        users = [u for u in cfg["users"] if u in cfg["admins"]]
    elif args.users == "employees":
        users = [u for u in cfg["users"] if u not in cfg["admins"]]
    else:
        users = [u for u in args.users.split(",") if u not in NEVER_TOUCH]
    return boxes, users

def cmd_check(cfg, args):
    boxes, _ = select(cfg, args)
    bad = 0
    for b in boxes:
        bx = Box(cfg, b)
        try:
            bx.connect()
            ok, detail = bx.check_sudo()
            print("%-16s %-16s %s" % (b["name"], b["host"],
                  ("OK  ssh+sudo as %s%s" % (bx.admin, " (NOPASSWD)" if bx.nopasswd else "")) if ok
                  else "FAIL sudo: " + detail))
            bad += 0 if ok else 1
        except Exception as ex:
            print("%-16s %-16s FAIL ssh: %s" % (b["name"], b["host"], ex))
            bad += 1
        finally:
            bx.close()
    sys.exit(1 if bad else 0)

def rotate_box(cfg, args, b, users, sheet, same_pw):
    bx = Box(cfg, b)
    print("\n== %s (%s) as %s" % (b["name"], b["host"], bx.admin))
    try:
        bx.connect()
    except Exception as ex:
        print("   FAIL ssh: %s  -- box skipped, nothing changed" % ex)
        return []
    ok, detail = bx.check_sudo()
    if not ok:
        print("   FAIL sudo: %s  -- box skipped, nothing changed" % detail)
        bx.close()
        return []

    # admin we log in with goes LAST so a mid-run failure never locks the tool out
    order = [u for u in users if u != bx.admin] + ([bx.admin] if bx.admin in users else [])
    done = []
    for user in order:
        if not bx.user_exists(user):
            print("   %-12s not on this box, skipped" % user)
            continue
        pw = same_pw.get(user) or gen_password(cfg.get("password_length", 16))
        if args.dry_run:
            print("   %-12s would rotate" % user)
            continue
        base = {"time": now(), "box": b["name"], "host": b["host"], "user": user, "password": pw}
        log_event(dict(base, status="pending"))       # recorded BEFORE it is applied
        try:
            ok, err = bx.change_and_verify(user, pw)
        except Exception as ex:
            # connection dropped mid-change: we genuinely don't know. Leave it 'pending'.
            print("   %-12s UNKNOWN  connection lost (%s) - password may be %s, test it" % (user, ex, pw))
            break
        if ok:
            e = dict(base, time=now(), status="changed")
            log_event(e)
            if user == bx.admin:
                save_admin_password(b["name"], pw)
                bx.pw = pw
            print("   %-12s CHANGED  %s" % (user, pw))
            done.append(e)
        else:
            e = dict(base, time=now(), status="FAILED")
            log_event(e)
            print("   %-12s FAILED   old password still active (%s)" % (user, err[:80]))
            done.append(e)
    bx.close()
    if sheet.enabled and sheet.append_many([e for e in done if e["status"] == "changed"]):
        print("   logged to Google Sheet")
    return done

def cmd_rotate(cfg, args):
    boxes, users = select(cfg, args)
    if not users:
        die("no users selected")
    print("boxes: %s" % ", ".join(b["name"] for b in boxes))
    print("users: %s" % ", ".join(users))
    print("never touched: %s" % ", ".join(sorted(NEVER_TOUCH)))
    if args.dry_run:
        print("DRY RUN - nothing will change")
    elif not args.yes:
        if input("\nRotate these now? type yes: ").strip().lower() != "yes":
            die("aborted")
    sheet = Sheet(cfg) if not args.dry_run else Sheet({})
    same_pw = {}
    if args.same_across_boxes:
        same_pw = {u: gen_password(cfg.get("password_length", 16)) for u in users}
    results = []
    for b in boxes:
        results += rotate_box(cfg, args, b, users, sheet, same_pw)
    if args.dry_run:
        return
    changed = [e for e in results if e["status"] == "changed"]
    fails = [e for e in results if e["status"] == "FAILED"]
    print("\n%d password(s) changed. NOW enter each one at /team/passwords:" % len(changed))
    for e in changed:
        print("   %-16s %-12s %s" % (e["box"], e["user"], e["password"]))
    if fails:
        print("\n%d failure(s) this run - these users keep their OLD password:" % len(fails))
        for e in fails:
            print("   %-16s %s" % (e["box"], e["user"]))

def cmd_show(cfg, args):
    latest, confirmed = {}, {}
    for e in read_log():
        k = (e["box"], e["user"])
        if e["status"] == "changed":
            latest[k] = confirmed[k] = e
        elif e["status"] == "pending":
            latest[k] = e
        elif e["status"] == "FAILED" and k in latest and latest[k]["password"] == e["password"]:
            # verified NOT applied: fall back to the last confirmed password (or none = default)
            if k in confirmed:
                latest[k] = confirmed[k]
            else:
                del latest[k]
    if not latest:
        print("log empty")
        return
    for (box, user), e in sorted(latest.items()):
        flag = "" if e["status"] == "changed" else "  <-- PENDING: may or may not have applied, test it"
        print("%-16s %-12s %-20s %s%s" % (box, user, e["password"], e["time"], flag))

def cmd_resync(cfg, args):
    sheet = Sheet(cfg)
    if not sheet.enabled:
        die("Sheet not available")
    have = set()
    for row in sheet.ws.get_all_values()[1:]:
        if len(row) >= 5:
            have.add((row[1], row[3], row[4]))
    missing = [e for e in read_log()
               if e["status"] == "changed" and (e["box"], e["user"], e["password"]) not in have]
    if sheet.append_many(missing):
        print("pushed %d missing row(s)" % len(missing))

def main():
    p = argparse.ArgumentParser(description="Rotate OS passwords on team Linux boxes")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("check", "rotate", "show", "resync"):
        s = sub.add_parser(name)
        s.add_argument("--boxes", help="comma list of box names (default: all)")
        s.add_argument("--users", default="all",
                       help="all | admins | employees | comma list of usernames")
        if name == "rotate":
            s.add_argument("--dry-run", action="store_true")
            s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
            s.add_argument("--same-across-boxes", action="store_true",
                           help="give each user ONE password on every box (fewer dashboard entries)")
    args = p.parse_args()
    cfg = load_config()
    {"check": cmd_check, "rotate": cmd_rotate, "show": cmd_show, "resync": cmd_resync}[args.cmd](cfg, args)

if __name__ == "__main__":
    main()
