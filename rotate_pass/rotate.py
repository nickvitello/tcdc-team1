#!/usr/bin/env python3
"""Chronolock: one-account Linux rotation through verified SSH host keys.

Use --dry-run for offline planning. Apply one account, verify access and update
/team/passwords, then ack before continuing. Pending/unknown candidates remain
in a durable local journal for manual recovery. Optional Sheets logging is a
password copy, never the source of truth or dashboard integration. See README.
"""
import argparse, datetime, json, os, re, secrets, string, sys, time
import contextlib, shlex, tempfile, uuid

try:
    import paramiko
except ImportError:
    paramiko = None  # Offline planning/show must not require SSH libraries.

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

@contextlib.contextmanager
def operation_lock():
    """One local operator process at a time, including durable state + remote operation."""
    with open(os.path.join(HERE, ".rotation.lock"), "a+b") as stream:
        if os.name == "nt":
            import msvcrt
            if os.fstat(stream.fileno()).st_size == 0: stream.write(b"0"); stream.flush()
            stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try: yield
        finally:
            if os.name == "nt": stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else: fcntl.flock(stream, fcntl.LOCK_UN)


def private_write(path, text, mode="w"):
    if os.path.islink(path): raise ValueError("refusing symlink secret file")
    if mode == "a":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "a") as stream:
            if os.name != "nt": os.fchmod(stream.fileno(), 0o600)
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
    else:
        fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".rotation-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(text); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    if os.name != "nt":
        directory = os.open(os.path.dirname(path), os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def gen_password(length):
    """Letters + digits only: no quotes, $, \\, : or spaces that could break chpasswd,
    a shell, or a scoring checker. Always has upper, lower and digit (meets AD rules too)."""
    if not isinstance(length, int) or not 16 <= length <= 128:
        raise ValueError("password_length must be 16..128")
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
                    except ValueError as ex:
                        raise ValueError("corrupt password journal; preserve and recover it before continuing") from ex
    return out


# ---------------------------------------------------------------- config
def validate_user(user):
    if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", user):
        raise ValueError("invalid username")
    if user in NEVER_TOUCH: raise ValueError("protected staff account")
    return user


def load_config():
    cfg = load_json(CONFIG, None)
    if cfg is None: die("copy config.example.json to config.json and configure verified host keys")
    team = int(cfg["team"])
    if not 1 <= team <= 154: die("invalid team number")
    names=set()
    for box in cfg["boxes"]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", box["name"]) or box["name"] in names:
            die("invalid/duplicate box name")
        names.add(box["name"])
        box["host"] = box["host"].format(team=team, net=100 + team)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", box["host"]): die("invalid host")
        validate_user(box.get("admin_user", cfg["ssh"]["admin_user"]))
        if not 1 <= int(box.get("port", cfg["ssh"].get("port", 22))) <= 65535: die("invalid port")
    for user in cfg["users"] + cfg.get("admins", []): validate_user(user)
    if len(set(cfg["users"])) != len(cfg["users"]): die("duplicate users")
    length=cfg.get("password_length",16)
    if not isinstance(length,int) or not 16 <= length <= 128: die("password_length must be 16..128")
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
        validate_user(self.admin)
        if not isinstance(self.pw,str) or any(c in self.pw for c in "\r\n\0"): raise ValueError("invalid admin password")
        if paramiko is None: die("paramiko missing: pip install -r requirements.txt")
        self.c = paramiko.SSHClient()
        known = os.path.expanduser(cfg["ssh"].get("known_hosts_file", "~/.ssh/known_hosts"))
        if not os.path.isabs(known): known = os.path.join(HERE, known)
        self.c.load_host_keys(known)
        self.c.set_missing_host_key_policy(paramiko.RejectPolicy())

    def connect(self):
        self.c.connect(self.host, port=self.port, username=self.admin, password=self.pw,
                       timeout=8, banner_timeout=8, auth_timeout=8,
                       look_for_keys=False, allow_agent=False)

    def sudo(self, cmd, stdin_text=""):
        """Separate sudo authentication from command input, including NOPASSWD/cached sudo.

        Passwords are sent only on the unique stderr prompt. Command input is sent
        only after the privileged wrapper announces readiness. Nothing secret goes
        in the SSH command line or remote process arguments.
        """
        token = secrets.token_hex(16)
        prompt, ready = "TCDC_AUTH_" + token, "TCDC_READY_" + token
        wrapper = "printf '%s\\n' " + shlex.quote(ready) + " >&2; exec " + cmd
        full = "sudo -k -S -p " + shlex.quote(prompt) + " -- sh -c " + shlex.quote(wrapper)
        channel = self.c.get_transport().open_session(timeout=10)
        channel.settimeout(20)
        output, errors = b"", b""
        sent_auth = sent_input = False
        deadline = time.monotonic() + 20
        try:
            channel.exec_command(full)
            while True:
                if channel.recv_ready(): output += channel.recv(65536)
                if channel.recv_stderr_ready(): errors += channel.recv_stderr(65536)
                if prompt.encode() in errors:
                    if sent_auth: raise RuntimeError("sudo authentication rejected")
                    channel.sendall((self.pw + "\n").encode())
                    sent_auth = True; errors = errors.replace(prompt.encode(), b"", 1)
                if ready.encode() in errors and not sent_input:
                    channel.sendall(stdin_text.encode())
                    channel.shutdown_write(); sent_input = True
                    errors = errors.replace(ready.encode(), b"", 1)
                if len(output) + len(errors) > 1048576: raise RuntimeError("excess remote output")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    return channel.recv_exit_status(), output.decode(errors="replace"), errors.decode(errors="replace")
                if time.monotonic() > deadline: raise TimeoutError("sudo/command timed out; result unknown")
                time.sleep(0.01)
        finally:
            channel.close()

    def check_sudo(self):
        code, out, err = self.sudo("id -u")
        return code == 0 and out.strip() == "0", (err or out).strip()

    def user_exists(self, user):
        validate_user(user)
        code, out, _ = self.sudo("getent passwd " + shlex.quote(user) + " >/dev/null")
        return code == 0

    def change_and_verify(self, user, pw):
        """Read the shadow hash, run chpasswd, read it again - all inside ONE sudo call.
        (Separate sudo calls break when the user is the admin we log in with: after
        chpasswd, sudo would demand the NEW password and the check would wrongly fail.)
        Returns (changed: bool, detail: str)."""
        validate_user(user)
        if not re.fullmatch(r"[A-Za-z0-9]{16,128}", pw): raise ValueError("invalid generated password")
        # Hashes stay on the target. Only a result marker comes back to the operator.
        script = ("before=$(getent shadow {u} | cut -d: -f2); "
                  "[ -n \"$before\" ] || exit 2; "
                  "chpasswd || exit 3; "
                  "after=$(getent shadow {u} | cut -d: -f2); "
                  "[ -n \"$after\" ] && [ \"$before\" != \"$after\" ] || exit 4; "
                  "printf 'TCDC_CHANGED\\n'").format(u=shlex.quote(user))
        code, out, err = self.sudo("sh -c " + shlex.quote(script), stdin_text="%s:%s\n" % (user, pw))
        if code == 0 and out.strip() == "TCDC_CHANGED": return True, ""
        return False, "remote verification incomplete (rc=%d); new password may already be active" % code

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
    for user in users:
        validate_user(user)
        if user not in cfg["users"]: die("user is not in configured allowlist")
    if not boxes or not users: die("empty selection")
    if len(set(users)) != len(users): die("duplicate selected user")
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
                  ("OK  ssh+sudo as %s" % bx.admin) if ok
                  else "FAIL sudo: " + detail))
            bad += 0 if ok else 1
        except Exception as ex:
            print("%-16s %-16s FAIL ssh: %s" % (b["name"], b["host"], ex))
            bad += 1
        finally:
            bx.close()
    sys.exit(1 if bad else 0)

def latest_entries():
    latest={}
    for entry in read_log():
        if not isinstance(entry,dict) or any(not isinstance(entry.get(k),str) for k in ("box","user","password","status","time")):
            die("invalid journal schema; preserve and recover it")
        latest[(entry["box"],entry["user"])]=entry
    return latest


def rotate_box(cfg, args, b, users, sheet, same_pw):
    bx=Box(cfg,b)
    try:
        bx.connect()
        ok,detail=bx.check_sudo()
        if not ok: die("sudo check failed; no rotation attempted")
        user=users[0]
        if not bx.user_exists(user): die("selected user does not exist; no rotation attempted")
        pw=gen_password(cfg.get("password_length",16))
        base={"operation":uuid.uuid4().hex,"time":now(),"box":b["name"],"host":b["host"],"user":user,"password":pw}
        log_event(dict(base,status="pending"))  # Durable journal before any change.
        try:
            ok,detail=bx.change_and_verify(user,pw)
        except Exception:
            log_event(dict(base,status="unknown"))
            die("connection/verification failed; result UNKNOWN. Use show; verify or manually apply the recorded candidate, then update dashboard and ack")
        if not ok:
            log_event(dict(base,status="unknown"))
            die(detail + "; use show and recover before another rotation")
        event=dict(base,time=now(),status="changed")
        log_event(event)
        if user == bx.admin: save_admin_password(b["name"],pw)
        print("CHANGED %s/%s: %s" % (b["name"],user,pw))
        print("Verify access, update /team/passwords, then run ack for this exact box/user before another rotation.")
        sheet.append_many([event])
        return [event]
    finally:
        bx.close()


def cmd_rotate(cfg, args):
    boxes,users=select(cfg,args)
    if args.dry_run:
        for box in boxes:
            for user in users: print("PLAN %s (%s) / %s" % (box["name"],box["host"],user))
        print("Offline plan only: no SSH, sudo, password generation, Sheet access, or writes.")
        return
    if len(boxes) != 1 or len(users) != 1: die("select exactly one --boxes NAME and one --users USER; sync the dashboard after each")
    if args.same_across_boxes: die("shared passwords disabled; use a unique password per box/account")
    if any(e["status"] != "synced" for e in latest_entries().values()):
        die("prior rotation is unsynced or uncertain; recover and ack it before continuing")
    if not args.yes and input("Rotate this one account now? type yes: ").strip() != "yes": die("aborted")
    rotate_box(cfg,args,boxes[0],users,Sheet(cfg),{})


def cmd_ack(cfg,args):
    boxes,users=select(cfg,args)
    if len(boxes)!=1 or len(users)!=1: die("ack requires exactly one box and user")
    box,user=boxes[0],users[0]
    entry=latest_entries().get((box["name"],user))
    if entry is None: die("no recorded candidate")
    if entry["status"] == "synced": print("already acknowledged"); return
    if input("Confirm recorded candidate works AND /team/passwords is updated; type verified: ").strip() != "verified": die("not acknowledged")
    # Recovery of a lost response is manual: only acknowledge after testing or
    # applying the journaled candidate. Never discard that candidate as 'failed'.
    if user == box.get("admin_user",cfg["ssh"]["admin_user"]): save_admin_password(box["name"],entry["password"])
    log_event(dict(entry,time=now(),status="synced"))
    print("Manual dashboard/access attestation recorded; not an automated scorer verification.")

def cmd_show(cfg,args):
    latest=latest_entries()
    if not latest: print("log empty")
    for (box,user),entry in sorted(latest.items()):
        print("%s %s %s [%s]" % (box,user,entry["password"],entry["status"]))
    print("pending/unknown/FAILED means the candidate MAY be active; verify or manually apply it before ack.")

def cmd_resync(cfg, args):
    sheet = Sheet(cfg)
    if not sheet.enabled:
        die("Sheet not available")
    have = set()
    for row in sheet.ws.get_all_values()[1:]:
        if len(row) >= 5:
            have.add((row[1], row[3], row[4]))
    candidates = {(e["box"], e["user"], e["password"]): e for e in read_log() if e["status"] in ("changed", "synced")}
    missing = [e for key,e in candidates.items() if key not in have]
    if sheet.append_many(missing):
        print("pushed %d missing row(s)" % len(missing))

def main():
    p = argparse.ArgumentParser(description="Rotate OS passwords on team Linux boxes")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("check", "rotate", "show", "resync", "ack"):
        s = sub.add_parser(name)
        s.add_argument("--boxes", help="comma list of box names (default: all)")
        s.add_argument("--users", default="all",
                       help="all | admins | employees | comma list of usernames")
        if name == "rotate":
            s.add_argument("--dry-run", action="store_true")
            s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
            s.add_argument("--same-across-boxes", action="store_true",
                           help="legacy option; live shared-password rotation is refused")
    args = p.parse_args()
    try:
        cfg = load_config()
        if args.cmd == "rotate" and args.dry_run:
            cmd_rotate(cfg,args); return
        with operation_lock():
            {"check":cmd_check,"rotate":cmd_rotate,"show":cmd_show,"resync":cmd_resync,"ack":cmd_ack}[args.cmd](cfg,args)
    except (OSError,ValueError) as ex:
        die(str(ex))

if __name__ == "__main__":
    main()
