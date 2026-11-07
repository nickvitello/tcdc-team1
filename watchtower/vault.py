#!/usr/bin/env python3
"""TCDC password vault CLI. ONE funnel for every password change so the
/team/passwords dashboard never drifts (drift = lost uptime: scored checks use these creds).

  python3 vault.py set <box> <user> <newpass> [--win] [--ad]   record + print SAFE box command
  python3 vault.py sync <box> <user>                           mark dashboard-synced (manual attestation)
  python3 vault.py svc <name> <user> <pass>                    store a SERVICE cred (monitor uses these)
  python3 vault.py list                                        show table

Prefer omitting <newpass>/<pass> to use a hidden prompt; positional secrets can enter
shell history. On Windows, store the checkout on a private user-profile directory
with an appropriate NTFS ACL (POSIX mode 0600 is not a Windows access control).

The printed reset commands PROMPT for the password on the box (interactive) - the
secret is never placed on a command line, so it can't land in shell history or be
mangled by shell metacharacters. You type the SAME value you recorded here.

Stored in vault.json (gitignored, mode 0600). Never commit it.
"""
import json, os, sys, time, tempfile, shlex, contextlib, getpass
if os.name == "nt":
    import msvcrt
else:
    import fcntl

HERE = os.path.dirname(os.path.abspath(__file__))
VP = os.path.join(HERE, "vault.json")
LOCKP = os.path.join(HERE, ".vault.lock")

@contextlib.contextmanager
def locked():
    """Advisory exclusive lock for the whole read-modify-write, so two concurrent
    vault.py invocations can't lose each other's updates (review #10)."""
    f = open(LOCKP, "a+b")
    acquired = False
    try:
        if os.name == "nt":
            if os.fstat(f.fileno()).st_size == 0:
                f.write(b"0"); f.flush()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(f, fcntl.LOCK_EX)
        acquired = True
        yield
    finally:
        try:
            if acquired:
                if os.name == "nt":
                    f.seek(0); msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(f, fcntl.LOCK_UN)
        finally: f.close()

def _abort(msg):
    print("ABORT: %s" % msg); sys.exit(3)

def load():
    # review #10: ONLY an absent file means "new vault". A corrupt/unreadable vault must
    # NOT be silently replaced with an empty one - that destroys recoverable credentials.
    try:
        with open(VP) as f:
            raw = f.read()
    except FileNotFoundError:
        return {"services": {}, "passwords": []}
    except OSError as ex:
        _abort("cannot read %s (%s). Refusing to proceed so creds aren't lost." % (VP, ex))
    try: os.chmod(VP, 0o600)   # enforce private perms on existing file (review #12)
    except OSError: pass
    try:
        data = json.loads(raw)
    except ValueError as ex:
        _abort("%s is corrupt/unparseable (%s). NOT overwriting. Back it up and fix by hand." % (VP, ex))
    if not isinstance(data, dict):
        _abort("%s is not a JSON object. NOT overwriting." % VP)
    data.setdefault("services", {}); data.setdefault("passwords", [])
    if not isinstance(data["passwords"], list) or not isinstance(data["services"], dict):
        _abort("invalid vault schema; NOT overwriting")
    for entry in data["passwords"]:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) for k in ("box", "user", "pass", "changed")) or not isinstance(entry.get("synced"), bool):
            _abort("invalid password entry; NOT overwriting")
    for entry in data["services"].values():
        if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) for k in ("user", "pass")):
            _abort("invalid service credential; NOT overwriting")
    return data

def save(v):
    # atomic write with 0600 so readers never see a partial file and other local
    # users can't read creds (review #5 atomicity + #12 perms)
    fd, tmp = tempfile.mkstemp(dir=HERE, prefix=".vault.", suffix=".tmp")
    try:
        if os.name != "nt": os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(v, f, indent=2)
        os.replace(tmp, VP)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def now(): return time.strftime("%Y-%m-%d %H:%M")

def _reject_bad(pw):
    if "\n" in pw or "\r" in pw or "\x00" in pw:
        print("REFUSED: password contains newline/NUL - not a valid credential."); sys.exit(2)

def cmd_set(box, user, pw, win, ad):
    _reject_bad(pw)
    if user.casefold().split("\\")[-1].split("@")[0] in ("blackteam", "whiteteam"):
        _abort("protected staff account; password changes prohibited by R8")
    if not user or user.startswith(("-", "/")) or any(ord(c) < 32 for c in user + box):
        _abort("invalid account/box name")
    if win and ad: _abort("choose --win or --ad")
    with locked():
        v = load()
        v["passwords"] = [p for p in v["passwords"] if not (p["box"] == box and p["user"] == user)]
        v["passwords"].append({"box": box, "user": user, "pass": pw, "changed": now(), "synced": False})
        save(v)
    qu = shlex.quote(user)
    psuser = "\'" + user.replace("\'", "\'\'") + "\'"
    print("recorded %s/%s (synced=False)" % (box, user))
    print("\nRUN THIS ON THE BOX - it PROMPTS for the new password (type the value above):")
    if ad:
        print('  $p = Read-Host -AsSecureString "New password"')
        print('  Set-ADAccountPassword -Identity %s -Reset -NewPassword $p' % psuser)
        print('  Set-ADUser -Identity %s -ChangePasswordAtLogon $false' % psuser)
    elif win:
        print("  $u = %s; & net.exe user $u '*'" % psuser)
    else:
        print("  sudo passwd -- %s" % qu)

    print("\nTHEN: update /team/passwords, then run vault.py sync with the same quoted box/user arguments.")

def cmd_sync(box, user):
    with locked():
        v = load(); hit = False
        for p in v["passwords"]:
            if p["box"] == box and p["user"] == user: p["synced"] = True; hit = True
        # review #10: don't rewrite the file for a no-op (absent entry) - nothing to persist
        if hit: save(v)
    print(("synced %s/%s (manual attestation - does NOT verify scorer)" % (box, user)) if hit else "no such entry")

def cmd_svc(name, user, pw):
    _reject_bad(pw)
    with locked():
        v = load(); v.setdefault("services", {})[name] = {"user": user, "pass": pw}
        save(v)
    print("service cred stored: %s (%s)" % (name, user))

def cmd_list():
    v = load()
    print("== passwords ==")
    for p in v["passwords"]:
        print("  %-14s %-12s %-20s %s  %s" % (p["box"], p["user"], p["pass"], p["changed"],
                                              "SYNCED" if p.get("synced") else "*** NOT SYNCED ***"))
    unsynced = [p for p in v["passwords"] if not p.get("synced")]
    if unsynced: print("\n!! %d entries NOT synced to /team/passwords" % len(unsynced))
    print("== service creds (for monitor) ==")
    for k, c in v.get("services", {}).items(): print("  %-14s %s" % (k, c.get("user")))

def main(a):
    if not a: print(__doc__); return
    c = a[0]
    if c == "set" and len(a) >= 3:
        args = [x for x in a[3:] if x not in ("--win", "--ad")]
        pw = args[0] if args else getpass.getpass("New password (hidden): ")
        cmd_set(a[1], a[2], pw, "--win" in a, "--ad" in a)
    elif c == "sync" and len(a) >= 3: cmd_sync(a[1], a[2])
    elif c == "svc" and len(a) >= 3: cmd_svc(a[1], a[2], a[3] if len(a) >= 4 else getpass.getpass("Service password (hidden): "))
    elif c == "list": cmd_list()
    else: print(__doc__)

if __name__ == "__main__": main(sys.argv[1:])
