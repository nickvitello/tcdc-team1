#!/usr/bin/env python3
"""TCDC password vault CLI. ONE funnel for every password change so the
/team/passwords dashboard never drifts (drift = lost uptime: scored checks use these creds).

  python3 vault.py set <box> <user> <newpass> [--win] [--ad]   record + print box command
  python3 vault.py sync <box> <user>                           mark dashboard-synced after you update it
  python3 vault.py svc <name> <user> <pass>                    store a SERVICE cred (monitor uses these)
  python3 vault.py list                                        show table

Stored in vault.json (gitignored). Never commit it.
"""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
VP = os.path.join(HERE, "vault.json")

def load():
    try: return json.load(open(VP))
    except Exception: return {"services": {}, "passwords": []}
def save(v): json.dump(v, open(VP, "w"), indent=2)
def now(): return time.strftime("%Y-%m-%d %H:%M")

def cmd_set(box, user, pw, win, ad):
    v = load()
    v["passwords"] = [p for p in v["passwords"] if not (p["box"] == box and p["user"] == user)]
    v["passwords"].append({"box": box, "user": user, "pass": pw, "changed": now(), "synced": False})
    save(v)
    print("recorded %s/%s (synced=False)" % (box, user))
    print("\nRUN THIS ON THE BOX:")
    if ad:
        print('  Set-ADAccountPassword -Identity %s -Reset -NewPassword (ConvertTo-SecureString "%s" -AsPlainText -Force)' % (user, pw))
    elif win:
        print('  net user %s "%s"' % (user, pw))
    else:
        print("  echo '%s:%s' | sudo chpasswd" % (user, pw))
    print("\nTHEN: update /team/passwords on the dashboard, then: python3 vault.py sync %s %s" % (box, user))

def cmd_sync(box, user):
    v = load(); hit = False
    for p in v["passwords"]:
        if p["box"] == box and p["user"] == user: p["synced"] = True; hit = True
    save(v); print("synced %s/%s" % (box, user) if hit else "no such entry")

def cmd_svc(name, user, pw):
    v = load(); v.setdefault("services", {})[name] = {"user": user, "pass": pw}
    save(v); print("service cred stored: %s (%s)" % (name, user))

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
    if c == "set" and len(a) >= 4: cmd_set(a[1], a[2], a[3], "--win" in a, "--ad" in a)
    elif c == "sync" and len(a) >= 3: cmd_sync(a[1], a[2])
    elif c == "svc" and len(a) >= 4: cmd_svc(a[1], a[2], a[3])
    elif c == "list": cmd_list()
    else: print(__doc__)

if __name__ == "__main__": main(sys.argv[1:])
