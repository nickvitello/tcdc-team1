#!/usr/bin/env python3
"""TCDC Team 1 Watchtower - uptime monitor + dashboard + password vault.
Pure stdlib (no pip). Run on your laptop over the VPN:  python3 monitor.py
Open http://127.0.0.1:8787  . Polls every 15s with REAL protocol checks so you
see a drop before the official 30s tick. Discord alert on state change.

Config: config.json (targets, team X, webhook). Secrets: vault.json (gitignored).
"""
import json, os, socket, struct, threading, time, traceback, ftplib
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
POLL_SEC = 15
HIST = 120

def load_json(name, default):
    p = os.path.join(HERE, name)
    try:
        with open(p) as f: return json.load(f)
    except Exception:
        return default

CFG = load_json("config.json", None)
if CFG is None:
    X = int(os.environ.get("TCDC_X", "1"))
    CFG = {
        "team_x": X, "webhook": os.environ.get("TCDC_WEBHOOK", ""),
        "targets": [
            {"name": "ns1-dns",       "host": "10.101.10.53",    "type": "dns",  "port": 53, "query": "aggiemuseum.local"},
            {"name": "ipcam-http",    "host": "10.150.0.%d" % X,  "type": "http", "port": 80, "path": "/", "expect": ""},
            {"name": "ftp-archive",   "host": "10.101.10.21",    "type": "ftp",  "port": 21, "cred": "ftp-archive"},
            {"name": "artifactorium", "host": "10.101.10.80",    "type": "http", "port": 80, "path": "/", "expect": ""},
            {"name": "ssh-wkstn",     "host": "10.101.10.22",    "type": "ssh",  "port": 22},
            {"name": "ad-dc",         "host": "10.101.20.88",    "type": "ldap", "port": 389},
            {"name": "mqtt",          "host": "10.101.30.49",    "type": "mqtt", "port": 1883},
            {"name": "opnsense-fw",   "host": "10.101.40.1",     "type": "tcp",  "port": 443, "scored": False},
        ],
    }
VAULT = load_json("vault.json", {"services": {}, "passwords": []})

def c_tcp(t):
    s = socket.create_connection((t["host"], t["port"]), timeout=4); s.close()
    return True, "tcp open"

def c_http(t):
    url = "http://%s:%d%s" % (t["host"], t.get("port", 80), t.get("path", "/"))
    req = urllib.request.Request(url, headers={"User-Agent": "tcdc-watch"})
    with urllib.request.urlopen(req, timeout=5) as r:
        body = r.read(4096).decode("latin1", "replace"); code = r.getcode()
    exp = t.get("expect", "")
    if code >= 500: return False, "HTTP %d" % code
    if exp and exp not in body: return False, "HTTP %d missing-expect" % code
    return True, "HTTP %d" % code

def c_ssh(t):
    s = socket.create_connection((t["host"], t["port"]), timeout=4)
    s.settimeout(4); banner = s.recv(64).decode("latin1", "replace"); s.close()
    return (banner.startswith("SSH-"), "banner=%r" % banner.strip()[:24])

def c_ftp(t):
    cred = VAULT.get("services", {}).get(t.get("cred", ""), {})
    user = cred.get("user", "anonymous"); pw = cred.get("pass", "anon@tcdc")
    f = ftplib.FTP(); f.connect(t["host"], t.get("port", 21), timeout=5)
    f.login(user, pw); f.nlst(); f.quit()
    return True, "login+list ok (%s)" % user

def c_dns(t):
    q = t.get("query", "example.com")
    header = struct.pack(">H", 0x1234) + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    qn = b"".join(struct.pack("B", len(p)) + p.encode() for p in q.split(".")) + b"\x00"
    pkt = header + qn + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
    s.sendto(pkt, (t["host"], t.get("port", 53)))
    data, _ = s.recvfrom(512); s.close()
    rcode = data[3] & 0x0F
    return (rcode == 0, "rcode=%d ancount=%d" % (rcode, struct.unpack(">H", data[6:8])[0]))

def c_mqtt(t):
    cid = b"tcdcwatch"
    vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
    rem = vh + struct.pack(">H", len(cid)) + cid
    pkt = b"\x10" + struct.pack("B", len(rem)) + rem
    s = socket.create_connection((t["host"], t.get("port", 1883)), timeout=5)
    s.settimeout(4); s.sendall(pkt); resp = s.recv(4); s.close()
    if len(resp) >= 4:
        ok = resp[0] == 0x20 and resp[3] == 0x00
    else:
        ok = len(resp) >= 1 and resp[0] == 0x20
    return (ok, "connack=%s" % resp.hex())

def c_ldap(t):
    s = socket.create_connection((t["host"], t.get("port", 389)), timeout=5); s.settimeout(4)
    bind = bytes([0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00])
    s.sendall(bind); resp = s.recv(32); s.close()
    return (len(resp) >= 2 and resp[0] == 0x30, "ldap %s" % resp[:8].hex())

CHECKS = {"tcp": c_tcp, "http": c_http, "ssh": c_ssh, "ftp": c_ftp,
          "dns": c_dns, "mqtt": c_mqtt, "ldap": c_ldap}

LOCK = threading.Lock()
STATE = {}
for t in CFG["targets"]:
    STATE[t["name"]] = {"up": None, "detail": "init", "ts": 0, "ok": 0, "total": 0,
                        "hist": [], "scored": t.get("scored", True), "host": t["host"]}

def notify(msg):
    hook = CFG.get("webhook", "")
    if not hook: return
    try:
        data = json.dumps({"content": msg}).encode()
        urllib.request.urlopen(urllib.request.Request(hook, data=data,
            headers={"Content-Type": "application/json"}), timeout=5)
    except Exception: pass

def check_one(t):
    fn = CHECKS.get(t["type"], c_tcp)
    try:
        ok, detail = fn(t)
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, str(e)[:40])
    with LOCK:
        st = STATE[t["name"]]; prev = st["up"]
        st.update(up=ok, detail=detail, ts=time.time())
        st["total"] += 1; st["ok"] += 1 if ok else 0
        st["hist"].append(1 if ok else 0); st["hist"] = st["hist"][-HIST:]
    if prev is not None and prev != ok and STATE[t["name"]]["scored"]:
        notify("%s %s is now %s - %s" % (
            "DOWN" if not ok else "UP", t["name"], "DOWN" if not ok else "UP", detail))

def poll_once():
    # poll all targets concurrently so one dead host can't stall the cycle
    threads = [threading.Thread(target=check_one, args=(t,), daemon=True) for t in CFG["targets"]]
    for th in threads: th.start()
    for th in threads: th.join(timeout=8)

def poller():
    while True:
        try: poll_once()
        except Exception: traceback.print_exc()
        time.sleep(POLL_SEC)

PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>TCDC Team %(x)d Watchtower</title><meta http-equiv=refresh content=5>
<style>
body{background:#0b0e14;color:#cdd6f4;font:14px ui-monospace,Menlo,monospace;margin:0;padding:18px}
h1{font-size:18px;margin:0 0 4px}.sub{color:#6c7086;margin-bottom:14px}
table{border-collapse:collapse;width:100%%;margin-bottom:26px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1e2230}
th{color:#89b4fa;font-weight:600}
.up{color:#a6e3a1;font-weight:700}.down{color:#f38ba8;font-weight:700}.na{color:#6c7086}
.spark{letter-spacing:-1px}.pct{color:#f9e2af}
.tag{background:#1e2230;border-radius:4px;padding:1px 6px;color:#89dceb;font-size:12px}
</style></head><body>
<h1>TCDC Team %(x)d - Watchtower</h1>
<div class=sub>poll %(poll)ds &middot; %(ts)s &middot; Discord alerts %(hook)s</div>
<table><tr><th>service</th><th>host</th><th>state</th><th>uptime</th><th>last 30m</th><th>detail</th></tr>
%(rows)s
</table>
<h1>Password Vault <span class=tag>local only</span></h1>
<div class=sub>single source of truth - change a pw? record here AND push to /team/passwords</div>
<table><tr><th>box</th><th>user</th><th>password</th><th>changed</th><th>dash-synced</th></tr>
%(vrows)s
</table>
</body></html>"""

def spark(hist):
    return "".join("#" if h else "." for h in hist[-40:]) or "."

def render():
    rows = []
    for t in CFG["targets"]:
        st = STATE[t["name"]]
        if st["up"] is None: cls, lab = "na", "..."
        elif st["up"]: cls, lab = "up", "UP"
        else: cls, lab = "down", "DOWN"
        pct = (100.0 * st["ok"] / st["total"]) if st["total"] else 0.0
        scored = "" if st["scored"] else " <span class=na>(unscored)</span>"
        rows.append("<tr><td>%s%s</td><td class=na>%s</td><td class=%s>%s</td>"
                    "<td class=pct>%.1f%%</td><td class=spark>%s</td><td class=na>%s</td></tr>" % (
            t["name"], scored, st["host"], cls, lab, pct, spark(st["hist"]), st["detail"]))
    vrows = []
    for p in VAULT.get("passwords", []):
        synced = "yes" if p.get("synced") else "NO"
        vrows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class=na>%s</td><td>%s</td></tr>" % (
            p.get("box", ""), p.get("user", ""), p.get("pass", ""), p.get("changed", ""), synced))
    if not vrows: vrows = ["<tr><td colspan=5 class=na>empty - add entries to vault.json</td></tr>"]
    return PAGE % {"x": CFG["team_x"], "poll": POLL_SEC, "ts": time.strftime("%H:%M:%S"),
                   "hook": "on" if CFG.get("webhook") else "off",
                   "rows": "\n".join(rows), "vrows": "\n".join(vrows)}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/api/status"):
            with LOCK: body = json.dumps(STATE, default=str).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(body); return
        body = render().encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    threading.Thread(target=poller, daemon=True).start()
    port = int(os.environ.get("TCDC_PORT", "8787"))
    print("Watchtower on http://127.0.0.1:%d  (team X=%d, %d targets)" % (
        port, CFG["team_x"], len(CFG["targets"])))
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
