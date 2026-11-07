#!/usr/bin/env python3
"""TCDC Team 1 Watchtower - uptime monitor + dashboard + password vault.
Pure stdlib (no pip). Run on your laptop over the VPN:  python3 monitor.py
Open http://127.0.0.1:8787  . Polls every 15s with protocol checks so you
see a drop early. Discord alert on state change.

HONESTY NOTE: these checks verify reachability + protocol-level sanity, NOT the
official scorer's secret transactions. A GREEN here means "answered correctly at
the protocol layer"; it is NOT a guarantee the scorer's check passes. Checks that
can only confirm reachability (ssh banner, http with no expect) are tagged [reach].

Config: config.json (targets, team X, webhook). Secrets: vault.json (gitignored).
"""
import json, os, socket, struct, threading, time, traceback, ftplib, html
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
            {"name": "ns1-dns",       "host": "10.101.10.53",    "type": "dns",  "port": 53, "query": "aggiemuseum.local", "expect_answer": True},
            {"name": "ipcam-http",    "host": "10.150.0.%d" % X,  "type": "http", "port": 80, "path": "/", "expect": ""},
            {"name": "ftp-archive",   "host": "10.101.10.21",    "type": "ftp",  "port": 21, "cred": "ftp-archive"},
            {"name": "artifactorium", "host": "10.101.10.80",    "type": "http", "port": 80, "path": "/", "expect": ""},
            {"name": "ssh-wkstn",     "host": "10.101.10.22",    "type": "ssh",  "port": 22},
            {"name": "ad-dc",         "host": "10.101.20.88",    "type": "ldap", "port": 389},
            {"name": "mqtt",          "host": "10.101.30.49",    "type": "mqtt", "port": 1883},
            {"name": "opnsense-fw",   "host": "10.101.40.1",     "type": "tcp",  "port": 443, "scored": False},
        ],
    }

# ---- vault: reloaded live so rotations show up without a restart (review #5) ----
VP = os.path.join(HERE, "vault.json")
_VAULT = {"data": load_json("vault.json", {"services": {}, "passwords": []}), "mtime": 0.0}
try: _VAULT["mtime"] = os.path.getmtime(VP)
except OSError: pass

def reload_vault():
    """Re-read vault.json if it changed on disk. Called under LOCK."""
    try:
        m = os.path.getmtime(VP)
    except OSError:
        return
    if m == _VAULT["mtime"]:
        return
    try:
        with open(VP) as f: d = json.load(f)
        _VAULT["data"] = d; _VAULT["mtime"] = m
    except Exception:
        pass  # partial/invalid write in progress; keep last good copy

def vault():
    return _VAULT["data"]

# ---------- protocol checks ----------
# Each returns (ok: bool, detail: str, reach_only: bool)
def c_tcp(t):
    s = socket.create_connection((t["host"], t["port"]), timeout=4); s.close()
    return True, "tcp open", True

def c_http(t):
    url = "http://%s:%d%s" % (t["host"], t.get("port", 80), t.get("path", "/"))
    req = urllib.request.Request(url, headers={"User-Agent": "tcdc-watch"})
    with urllib.request.urlopen(req, timeout=5) as r:
        body = r.read(8192).decode("latin1", "replace"); code = r.getcode()
    exp = t.get("expect", "")
    if code >= 500: return False, "HTTP %d" % code, False
    if exp:
        if exp not in body: return False, "HTTP %d missing-expect" % code, False
        return True, "HTTP %d expect-ok" % code, False
    return True, "HTTP %d (no expect set)" % code, True  # reachability only

def c_ssh(t):
    s = socket.create_connection((t["host"], t["port"]), timeout=4)
    s.settimeout(4); banner = s.recv(64).decode("latin1", "replace"); s.close()
    return (banner.startswith("SSH-"), "banner=%r" % banner.strip()[:24], True)

def c_ftp(t):
    cred = vault().get("services", {}).get(t.get("cred", ""), {})
    user = cred.get("user", "anonymous"); pw = cred.get("pass", "anon@tcdc")
    f = ftplib.FTP(); f.connect(t["host"], t.get("port", 21), timeout=5)
    f.login(user, pw); f.nlst(); f.quit()
    return True, "login+list ok (%s)" % user, False

def _dns_skip_name(data, off):
    """Advance past a DNS name at off. Handles compression pointers. Raises on overrun."""
    seen = 0
    while True:
        if off >= len(data): raise ValueError("name overruns packet")
        l = data[off]
        if l == 0:
            return off + 1
        if (l & 0xC0) == 0xC0:          # compression pointer: 2 bytes, name ends here
            if off + 1 >= len(data): raise ValueError("name pointer overruns packet")
            return off + 2
        off += 1 + l                    # ordinary label
        seen += 1
        if seen > 128: raise ValueError("name too long")  # loop guard

def c_dns(t):
    q = t.get("query", "example.com")
    txid = 0x1234
    header = struct.pack(">H", txid) + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    qn = b"".join(struct.pack("B", len(p)) + p.encode() for p in q.split(".")) + b"\x00"
    pkt = header + qn + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
    s.sendto(pkt, (t["host"], t.get("port", 53)))
    data, src = s.recvfrom(2048); s.close()
    if len(data) < 12: return False, "dns short", False
    rtxid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x0F
    if rtxid != txid: return False, "dns txid-mismatch", False
    # response must come from the queried server. host may be an IP or a name - resolve so a
    # configured DNS hostname does not cause a false wrong-src (review #11).
    try: expected = {socket.gethostbyname(t["host"]), t["host"]}
    except Exception: expected = {t["host"]}
    if src[0] not in expected: return False, "dns wrong-src %s" % src[0], False
    if not (flags & 0x8000): return False, "dns not-a-response", False
    if rcode != 0: return False, "rcode=%d" % rcode, False
    # PARSE the question + answer sections. A 12-byte header claiming answers with no RR
    # bytes is malformed and must NOT pass as success (review #11).
    try:
        off = 12
        for _ in range(qd):
            off = _dns_skip_name(data, off) + 4      # qtype(2) + qclass(2)
            if off > len(data): raise ValueError("question section overruns")
        answers = []
        for _ in range(an):
            off = _dns_skip_name(data, off)
            if off + 10 > len(data): raise ValueError("answer header overruns")
            atype, aclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if off + rdlen > len(data): raise ValueError("rdata overruns")
            answers.append((atype, data[off:off + rdlen])); off += rdlen
    except (ValueError, struct.error) as ex:
        return False, "dns malformed (%s)" % ex, False
    if t.get("expect_answer", True) and an == 0:
        return False, "rcode=0 but 0 answers", False  # NXRECORD-ish; record gone
    want_ip = t.get("expect_ip")
    if want_ip:
        got = [".".join(str(b) for b in rd) for ty, rd in answers if ty == 1 and len(rd) == 4]
        if want_ip not in got:
            return False, "dns A %s != expect_ip %s" % (got, want_ip), False
    return True, "rcode=0 ancount=%d (parsed)" % an, False

def c_mqtt(t):
    cid = b"tcdcwatch"
    vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
    rem = vh + struct.pack(">H", len(cid)) + cid
    pkt = b"\x10" + struct.pack("B", len(rem)) + rem
    s = socket.create_connection((t["host"], t.get("port", 1883)), timeout=5)
    s.settimeout(4); s.sendall(pkt)
    resp = b""
    try:
        while len(resp) < 4:
            chunk = s.recv(4 - len(resp))
            if not chunk: break
            resp += chunk
    finally:
        s.close()
    if len(resp) < 4:
        return False, "connack short=%s" % resp.hex(), False
    # CONNACK: type 0x20, remaining-len 0x02, ack-flags, return-code 0x00 = accepted
    ok = resp[0] == 0x20 and resp[1] == 0x02 and resp[3] == 0x00
    return (ok, "connack=%s rc=%d" % (resp.hex(), resp[3]), False)

def c_ldap(t):
    s = socket.create_connection((t["host"], t.get("port", 389)), timeout=5); s.settimeout(4)
    # anonymous simple bind, msgid 1
    bind = bytes([0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00])
    s.sendall(bind)
    resp = b""
    try:
        while len(resp) < 14:
            chunk = s.recv(64)
            if not chunk: break
            resp += chunk
    finally:
        s.close()
    if len(resp) < 7 or resp[0] != 0x30:
        return False, "ldap not-a-message %s" % resp[:8].hex(), False
    # find BindResponse tag 0x61, then enumerated resultCode (tag 0x0a len 0x01 <code>)
    i = resp.find(b"\x61")
    if i == -1 or i + 2 >= len(resp):
        return False, "ldap no-bindresponse %s" % resp[:12].hex(), False
    j = resp.find(b"\x0a\x01", i)
    if j == -1 or j + 2 >= len(resp):
        return False, "ldap no-resultcode %s" % resp[:12].hex(), False
    code = resp[j + 2]
    # RFC 4511 resultCode semantics - distinguish success, auth-policy, and SERVICE ERROR:
    #   0  success            -> HEALTHY (up, full health)
    #   49 invalidCredentials -> anon bind refused by policy. Server answered LDAP correctly:
    #                            REACHABLE, but service health is UNKNOWN (reach-only up -> the
    #                            dashboard shows [reach] and check_one alerts on health loss).
    #   51 busy / 52 unavailable / 2 protocolError / anything else
    #                         -> SERVICE ERROR, counts as DOWN (review #2). These used to be
    #                            reported as healthy; a healthy->unavailable transition emitted
    #                            no DOWN alert. Now it does.
    if code == 0:
        return True, "ldap bind ok (rc=0)", False
    if code == 49:
        return True, "ldap rc=49 invalidCreds (anon refused; reachable, health unknown)", True
    names = {2: "protocolError", 51: "busy", 52: "unavailable", 53: "unwillingToPerform",
             80: "other", 1: "operationsError"}
    return False, "ldap rc=%d %s (service error - DOWN)" % (code, names.get(code, "resultCode")), False

CHECKS = {"tcp": c_tcp, "http": c_http, "ssh": c_ssh, "ftp": c_ftp,
          "dns": c_dns, "mqtt": c_mqtt, "ldap": c_ldap}

LOCK = threading.Lock()
STATE = {}
for t in CFG["targets"]:
    STATE[t["name"]] = {"up": None, "detail": "init", "ts": 0, "ok": 0, "total": 0,
                        "hist": [], "scored": t.get("scored", True), "host": t["host"],
                        "reach": False}

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
    reach = False
    try:
        res = fn(t)
        ok, detail = res[0], res[1]
        reach = res[2] if len(res) > 2 else False
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, str(e)[:50])
    with LOCK:
        st = STATE[t["name"]]; prev = st["up"]; prevreach = st.get("reach", False)
        st.update(up=ok, detail=detail, ts=time.time(), reach=reach)
        st["total"] += 1; st["ok"] += 1 if ok else 0
        st["hist"].append(1 if ok else 0); st["hist"] = st["hist"][-HIST:]
        scored = st["scored"]
    # review #13: alert on FIRST observed failure (None->False), not only transitions
    if scored and not ok and (prev is None or prev):
        notify(":red_circle: DOWN - %s (%s) - %s" % (t["name"], t["host"], detail))
    elif scored and ok and prev is False:
        notify(":green_circle: UP - %s (%s) - %s" % (t["name"], t["host"], detail))
    # review #2: health LOSS without full DOWN - a service that was fully healthy now only
    # answers at the reachability layer (e.g. LDAP rc=0 -> rc=49). Alert once on that edge.
    elif scored and ok and prev and reach and not prevreach:
        notify(":yellow_circle: DEGRADED - %s (%s) - %s" % (t["name"], t["host"], detail))

def poll_once():
    with LOCK: reload_vault()
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
.reach{background:#2a2410;border-radius:4px;padding:0 5px;color:#f9e2af;font-size:11px}
.warn{color:#fab387;font-size:12px}
</style></head><body>
<h1>TCDC Team %(x)d - Watchtower</h1>
<div class=sub>poll %(poll)ds &middot; %(ts)s &middot; Discord alerts %(hook)s &middot;
<span class=warn>GREEN = protocol-ok, NOT a scorer guarantee. [reach] = reachability only.</span></div>
<table><tr><th>service</th><th>host</th><th>state</th><th>uptime</th><th>last 40</th><th>detail</th></tr>
%(rows)s
</table>
<h1>Password Vault <span class=tag>local only - localhost bind</span></h1>
<div class=sub>single source of truth - change a pw? record via vault.py AND push to /team/passwords</div>
<table><tr><th>box</th><th>user</th><th>password</th><th>changed</th><th>dash-synced</th></tr>
%(vrows)s
</table>
</body></html>"""

def spark(hist):
    return "".join("#" if h else "." for h in hist[-40:]) or "."

def e(x):
    return html.escape(str(x), quote=True)

def render():
    with LOCK:
        reload_vault()
        snap = {k: dict(v) for k, v in STATE.items()}
        vdata = {"passwords": list(vault().get("passwords", []))}
    rows = []
    for t in CFG["targets"]:
        st = snap[t["name"]]
        if st["up"] is None: cls, lab = "na", "..."
        elif st["up"]: cls, lab = "up", "UP"
        else: cls, lab = "down", "DOWN"
        pct = (100.0 * st["ok"] / st["total"]) if st["total"] else 0.0
        tags = "" if st["scored"] else " <span class=na>(unscored)</span>"
        if st.get("reach") and st["up"]: tags += " <span class=reach>reach</span>"
        rows.append("<tr><td>%s%s</td><td class=na>%s</td><td class=%s>%s</td>"
                    "<td class=pct>%.1f%%</td><td class=spark>%s</td><td class=na>%s</td></tr>" % (
            e(t["name"]), tags, e(st["host"]), cls, lab, pct, spark(st["hist"]), e(st["detail"])))
    vrows = []
    for p in vdata["passwords"]:
        synced = "yes" if p.get("synced") else "<span class=down>NO</span>"
        vrows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class=na>%s</td><td>%s</td></tr>" % (
            e(p.get("box", "")), e(p.get("user", "")), e(p.get("pass", "")), e(p.get("changed", "")), synced))
    if not vrows: vrows = ["<tr><td colspan=5 class=na>empty - add entries via vault.py</td></tr>"]
    return PAGE % {"x": CFG["team_x"], "poll": POLL_SEC, "ts": time.strftime("%H:%M:%S"),
                   "hook": "on" if CFG.get("webhook") else "off",
                   "rows": "\n".join(rows), "vrows": "\n".join(vrows)}

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _sec(self):
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
    def do_GET(self):
        if self.path.startswith("/api/status"):
            with LOCK: body = json.dumps(STATE, default=str).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self._sec(); self.end_headers(); self.wfile.write(body); return
        body = render().encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self._sec(); self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    threading.Thread(target=poller, daemon=True).start()
    port = int(os.environ.get("TCDC_PORT", "8787"))
    print("Watchtower on http://127.0.0.1:%d  (team X=%d, %d targets)" % (
        port, CFG["team_x"], len(CFG["targets"])))
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
