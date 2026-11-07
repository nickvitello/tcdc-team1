#!/usr/bin/env python3
"""Behavior regression tests for hostile-review round 2 (issue #1).

Each previously-OPEN finding is encoded here as the FIXED expectation, so a regression
re-opens the test. Offline only: sockets mocked, Linux watcher paths redirected into temp
dirs, external commands stubbed. Never contacts competition systems.

Usage: python3 tests/regression_round2.py [/path/to/repo-root]   (default: parent of tests/)
"""
import contextlib, hashlib, importlib.util, io, json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path
from unittest.mock import patch

REPO = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent).resolve()
PASS = []
def ok(msg): PASS.append(msg); print("PASS:", msg)

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

class Socket:
    def __init__(self, chunks, source=('127.0.0.1', 53)):
        self.chunks = list(chunks); self.source = source
    def settimeout(self, n): pass
    def sendall(self, b): pass
    def sendto(self, b, target): pass
    def recv(self, n): return self.chunks.pop(0) if self.chunks else b''
    def recvfrom(self, n): return self.recv(n), self.source
    def close(self): pass

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

with tempfile.TemporaryDirectory(prefix='regr2-') as tmp:
    root = Path(tmp)
    for f in ('monitor.py', 'vault.py'):
        shutil.copy(REPO/'watchtower'/f, root/f)
    v = module('v', root/'vault.py')
    v.save({'services': {}, 'passwords': [{'box':'fixture','user':'fixture','pass':'OLD','synced':True}]})
    m = module('m', root/'monitor.py')

    # --- preserved fixes (must stay green) -----------------------------------------
    with patch.object(m.socket, 'create_connection', return_value=Socket([b'SSH-<svg/onload=alert()>'])):
        res = m.c_ssh({'host':'127.0.0.1','port':22})
    m.STATE['ssh-wkstn'].update(up=res[0], detail=res[1], reach=res[2])
    page = m.render()
    assert '<svg/onload=alert()>' not in page and '&lt;svg/onload=alert()&gt;' in page
    ok("dashboard HTML-escapes hostile markup")

    for chunks, exp in [([b'\x20', b'\x02\x00\x05'], False), ([b'\x20', b'\x02\x00\x00'], True), ([b'\x20'], False)]:
        with patch.object(m.socket, 'create_connection', return_value=Socket(chunks)):
            assert m.c_mqtt({'host':'127.0.0.1'})[0] is exp
    ok("MQTT fragmented success/refusal/short handled")

    # #2 LDAP: success=healthy, 49=reachable-degraded, 51/52/2=DOWN
    expect = {0:(True,False), 49:(True,True), 51:(False,None), 52:(False,None), 2:(False,None)}
    for code,(up,reach) in expect.items():
        resp = bytes.fromhex('300c02010161070a01') + bytes([code]) + bytes.fromhex('04000400')
        with patch.object(m.socket, 'create_connection', return_value=Socket([resp])):
            r = m.c_ldap({'host':'127.0.0.1'})
        assert r[0] is up, "rc=%d expected up=%s got %s" % (code, up, r)
        if reach is not None: assert r[2] is reach, "rc=%d reach %s" % (code, r)
    ok("#2 LDAP busy/unavailable/protocolError now count as DOWN; 49 degraded; 0 healthy")

    t = {'name':'ad-dc','host':'127.0.0.1','type':'test'}
    m.STATE['ad-dc'].update(up=True, reach=False)
    m.CHECKS['test'] = lambda x: (False, 'ldap rc=52 unavailable (service error - DOWN)', False)
    a = []
    with patch.object(m, 'notify', side_effect=a.append): m.check_one(t)
    assert len(a) == 1 and 'DOWN' in a[0], a
    ok("#2 healthy -> LDAP unavailable fires one DOWN alert")

    m.STATE['ad-dc'].update(up=True, reach=False)
    m.CHECKS['test'] = lambda x: (True, 'ldap rc=49 invalidCreds', True)
    a = []
    with patch.object(m, 'notify', side_effect=a.append): m.check_one(t)
    assert len(a) == 1 and 'DEGRADED' in a[0], a
    ok("#2 healthy -> degraded (reach-only) fires one DEGRADED alert")

    # #11 DNS: header-only packet (claims answers, no RR bytes) must be DOWN
    for data in (bytes.fromhex('123481800001000000000000'), bytes.fromhex('123481800001000100000000')):
        with patch.object(m.socket, 'socket', return_value=Socket([data])):
            assert m.c_dns({'host':'127.0.0.1'})[0] is False
    ok("#11 DNS header-only responses (0 and 1 claimed answers) both rejected")

    # #10 vault: corrupt file must NOT be silently overwritten with an empty vault
    corrupt = '{"passwords": [{"pass": "RECOVERABLE"}],'
    (root/'vault.json').write_text(corrupt)
    try:
        with contextlib.redirect_stdout(io.StringIO()): v.cmd_sync('absent', 'absent')
        raise AssertionError("expected abort on corrupt vault")
    except SystemExit as ex:
        assert ex.code == 3
    assert (root/'vault.json').read_text() == corrupt
    ok("#10 corrupt vault aborts instead of overwriting; file preserved")
    # and 0600 perms + interactive reset still hold on a valid vault
    v.save({'services': {}, 'passwords': []})
    out = io.StringIO()
    with contextlib.redirect_stdout(out): v.cmd_set('fixture', 'fixture', "NEW_'_$X", False, False)
    assert stat.S_IMODE((root/'vault.json').stat().st_mode) == 0o600
    assert 'sudo passwd fixture' in out.getvalue() and "NEW_'_$X" not in out.getvalue()
    ok("#12/#6 vault 0600 + interactive reset (no secret on cmdline) preserved")

    # ---- Linux watcher fixture -----------------------------------------------------
    bk = root/'baseline'; bk.mkdir()
    etc = root/'etc'; cron = etc/'cron.d'
    for d in ('sudoers.d','cron.d','cron.hourly','cron.daily','cron.weekly','cron.monthly','systemd/system'):
        (etc/d).mkdir(parents=True, exist_ok=True)
    spool = root/'spool'; spool.mkdir()
    passwd = etc/'passwd'; passwd.write_text('root:x:0:0:root:/root:/bin/bash\n')
    (bk/'baseline.sha256').write_text(f'{digest(passwd)}  {passwd}\n')
    (bk/'inventory.base').write_text('')      # present-but-empty = valid fresh baseline
    (bk/'enabled-services.txt').write_text('')
    bin_dir = root/'bin'; bin_dir.mkdir()
    for name in ('systemctl','getent','ss'):
        p = bin_dir/name; p.write_text('#!/bin/sh\nexit 0\n'); p.chmod(0o700)
    agent = root/'watch-agent.sh'
    agent.write_text((REPO/'linux/watch-agent.sh').read_text()
                     .replace('/root/tcdc-baseline', str(bk))
                     .replace('/etc/', str(etc)+'/')
                     .replace('/var/spool/cron', str(spool)))
    env = dict(os.environ, PATH=str(bin_dir)+':'+os.environ['PATH'], TCDC_WEBHOOK='')
    def run_agent():
        (bk/'drift.log').write_text('')
        subprocess.run(['bash', str(agent), 'fixture'], env=env, check=True)
        return (bk/'drift.log').read_text()

    n = cron/'ordinary-fixture'; n.write_text('# x\n')
    assert 'NEW persistence file:' in run_agent(); n.unlink()
    ok("#5 present-but-empty inventory still detects an ordinary new cron file")

    h = cron/'tcdc-watch-helper'; h.write_text('# x\n')
    assert 'NEW persistence file:' in run_agent(); h.unlink()
    ok("#4 attacker file named tcdc-watch-helper is no longer whitelisted")

    tgt = root/'harmless-target'; tgt.write_text('# x\n')
    (cron/'linked-fixture').symlink_to(tgt)
    assert 'NEW persistence symlink:' in run_agent(); (cron/'linked-fixture').unlink()
    ok("#12 a new cron symlink is detected (find -type l)")

    (bk/'inventory.base').unlink()            # old-format baseline: inventory ABSENT
    assert 'NO inventory.base' in run_agent()
    ok("#5 old-format baseline (no inventory) now alerts loudly instead of silent no-op")

    # #9 SSH re-bless only when sshd_config was clean vs baseline before our edit
    sshd = etc/'ssh/sshd_config'; sshd.parent.mkdir()
    sshd.write_text('PermitRootLogin prohibit-password\nAuthorizedKeysFile .ssh/authorized_keys\n')
    original = digest(sshd)
    (bk/'baseline.sha256').write_text(f'{digest(passwd)}  {passwd}\n{original}  {sshd}\n')
    # someone changed an UNRELATED setting after baseline (pre-existing drift)
    sshd.write_text('PermitRootLogin prohibit-password\nAuthorizedKeysFile /tmp/evil-keys\n')
    harden = (REPO/'linux/harden.sh').read_text()
    pre = harden[harden.index('SSHD_PRECLEAN=0'):harden.index('  set_sshd(){')]
    reb = harden[harden.index('if [ "$SSHD_PRECLEAN" -eq 1 ]'):harden.index('\n  else\n    log "    !! sshd -t FAILED')]
    script = ("set -u\nlog(){ :; }\nREBASELINE=0\nSSHD=%r\nBK=%r\n%s\n%s\n" % (str(sshd), str(bk), pre, reb))
    subprocess.run(['bash','-c', script], check=True)
    baseline_txt = (bk/'baseline.sha256').read_text()
    assert original in baseline_txt, "original hash must be preserved (drift kept unresolved)"
    assert digest(sshd) not in baseline_txt, "drifted hash must NOT be blessed"
    ok("#9 pre-existing sshd drift is NOT re-blessed on a normal rerun")

print("\nALL %d regression checks passed. No external network calls made." % len(PASS))
