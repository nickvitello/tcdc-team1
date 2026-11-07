"""Offline adversarial tests for the remote password rotator; no connections or resets."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

REPO=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rotate',REPO/'rotate_pass/rotate.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Channel:
    def __init__(self,password=True,fail=False):
        self.password=password;self.fail=fail;self.errors=b'';self.out=b'';self.sent=[];self.done=False;self.closed=False
    def settimeout(self,n):pass
    def exec_command(self,cmd):
        self.cmd=cmd;parts=shlex.split(cmd)
        self.prompt=parts[4].encode();self.ready=re.search(r'TCDC_READY_[0-9a-f]+',parts[-1]).group().encode()
        self.errors=self.prompt if self.password else self.ready+b'\n'
    def recv_ready(self):return bool(self.out)
    def recv(self,n):out=self.out;self.out=b'';return out
    def recv_stderr_ready(self):return bool(self.errors)
    def recv_stderr(self,n):out=self.errors[:7];self.errors=self.errors[7:];return out # fragmented prompt/ready
    def sendall(self,data):
        self.sent.append(data)
        if self.password and len(self.sent)==1:self.errors+=self.prompt if self.fail else self.ready+b'\n'
    def shutdown_write(self):self.done=True;self.out=b'TCDC_CHANGED\n'
    def exit_status_ready(self):return self.done
    def recv_exit_status(self):return 0
    def close(self):self.closed=True

class RotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.patches=[patch.object(r,k,str(self.root/v)) for k,v in [('LOG','journal.jsonl'),('STATE','state.json'),('CONFIG','config.json')]]
        for p in self.patches:p.start()
        self.cfg={'ssh':{'admin_user':'washington','admin_password':'sudo-secret'},'users':['washington','kennedy'],'admins':['washington'],'boxes':[{'name':'fixture','host':'127.0.0.1'}]}
        self.args=argparse.Namespace(boxes='fixture',users='kennedy',dry_run=False,yes=True,same_across_boxes=False)
    def tearDown(self):
        for p in self.patches:p.stop()
        self.tmp.cleanup()
    def test_cli_injection_and_unlisted_accounts_rejected(self):
        for user in ["kennedy; id", "x'", '-root', 'root', 'blackteam', 'whiteteam']:
            self.args.users=user
            with self.subTest(user=user),self.assertRaises((ValueError,SystemExit)),contextlib.redirect_stderr(io.StringIO()):r.select(self.cfg,self.args)
    def test_methods_reject_injection_before_sudo(self):
        box=r.Box.__new__(r.Box);box.sudo=Mock()
        with self.assertRaises(ValueError):box.user_exists("x; id")
        with self.assertRaises(ValueError):box.change_and_verify('blackteam','Aa12345678901234')
        box.sudo.assert_not_called()
    def test_password_bounds(self):
        for n in [0,2,15,129]:
            with self.assertRaises(ValueError):r.gen_password(n)
        self.assertEqual(len(r.gen_password(16)),16)
    def test_known_hosts_required(self):
        client=Mock();fake=types.SimpleNamespace(SSHClient=Mock(return_value=client),RejectPolicy=Mock(return_value='REJECT'))
        with patch.object(r,'paramiko',fake):r.Box(self.cfg,self.cfg['boxes'][0])
        client.load_host_keys.assert_called_once();client.set_missing_host_key_policy.assert_called_once_with('REJECT')
    def test_sudo_password_and_nopasswd_protocol(self):
        for needs_password in [False,True]:
            channel=Channel(needs_password)
            box=r.Box.__new__(r.Box);box.pw='sudo-secret';box.c=Mock();box.c.get_transport.return_value.open_session.return_value=channel
            with patch.object(r.time,'sleep'):
                code,out,err=box.sudo('cat','COMMAND-INPUT\n')
            self.assertEqual(code,0);self.assertTrue(channel.closed)
            self.assertEqual(channel.sent,([b'sudo-secret\n'] if needs_password else [])+[b'COMMAND-INPUT\n'])
            self.assertNotIn('sudo-secret',channel.cmd);self.assertNotIn('COMMAND-INPUT',channel.cmd)
    def test_sudo_reprompt_fails_without_sending_payload(self):
        channel=Channel(True,True);box=r.Box.__new__(r.Box);box.pw='bad';box.c=Mock();box.c.get_transport.return_value.open_session.return_value=channel
        with patch.object(r.time,'sleep'),self.assertRaises(RuntimeError):box.sudo('cat','payload')
        self.assertEqual(channel.sent,[b'bad\n']);self.assertTrue(channel.closed)
    def test_no_shadow_hashes_returned(self):
        box=r.Box.__new__(r.Box);box.sudo=Mock(return_value=(0,'TCDC_CHANGED\n',''))
        self.assertTrue(box.change_and_verify('kennedy','Aa12345678901234')[0])
        cmd=box.sudo.call_args.args[0]
        self.assertNotIn('Aa12345678901234',cmd)
        self.assertIn('before=$(getent shadow',cmd);self.assertNotIn('echo "$before"',cmd)
    def test_corrupt_journal_fails_closed(self):
        Path(r.LOG).write_text('{broken')
        with self.assertRaises(ValueError):r.read_log()
    def test_private_write_atomic_and_repairs_mode(self):
        path=Path(r.STATE);path.write_text('before');path.chmod(0o644)
        r.private_write(str(path),'after');self.assertEqual(path.read_text(),'after')
        if os.name!='nt':self.assertEqual(path.stat().st_mode & 0o777,0o600)
    def test_dry_run_no_network_or_writes(self):
        self.args.dry_run=True
        with patch.object(r,'Box') as box,patch.object(r,'Sheet') as sheet,contextlib.redirect_stdout(io.StringIO()):r.cmd_rotate(self.cfg,self.args)
        box.assert_not_called();sheet.assert_not_called();self.assertFalse(Path(r.LOG).exists())
    def test_batch_refused_before_network(self):
        self.args.users='all'
        with patch.object(r,'Box') as box,self.assertRaises(SystemExit),contextlib.redirect_stderr(io.StringIO()):r.cmd_rotate(self.cfg,self.args)
        box.assert_not_called()
    def test_unknown_result_retains_candidate_blocks_retry(self):
        fake=Mock();fake.check_sudo.return_value=(True,'');fake.user_exists.return_value=True;fake.change_and_verify.return_value=(False,'unverified')
        with patch.object(r,'Box',return_value=fake),self.assertRaises(SystemExit),contextlib.redirect_stderr(io.StringIO()):r.cmd_rotate(self.cfg,self.args)
        events=r.read_log();self.assertEqual([e['status'] for e in events],['pending','unknown'])
        self.assertEqual(events[0]['password'],events[1]['password']);fake.close.assert_called_once()
        with patch.object(r,'Box') as box,self.assertRaises(SystemExit),contextlib.redirect_stderr(io.StringIO()):r.cmd_rotate(self.cfg,self.args)
        box.assert_not_called()
    def test_changed_requires_dashboard_ack(self):
        fake=Mock();fake.check_sudo.return_value=(True,'');fake.user_exists.return_value=True;fake.change_and_verify.return_value=(True,'')
        with patch.object(r,'Box',return_value=fake),contextlib.redirect_stdout(io.StringIO()):r.cmd_rotate(self.cfg,self.args)
        self.assertEqual(r.read_log()[-1]['status'],'changed')
        with patch('builtins.input',return_value='verified'),contextlib.redirect_stdout(io.StringIO()):r.cmd_ack(self.cfg,self.args)
        self.assertEqual(r.read_log()[-1]['status'],'synced')

if __name__=='__main__':unittest.main()
