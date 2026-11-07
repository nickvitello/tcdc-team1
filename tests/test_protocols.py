import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
m=module(REPO/'watchtower/monitor.py','monitor')
def name(value):return b''.join(bytes([len(p)])+p.encode() for p in value.split('.'))+b'\0'
def rr(owner='expected.example',kind=1,cls=1,value=b'\xc0\x00\x02\x01'):
    return name(owner)+struct.pack('>HHIH',kind,cls,60,len(value))+value

def packet(answer=None,question='expected.example',flags=0x8180):
    return struct.pack('>6H',0x1234,flags,1,1,0,0)+name(question)+b'\0\1\0\1'+(rr() if answer is None else answer)

class ProtocolTests(unittest.TestCase):
    def check(self,data): return m._dns_response(data,0x1234,(b'expected',b'example'),True,'192.0.2.1')[0]
    def test_ldap_structural_validation(self):
        valid=bytes.fromhex('300c02010161070a010004000400')
        self.assertTrue(m._ldap_response(valid)[0])
        for data in (valid[:-1], valid+b'junk', valid.replace(b'\x02\x01\x01',b'\x02\x01\x02',1), b'\x30\x0chello\x61\x0a\x01\x00junk'):
            self.assertFalse(m._ldap_response(data)[0])
    def test_http_redirect_scope(self):
        req=m.urllib.request.Request('http://127.0.0.1:80/')
        with self.assertRaises(ValueError):m.ScopedRedirect().redirect_request(req,None,302,'',{},'http://outside.invalid/')
    def test_dns_positive(self): self.assertTrue(self.check(packet()))
    def test_dns_negative(self):
        for data in [packet(question='wrong.example'),packet(rr(owner='wrong.example')),
                     packet(b'\xc0\xff'+rr()[len(name('expected.example')):]),
                     packet(rr(cls=3)),packet(rr(value=b'bad')),packet(flags=0x8380),
                     packet()+b'junk',packet(rr(kind=5,value=name('expected.example')))]:
            with self.subTest(data=data): self.assertFalse(self.check(data))
    def test_cname(self):
        data=packet(rr(kind=5,value=name('alias.example')))
        data=data[:6]+b'\0\2'+data[8:]+rr(owner='alias.example')
        self.assertTrue(self.check(data))
    def test_valid_compression(self):
        self.assertTrue(self.check(packet(b'\xc0\x0c'+rr()[len(name('expected.example')):])))
    def test_wrong_source_port_and_socket_close(self):
        class Socket:
            closed=False
            def settimeout(self,n):pass
            def sendto(self,data,target):pass
            def recvfrom(self,n):return packet(),('127.0.0.1',54)
            def close(self):self.closed=True
        sock=Socket()
        with patch.object(m.socket,'socket',return_value=sock),patch.object(m.secrets,'randbits',return_value=0x1234):
            self.assertFalse(m.c_dns({'host':'127.0.0.1','query':'expected.example'})[0])
        self.assertTrue(sock.closed)

class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        shutil.copy(REPO/'watchtower/vault.py',self.root/'vault.py');self.v=module(self.root/'vault.py','testvault')
    def tearDown(self):self.temp.cleanup()
    def test_invalid_schema_preserved(self):
        path=self.root/'vault.json';bad='{"passwords": {}, "services": {}}';path.write_text(bad)
        with self.assertRaises(SystemExit),contextlib.redirect_stdout(io.StringIO()):self.v.cmd_sync('x','y')
        self.assertEqual(path.read_text(),bad)
    def test_protected_account(self):
        with self.assertRaises(SystemExit),contextlib.redirect_stdout(io.StringIO()):self.v.cmd_set('box','DOMAIN\\blackteam','fixture',False,True)
        self.assertFalse((self.root/'vault.json').exists())
    def test_powershell_literal_and_no_secret(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):self.v.cmd_set('box',"o'brien; echo BAD",'SECRET',False,True)
        self.assertIn("-Identity 'o''brien; echo BAD'",output.getvalue())
        self.assertNotIn('SECRET',output.getvalue())
    def test_concurrent_writes(self):
        import subprocess,sys
        children=[subprocess.Popen([sys.executable,str(self.root/'vault.py'),'svc','svc'+str(i),'user','fixture'],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(8)]
        for child in children:
            out,err=child.communicate(timeout=30);self.assertEqual(child.returncode,0,err)
        self.assertEqual(len(json.loads((self.root/'vault.json').read_text())['services']),8)

if __name__=='__main__':unittest.main()
