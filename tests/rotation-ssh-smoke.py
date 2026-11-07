"""CI ONLY: real SSH/sudo/password changes on disposable runner accounts, loopback only."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

if os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('Requires disposable GitHub runner')
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rotate',ROOT/'rotate_pass/rotate.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,**kw)
def root(args,**kw):return run(['sudo',*args],**kw)
accounts=['tcdc-ci-admin','tcdc-ci-target']
for user in accounts:
    if subprocess.run(['getent','passwd',user],stdout=subprocess.DEVNULL).returncode==0:raise SystemExit('Refusing existing test account')
created=[];server=None;policy_created=False
with tempfile.TemporaryDirectory(prefix='rotation-ssh-') as temporary:
    path=Path(temporary)
    try:
        for user in accounts:
            root(['useradd','-M','-s','/bin/bash',user]);created.append(user)
        initial=r.gen_password(20)
        root(['chpasswd'],input=''.join(user+':'+initial+'\n' for user in accounts))
        policy='/etc/sudoers.d/tcdc-ci-rotation'
        if Path(policy).exists():raise RuntimeError('Refusing existing sudo policy fixture')
        def set_policy(password):
            local=path/'sudoers';local.write_text('tcdc-ci-admin ALL=(root) '+('PASSWD' if password else 'NOPASSWD')+': ALL\n')
            root(['visudo','-cf',str(local)])
            root(['install','-m','440',str(local),policy])
        set_policy(True);policy_created=True
        run(['ssh-keygen','-t','ed25519','-N','','-f',str(path/'hostkey')])
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        root(['mkdir','-p','/run/sshd'])
        config=path/'sshd_config'
        config.write_text('Port %s\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM yes\nPermitRootLogin no\nAllowUsers tcdc-ci-admin tcdc-ci-target\nAuthorizedKeysFile none\n' % (port,path/'hostkey',path/'pid'))
        root(['/usr/sbin/sshd','-t','-f',str(config)])
        server=subprocess.Popen(['sudo','/usr/sbin/sshd','-D','-e','-f',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('Fixture SSH server did not start')
        known=path/'known_hosts';known.write_text('[127.0.0.1]:%s %s' % (port,(path/'hostkey.pub').read_text()))
        cfg={'ssh':{'admin_user':accounts[0],'admin_password':initial,'port':port,'known_hosts_file':str(known)}}
        box={'name':'fixture','host':'127.0.0.1'}
        r.STATE=str(path/'state.json')
        def verify(user,password):
            client=r.paramiko.SSHClient();client.load_host_keys(str(known));client.set_missing_host_key_policy(r.paramiko.RejectPolicy())
            try:client.connect('127.0.0.1',port=port,username=user,password=password,allow_agent=False,look_for_keys=False,timeout=5,auth_timeout=5)
            finally:client.close()
        for needs_password in (True,False):
            set_policy(needs_password)
            session=r.Box(cfg,box)
            try:
                session.connect()
                assert session.check_sudo()[0], 'real sudo authentication failed'
                assert session.user_exists(accounts[1])
                candidate=r.gen_password(20)
                assert session.change_and_verify(accounts[1],candidate)[0], 'target change failed'
                verify(accounts[1],candidate)
                if needs_password:
                    session.pw='deliberately-wrong'
                    try:code,out,err=session.sudo('id -u');assert code!=0, 'wrong sudo password accepted'
                    except RuntimeError:pass
                    verify(accounts[1],candidate)
            finally:session.close()
            print('PASS: real SSH + sudo + target rotation + fresh login; password required=%s'%needs_password)
        # The login administrator itself can rotate without a second sudo using stale credentials.
        set_policy(True);session=r.Box(cfg,box)
        try:
            session.connect();candidate=r.gen_password(20)
            assert session.change_and_verify(accounts[0],candidate)[0]
            verify(accounts[0],candidate)
        finally:session.close()
        print('PASS: administrator rotation and new SSH login')
        empty=path/'unknown_hosts';empty.write_text('');cfg['ssh']['known_hosts_file']=str(empty)
        session=r.Box(cfg,box)
        try:
            try:session.connect()
            except r.paramiko.SSHException:pass
            else:raise AssertionError('unknown host key accepted')
        finally:session.close()
        print('PASS: unknown SSH host key rejected before authentication')
    finally:
        if server:
            if (path/'pid').exists():subprocess.run(['sudo','kill',str(int((path/'pid').read_text()))],check=False,capture_output=True)
            try:server.wait(timeout=10)
            except subprocess.TimeoutExpired:server.terminate()
        if policy_created and Path(policy).exists():subprocess.run(['sudo','rm','-f',policy],check=False)
        for user in created:subprocess.run(['sudo','userdel',user],check=False,capture_output=True)
