"""Unprivileged real-helper and installer fixtures; no host paths or network touched."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('baseline', REPO/'linux/baseline.py')
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)

@unittest.skipIf(os.name == 'nt', 'Linux fixture; exercised by Ubuntu CI')
class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for directory in b.DIRECTORIES + ('/root/tcdc-baseline', '/usr/local/sbin', '/usr/local/lib/tcdc'):
            self.path(directory).mkdir(parents=True, exist_ok=True)
        self.path('/etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\n')
    def tearDown(self): self.temp.cleanup()
    def path(self, name): return self.root/name.lstrip('/')
    def test_content_link_and_metadata_changes(self):
        file = self.path('/etc/cron.d/space name'); file.write_text('known')
        target = self.root/'target'; target.write_text('known')
        link = self.path('/etc/cron.d/link'); link.symlink_to(target)
        before=b.snapshot(self.root)
        target.write_text('changed')
        self.assertTrue(any('/link' in x for x in b.compare(before,b.snapshot(self.root))))
        target.write_text('known')
        other=self.root/'other'; other.write_text('known')
        link.unlink(); link.symlink_to(other)
        self.assertTrue(any('/link' in x for x in b.compare(before,b.snapshot(self.root))))
        file.chmod(0o777)
        self.assertTrue(any('space name' in x for x in b.compare(before,b.snapshot(self.root))))
        new=self.path('/etc/cron.d/tcdc-watch-helper\nforged');new.write_text('new')
        messages=b.compare(before,b.snapshot(self.root))
        self.assertTrue(any('NEW' in x and 'tcdc-watch-helper' in x for x in messages))
        self.assertFalse(any('\n' in x for x in messages))
    def test_missing_keys_and_removals(self):
        before=b.snapshot(self.root)
        key=self.path('/root/.ssh/authorized_keys');key.parent.mkdir();key.write_text('fixture')
        self.assertTrue(any('NEW' in x and 'authorized_keys' in x for x in b.compare(before,b.snapshot(self.root))))
        self.path('/etc/passwd').unlink()
        with self.assertRaises(FileNotFoundError): b.snapshot(self.root)
    def install(self, *args):
        source=self.root/'source';source.mkdir(exist_ok=True)
        for name in ('baseline.py','watch-agent.sh'): shutil.copy(REPO/'linux'/name,source/name)
        script=(REPO/'linux/harden.sh').read_text()
        # Redirect all privileged writes; never run the repository hardener directly on CI.
        for path in ('/root/tcdc-baseline','/usr/local/lib/tcdc','/usr/local/sbin/tcdc-watch','/etc/systemd/system'):
            script=script.replace(path,str(self.path(path)))
        script=script.replace('python3 "$SELFDIR/baseline.py"', 'python3 "$SELFDIR/baseline.py" --root "$TEST_ROOT"')
        script=script.replace('python3 '+str(self.path('/usr/local/lib/tcdc/baseline.py')), 'python3 '+str(self.path('/usr/local/lib/tcdc/baseline.py'))+' --root "$TEST_ROOT"')
        (source/'harden.sh').write_text(script)
        binpath=self.root/'bin';binpath.mkdir(exist_ok=True)
        stubs={'id':'echo 0','getent':"if [ \"$1\" = passwd ]; then cat \"$TEST_ROOT/etc/passwd\"; fi",'systemctl':'exit 0'}
        for name,body in stubs.items():
            path=binpath/name;path.write_text('#!/bin/sh\n'+body+'\n');path.chmod(0o700)
        env=dict(os.environ,PATH=str(binpath)+':'+os.environ['PATH'],TEST_ROOT=str(self.root))
        return subprocess.run(['bash',str(source/'harden.sh'),'fixture','--accept-initial-state',*args],env=env,text=True,capture_output=True)
    def test_install_tracks_own_units_and_rerun_preserves_drift(self):
        result=self.install();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        baseline=self.path('/root/tcdc-baseline/integrity.json')
        before=b.load(baseline)
        self.assertEqual(b.compare(before,b.snapshot(self.root)),[])
        unit=self.path('/etc/systemd/system/tcdc-watch.service');unit.write_text('altered ExecStart')
        self.assertTrue(any('tcdc-watch.service' in x for x in b.compare(before,b.snapshot(self.root))))
        config=self.path('/etc/ssh/sshd_config');config.write_text('AuthorizedKeysFile fixture')
        result=self.install();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(before,b.load(baseline))
        self.assertTrue(any('sshd_config' in x for x in b.compare(before,b.snapshot(self.root))))
    def test_upgrade_refuses_and_rebaseline_archives(self):
        legacy=self.path('/root/tcdc-baseline/baseline.sha256');legacy.write_text('old evidence')
        result=self.install();self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(legacy.read_text(),'old evidence')
        self.assertFalse(self.path('/root/tcdc-baseline/integrity.json').exists())
        result=self.install('--rebaseline');self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        archives=list(legacy.parent.glob('accepted-*/baseline.sha256'))
        self.assertEqual(len(archives),1);self.assertEqual(archives[0].read_text(),'old evidence')
        sudo=self.path('/etc/sudoers.d/operator');sudo.write_text('known')
        result=self.install('--rebaseline');self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        before=b.load(legacy.parent/'integrity.json');sudo.write_text('changed')
        self.assertTrue(any('/sudoers.d/operator' in x for x in b.compare(before,b.snapshot(self.root))))

if __name__=='__main__': unittest.main()
