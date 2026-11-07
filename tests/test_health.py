import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('health',Path(__file__).resolve().parents[1]/'linux/health.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class HealthTests(unittest.TestCase):
    def test_scheduler_states(self):
        timer={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled'}
        service={'LoadState':'loaded','Result':'success','ExecMainStatus':'0','ExecMainExitTimestampMonotonic':'990000000'}
        self.assertEqual(h.scheduler_issues(timer,service,1000000000),[])
        for changed in [dict(timer,ActiveState='inactive'),dict(timer,UnitFileState='disabled'),dict(timer,LoadState='not-found')]:self.assertTrue(h.scheduler_issues(changed,service,1000000000))
        for changed in [dict(service,Result='exit-code'),dict(service,ExecMainStatus='2'),dict(service,ExecMainExitTimestampMonotonic='0'),dict(service,ExecMainExitTimestampMonotonic='1000000'),dict(service,ExecMainExitTimestampMonotonic='future')]:self.assertTrue(h.scheduler_issues(timer,changed,1000000000))
if __name__=='__main__':unittest.main()
