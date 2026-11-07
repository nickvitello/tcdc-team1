#!/usr/bin/env python3
"""Independent read-only watcher health check. Run from a trusted checkout as root."""
import hashlib
import subprocess
import sys
import time
from pathlib import Path


def scheduler_issues(timer, service, now_us, max_age=180):
    problems=[]
    if timer.get('LoadState') != 'loaded' or timer.get('ActiveState') != 'active':
        problems.append('timer missing or inactive')
    if timer.get('UnitFileState') not in ('enabled','enabled-runtime'):
        problems.append('timer is not enabled')
    if service.get('LoadState') != 'loaded': problems.append('service missing')
    if service.get('Result') != 'success' or service.get('ExecMainStatus') != '0':
        problems.append('last watcher execution failed or is unknown')
    try:
        stamp=int(service.get('ExecMainExitTimestampMonotonic','0'))
        age=(now_us-stamp)/1_000_000
        if stamp <= 0 or age < 0 or age > max_age:
            problems.append('no recent completed watcher run')
    except ValueError:
        problems.append('invalid watcher completion timestamp')
    return problems


def properties(unit):
    result=subprocess.run(['systemctl','show',unit,'--no-pager'],capture_output=True,text=True,timeout=10,check=True)
    return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)


def main():
    source=Path(__file__).resolve().parent
    try:
        issues=scheduler_issues(properties('tcdc-watch.timer'),properties('tcdc-watch.service'),int(time.monotonic()*1_000_000))
        for name,destination in [('watch-agent.sh','/usr/local/sbin/tcdc-watch'),('baseline.py','/usr/local/lib/tcdc/baseline.py')]:
            path=Path(destination)
            if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                issues.append('unsafe owner/mode/type: '+destination)
            if hashlib.sha256(path.read_bytes()).digest()!=hashlib.sha256((source/name).read_bytes()).digest():
                issues.append('installed module differs from trusted checkout: '+name)
        baseline=Path('/root/tcdc-baseline/integrity.json')
        if not baseline.is_file() or baseline.is_symlink(): issues.append('accepted baseline missing or symlinked')
    except (OSError,subprocess.SubprocessError,ValueError) as ex:
        issues=['health collection failed: '+str(ex)]
    for issue in issues: print('UNHEALTHY: '+issue)
    if not issues: print('HEALTHY: timer enabled, recent completed run, and installed module hashes match this checkout')
    print('This local observation cannot establish trust in a root-compromised OS. Review drift.log separately.')
    return 1 if issues else 0

if __name__=='__main__':sys.exit(main())
