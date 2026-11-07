#!/usr/bin/env python3
"""Local file integrity snapshots. Standard library only; never transmits data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

VERSION = 3
DIRECTORIES = ('/etc/sudoers.d', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily',
               '/etc/cron.weekly', '/etc/cron.monthly', '/var/spool/cron',
               '/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system', '/etc/ssh')
FILES = ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers', '/etc/crontab',
         '/root/.ssh/authorized_keys', '/usr/local/sbin/tcdc-watch',
         '/usr/local/lib/tcdc/baseline.py')


def record(path):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {'kind': 'missing'}
    result = {'mode': stat.S_IMODE(st.st_mode), 'uid': st.st_uid, 'gid': st.st_gid}
    if path.is_symlink():
        result.update(kind='link', target=os.readlink(path))
        # Record both the link text and the bytes of a regular-file target. A dangling
        # link remains a tracked object; it must not vanish from the inventory.
        try:
            target = path.stat()
            if stat.S_ISREG(target.st_mode):
                result['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                result['target_mode'] = stat.S_IMODE(target.st_mode)
                result['target_uid'], result['target_gid'] = target.st_uid, target.st_gid
            else:
                result['target_kind'] = stat.S_IFMT(target.st_mode)
        except FileNotFoundError:
            result['target_missing'] = True
    elif stat.S_ISREG(st.st_mode):
        result.update(kind='file', sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    elif stat.S_ISDIR(st.st_mode):
        result['kind'] = 'directory'
    else:
        result.update(kind='special', type=stat.S_IFMT(st.st_mode))
    return result


def snapshot(root=Path('/')):
    root = root.resolve()
    def local(name): return root / name.lstrip('/')
    paths = set(FILES)
    for directory in DIRECTORIES:
        paths.add(directory)
        base = local(directory)
        if base.exists():
            def fail(error): raise error
            for parent, dirs, files in os.walk(base, followlinks=False, onerror=fail):
                for name in dirs + files:
                    paths.add('/' + str((Path(parent) / name).relative_to(root)))
    # NSS is authoritative on a real host; fixtures use only their own passwd file.
    if root == Path('/'):
        passwd = subprocess.check_output(['getent', 'passwd'], text=True)
    else:
        passwd = local('/etc/passwd').read_text()
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) == 7 and fields[5].startswith('/'):
            paths.add(fields[5].rstrip('/') + '/.ssh/authorized_keys')
    return {'version': VERSION, 'files': {p: record(local(p)) for p in sorted(paths)}}


def save(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.baseline-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def load(path):
    value = json.loads(path.read_text())
    if value.get('version') != VERSION or not isinstance(value.get('files'), dict):
        raise ValueError('incompatible baseline; archive and review before --rebaseline')
    return value


def compare(before, after):
    changes = []
    for path in sorted(before['files'].keys() | after['files'].keys()):
        old, new = before['files'].get(path), after['files'].get(path)
        if old != new:
            label = 'NEW' if old is None or old.get('kind') == 'missing' else 'CHANGED'
            if new is None or new.get('kind') == 'missing': label = 'GONE'
            # JSON quoting prevents a crafted filename from forging log lines.
            changes.append('%s file/link/metadata: %s' % (label, json.dumps(path)))
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['capture', 'check', 'validate'])
    parser.add_argument('baseline', type=Path)
    parser.add_argument('--root', type=Path, default=Path('/'), help='fixture root for offline tests')
    args = parser.parse_args()
    try:
        if args.action == 'capture': save(args.baseline, snapshot(args.root))
        elif args.action == 'validate': load(args.baseline)
        else:
            changes = compare(load(args.baseline), snapshot(args.root))
            for change in changes: print(change)
            return 1 if changes else 0
    except (OSError, ValueError, subprocess.SubprocessError) as ex:
        print('MONITOR ERROR: %s' % ex)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
