#!/usr/bin/env python3
"""User-level code installation. Never import, rewrite or delete connection state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time


def atomic_write(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.bindkit-install-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_file(path, content, mode):
    atomic_write(path, content, mode)


def install(source, home, bin_dir=None, console_dir=None, data_dir=None):
    source, home = Path(source).resolve(), Path(home).resolve()
    if os.name != 'posix' or sys.version_info < (3, 9):
        raise RuntimeError('BindKit requires macOS/Linux and Python 3.9 or later')
    if not shutil.which('ssh') or not shutil.which('ssh-keygen'):
        raise RuntimeError('OpenSSH client and ssh-keygen are required')
    bin_dir = Path(bin_dir).expanduser().absolute() if bin_dir else home / '.local/bin'
    console_dir = Path(console_dir).expanduser().absolute() if console_dir else home / '.bindconsole'
    data_dir = Path(data_dir).expanduser().absolute() if data_dir else home / '.local/share/bindkit'
    version = (source / 'VERSION').read_text().strip()
    receipt_path = data_dir / 'install-receipt.json'
    try:
        prior_paths = {x['path'] for x in json.loads(receipt_path.read_text())['files']}
    except (OSError, ValueError, KeyError, TypeError):
        prior_paths = set()
    mapping = [(source / 'sshbind/sshbind', bin_dir / 'sshbind', 0o755),
               (source / 'dbbind/dbbind', bin_dir / 'dbbind', 0o755)]
    for name in ('bindkit_console.py', 'bindkit_policy.py'):
        mapping.append((source / 'bindconsole' / name, console_dir / 'lib' / name, 0o644))
    for name in ('index.html', 'style.css', 'api.js', 'ui.js', 'app.js', 'pages.js'):
        mapping.append((source / 'bindconsole/web' / name, console_dir / 'web' / name, 0o644))
    for name in ('VERSION', 'README.md', 'LICENSE', 'AGENT.md'):
        mapping.append((source / name, data_dir / name, 0o644))
    mapping.append((source / 'scripts/uninstall.py', data_dir / 'uninstall.py', 0o755))
    # Existing agent instructions belong to the user; create only when absent.
    for relative in ('.dbbind/AGENT.md', '.ssh/sshbind/AGENT.md'):
        dest = home / relative
        if not os.path.lexists(dest) or (str(dest) in prior_paths and not dest.is_symlink()
                                       and dest.is_file()
                                       and dest.read_bytes() == (source / 'AGENT.md').read_bytes()):
            mapping.append((source / 'AGENT.md', dest, 0o644))
    updates = []
    receipt_files = []
    for src, dest, mode in mapping:
        if src.is_symlink() or not src.is_file():
            raise RuntimeError('Missing or unsafe installation source: %s' % src.name)
        if dest.is_dir() and not dest.is_symlink():
            raise RuntimeError('Refusing to replace directory: %s' % dest)
        content = src.read_bytes()
        receipt_files.append({'path': str(dest), 'sha256': hashlib.sha256(content).hexdigest()})
        updates.append((dest, content, mode))
    receipt = json.dumps({'version': version, 'files': receipt_files}, indent=2).encode() + b'\n'
    updates.append((receipt_path, receipt, 0o600))
    changed, backups = [], []
    try:
        for dest, content, mode in updates:
            previous = None
            backup = None
            if os.path.lexists(dest):
                if dest.is_symlink():
                    previous = ('link', os.readlink(dest), None)
                else:
                    previous = ('file', dest.read_bytes(), dest.stat().st_mode & 0o777)
                if previous[0] == 'file' and previous[1] == content and previous[2] == mode:
                    continue
                backup = dest.with_name(dest.name + '.bindkit-backup-' + str(time.time_ns()))
                backups.append(backup)
                shutil.copy2(dest, backup, follow_symlinks=False)
            changed.append((dest, backup))
            write_file(dest, content, mode)
    except BaseException:
        failed_restores = set()
        for dest, backup in reversed(changed):
            try:
                if backup is None:
                    if os.path.lexists(dest):
                        dest.unlink()
                else:
                    # Rename the existing backup: rollback must still work when the
                    # filesystem has no space for a newly allocated replacement.
                    os.replace(backup, dest)
            except OSError:
                if backup is not None:
                    failed_restores.add(backup)
                print('Rollback needs manual recovery for %s' % dest, file=sys.stderr)
        for backup in backups:
            if backup not in failed_restores and os.path.lexists(backup):
                backup.unlink()
        raise
    return {'version': version, 'bin_dir': str(bin_dir), 'console_dir': str(console_dir),
            'data_dir': str(data_dir), 'backups': [str(p) for p in backups]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--bin-dir', type=Path)
    p.add_argument('--console-dir', type=Path)
    p.add_argument('--data-dir', type=Path)
    args = p.parse_args()
    try:
        result = install(args.source_dir, Path.home(), args.bin_dir,
                         args.console_dir or os.environ.get('BINDCONSOLE_HOME'), args.data_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        p.exit(1, 'Installation failed: %s\n' % exc)
    print('BindKit %s installed in %s' % (result['version'], result['bin_dir']))
    if result['bin_dir'] not in os.environ.get('PATH', '').split(os.pathsep):
        import shlex
        print('Add to your shell: export PATH=%s:"$PATH"' % shlex.quote(result['bin_dir']))
    print('Start: sshbind --startserver  /  dbbind --startserver')
    print('Existing connections, credentials, policies and approvals were preserved.')
    if result['backups']:
        print('Previous code backed up beside replaced files (%d files).' % len(result['backups']))


if __name__ == '__main__':
    main()
