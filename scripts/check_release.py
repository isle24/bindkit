#!/usr/bin/env python3
"""Scan release candidates without opening any personal configuration or keys."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    'private-key': rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----\r?\n',
    'github-token': rb'(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,})',
    'aws-access-key': rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'personal-home-path': rb'/(?:Users|Volumes)/[A-Za-z0-9][^\s"\']*',
}
BAD_NAMES = {'config.json', 'databases.json', 'servers.json', 'secret.json', 'policy.json', 'audit.log'}
BAD_PARTS = {'.ssh', '.dbbind', '.bindconsole', '.env', 'screenshots', 'snapshots', '.work'}
BAD_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.sqlite', '.sqlite3', '.db', '.dump', '.log', '.png'}


def scan_bytes(name, data):
    path = Path(name)
    issues = []
    if path.name in BAD_NAMES or set(path.parts) & BAD_PARTS or path.suffix.lower() in BAD_SUFFIXES:
        issues.append('runtime-or-sensitive-file')
    if b'\x00' in data:
        issues.append('unexpected-binary')
    for label, pattern in PATTERNS.items():
        if re.search(pattern, data):
            issues.append(label)
    return issues


def candidates():
    p = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                       cwd=ROOT, capture_output=True)
    if p.returncode == 0:
        return sorted(set(p.stdout.decode().strip('\0').split('\0')) - {''})
    return sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob('*')
                  if p.is_file() and not set(p.relative_to(ROOT).parts) & {'dist', '.git', '__pycache__'})


def main():
    failed = []
    paths = candidates()
    for name in paths:
        path = ROOT / name
        if path.is_symlink():
            failed.append((name, ['unexpected-symlink']))
            continue
        issues = scan_bytes(name, path.read_bytes())
        if issues:
            failed.append((name, issues))
    for name, issues in failed:
        print('%s: %s' % (name, ', '.join(issues)), file=sys.stderr)
    print('Checked %d candidate files; %d blocked files. No secret values printed.' % (len(paths), len(failed)))
    return bool(failed)


if __name__ == '__main__':
    sys.exit(main())
