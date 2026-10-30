#!/usr/bin/env bash
# Standalone GitHub Release bootstrap and local checkout installer.
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo 'Python 3.9+ is required.' >&2; exit 1; }
bindkit_script="${BASH_SOURCE[0]:-}"
if [ -n "$bindkit_script" ]; then
  bindkit_source="$(cd "$(dirname "$bindkit_script")" && pwd)"
  if [ -f "$bindkit_source/scripts/install.py" ]; then
    exec python3 "$bindkit_source/scripts/install.py" "$@"
  fi
fi
exec python3 - "$@" <<'PYTHON_BOOTSTRAP'
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

VERSION = '1.3.0'
REPOSITORY = 'isle24/bindkit'


def download(url, destination):
    req = urllib.request.Request(url, headers={'User-Agent': 'BindKit-installer/' + VERSION})
    with urllib.request.urlopen(req, timeout=60) as response, open(destination, 'wb') as out:
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 10 * 1024 * 1024:
                raise ValueError('Release download exceeds 10 MiB')
            out.write(chunk)


def unpack(archive, expected, output):
    if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != expected:
        raise ValueError('SHA-256 mismatch; installation stopped')
    output = Path(output).resolve()
    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        seen, size = set(), 0
        for member in members:
            path = Path(member.name)
            target = (output / path).resolve()
            if path.is_absolute() or '..' in path.parts or target == output \
                    or output not in target.parents or member.name in seen \
                    or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe or duplicate release archive member')
            seen.add(member.name)
            size += member.size
            if member.size < 0 or size > 20 * 1024 * 1024 or len(seen) > 1000:
                raise ValueError('Release archive exceeds extraction limits')
        output.mkdir(parents=True)
        for member in members:
            target = output / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as src, target.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def main():
    if sys.version_info < (3, 9) or os.name != 'posix':
        raise RuntimeError('BindKit requires macOS/Linux and Python 3.9+')
    name = 'bindkit-v%s.tar.gz' % VERSION
    base = 'https://github.com/%s/releases/download/v%s/' % (REPOSITORY, VERSION)
    with tempfile.TemporaryDirectory(prefix='bindkit-download-') as tmp:
        root = Path(tmp)
        archive, checksums = root / name, root / 'SHA256SUMS'
        print('Downloading BindKit %s from %s' % (VERSION, REPOSITORY), flush=True)
        download(base + name, archive)
        download(base + 'SHA256SUMS', checksums)
        matches = [line.split()[0] for line in checksums.read_text().splitlines()
                   if len(line.split()) == 2 and line.split()[1].lstrip('*') == name]
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous archive checksum')
        unpack(archive, matches[0], root / 'unpacked')
        package = root / 'unpacked' / ('bindkit-v' + VERSION)
        if (package / 'VERSION').read_text().strip() != VERSION:
            raise ValueError('Release version mismatch')
        subprocess.run([sys.executable, str(package / 'scripts/install.py'), *sys.argv[1:]], check=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        sys.exit('Installation stopped: %s' % exc)
PYTHON_BOOTSTRAP
