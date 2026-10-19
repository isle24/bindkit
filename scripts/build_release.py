#!/usr/bin/env python3
"""Build a source-only distribution from the explicit release-files.txt allowlist."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

from check_release import scan_bytes

ROOT = Path(__file__).resolve().parents[1]


def build(root=ROOT):
    root = Path(root).resolve()
    version = (root / 'VERSION').read_text().strip()
    if not __import__('re').fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid version')
    names = [s.strip() for s in (root / 'release-files.txt').read_text().splitlines()
             if s.strip() and not s.startswith('#')]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate release entries')
    manifest, payload = {}, {}
    for name in names:
        path = root / name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or not path.is_file():
            raise ValueError('Unsafe or missing release path: ' + name)
        data = path.read_bytes()
        issues = scan_bytes(name, data)
        if issues:
            raise ValueError('Blocked release path %s: %s' % (name, ', '.join(issues)))
        payload[name] = data
        manifest[name] = hashlib.sha256(data).hexdigest()
    payload['MANIFEST.json'] = (json.dumps({'version': version, 'files': manifest},
                                         indent=2, sort_keys=True) + '\n').encode()
    dist = root / 'dist'
    dist.mkdir(exist_ok=True)
    archive = dist / ('bindkit-v%s.tar.gz' % version)
    prefix = 'bindkit-v' + version
    with tarfile.open(archive, 'w:gz') as tf:
        for name, data in sorted(payload.items()):
            info = tarfile.TarInfo(prefix + '/' + name)
            info.size = len(data)
            info.mode = 0o755 if name in ('install.sh', 'sshbind/sshbind', 'dbbind/dbbind') else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tf.addfile(info, io.BytesIO(data))
    bootstrap = dist / 'install.sh'
    bootstrap.write_bytes((root / 'install.sh').read_bytes())
    checksums = ''.join('%s  %s\n' % (hashlib.sha256(p.read_bytes()).hexdigest(), p.name)
                        for p in (archive, bootstrap))
    (dist / 'SHA256SUMS').write_text(checksums)
    # Read back every payload entry; the archive is the actual published product.
    with tarfile.open(archive, 'r:gz') as tf:
        actual = {m.name.removeprefix(prefix + '/'): tf.extractfile(m).read() for m in tf.getmembers()}
    if actual != payload:
        raise ValueError('Archive verification failed')
    print('Built %s (%d payload files); archive contents and checksums verified.' % (archive.name, len(payload)))
    return archive


if __name__ == '__main__':
    build()
