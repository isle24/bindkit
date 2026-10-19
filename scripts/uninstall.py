#!/usr/bin/env python3
"""Remove unchanged installed code only. Keep credentials and user-modified files."""
import hashlib
import json
from pathlib import Path


def main():
    receipt = Path(__file__).resolve().with_name('install-receipt.json')
    data = json.loads(receipt.read_text())
    removed = kept = 0
    for item in data['files']:
        path = Path(item['path'])
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file() \
                or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            kept += 1
            continue
        path.unlink()
        removed += 1
    if kept == 0:
        receipt.unlink()
    print('Removed %d code files; kept %d modified files. Connection data preserved.' % (removed, kept))


if __name__ == '__main__':
    main()
