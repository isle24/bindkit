#!/usr/bin/env python3
"""Portable release gate: no developer credentials, networks or external databases."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = [
    ['-m', 'unittest', 'discover', '-s', 'tests', '-v'],
    ['bindconsole/tests/policy/test_policy_unit.py'],
    ['bindconsole/tests/policy/test_acceptance_regressions.py'],
    ['bindconsole/tests/policy/test_handlers.py'],
    ['bindconsole/tests/policy/test_console_integration.py'],
    ['-m', 'unittest', 'discover', '-s', 'bindconsole/tests/backend', '-p', 'test_console.py', '-v'],
]


def main():
    with tempfile.TemporaryDirectory(prefix='bindkit-test-home-') as home:
        env = dict(os.environ, HOME=home, PYTHONDONTWRITEBYTECODE='1')
        for name in ('BINDCONSOLE_HOME', 'DBBIND_CONFIG', 'DBBIND_MYSQL', 'DBBIND_PSQL', 'DBBIND_SQLITE3'):
            env.pop(name, None)
        for args in COMMANDS:
            print('\nRunning: python3 ' + ' '.join(args), flush=True)
            p = subprocess.run([sys.executable, *args], cwd=ROOT, env=env)
            if p.returncode:
                return p.returncode
    return 0


if __name__ == '__main__':
    sys.exit(main())
