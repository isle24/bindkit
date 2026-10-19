#!/usr/bin/env python3
"""Portable release gate: no developer credentials, networks or external databases."""
import os
from pathlib import Path
import signal
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


def run_suite(args, env, timeout=180):
    proc = subprocess.Popen([sys.executable, *args], cwd=ROOT, env=env, start_new_session=True)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print('Test suite exceeded %s seconds: ' % timeout + ' '.join(args), file=sys.stderr)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # A suite may exit before a stubborn child does; remove the entire owned group.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        return 124


def main():
    with tempfile.TemporaryDirectory(prefix='bindkit-test-home-') as home:
        env = dict(os.environ, HOME=home, PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
        for name in ('BINDCONSOLE_HOME', 'DBBIND_CONFIG', 'DBBIND_MYSQL', 'DBBIND_PSQL', 'DBBIND_SQLITE3'):
            env.pop(name, None)
        for args in COMMANDS:
            print('\nRunning: python3 ' + ' '.join(args), flush=True)
            rc = run_suite(args, env)
            if rc:
                return rc
    return 0


if __name__ == '__main__':
    sys.exit(main())
