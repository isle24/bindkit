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


def _group_is_running(pgid):
    # macOS may return EPERM, rather than ESRCH, for an exited group that only
    # contains zombies. Inspect process metadata only, never command arguments.
    status = subprocess.run(['ps', '-axo', 'pgid=,stat='], capture_output=True, text=True)
    if status.returncode:
        return True
    for line in status.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == str(pgid) and not fields[1].startswith('Z'):
            return True
    return False


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
        except PermissionError:
            if _group_is_running(proc.pid):
                raise RuntimeError('Unable to terminate the owned test process group')
        proc.wait(timeout=5)
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
