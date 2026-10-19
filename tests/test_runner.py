import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RunnerTests(unittest.TestCase):
    def test_timed_out_suite_does_not_leave_child_process(self):
        spec = importlib.util.spec_from_file_location('bindkit_runner', ROOT / 'scripts/test.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertTrue(hasattr(mod, 'run_suite'), 'runner must own timeout cleanup')
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'child.pid'
            code = ('import subprocess,sys,pathlib,time; '
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]); '
                    'pathlib.Path(%r).write_text(str(p.pid)); time.sleep(60)' % str(marker))
            pid = None
            try:
                rc = mod.run_suite(['-c', code], dict(os.environ), timeout=2)
                self.assertEqual(rc, 124)
                pid = int(marker.read_text())
                alive = True
                for _ in range(30):
                    result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='],
                                            capture_output=True, text=True)
                    alive = result.returncode == 0 and not result.stdout.strip().startswith('Z')
                    if not alive:
                        break
                    time.sleep(.05)
                self.assertFalse(alive, 'suite child survived timeout')
            finally:
                if pid is None and marker.exists():
                    pid = int(marker.read_text())
                if pid:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
