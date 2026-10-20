import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'scripts/install.py').is_file(), 'installer must exist')
        spec = importlib.util.spec_from_file_location('bindkit_install', ROOT / 'scripts/install.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.tmp = tempfile.TemporaryDirectory(prefix='bindkit-install-test-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def install(self):
        return self.module.install(ROOT, self.home)

    def test_clean_install_has_runnable_tools_and_console(self):
        self.install()
        env = dict(os.environ, HOME=str(self.home))
        for name in ('sshbind', 'dbbind'):
            tool = self.home / '.local/bin' / name
            self.assertTrue(os.access(tool, os.X_OK))
            p = subprocess.run([str(tool), '--help'], env=env, capture_output=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
        for name in ('bindkit_policy.py', 'bindkit_console.py'):
            self.assertTrue((self.home / '.bindconsole/lib' / name).is_file())
        self.assertTrue((self.home / '.bindconsole/web/index.html').is_file())
        self.assertFalse((self.home / '.bindconsole/secret.json').exists())
        self.assertFalse((self.home / '.dbbind/config.json').exists())

    def test_repeat_install_is_idempotent(self):
        self.install()
        self.install()
        self.assertEqual(list(self.home.rglob('*.bindkit-backup-*')), [])

    def test_upgrade_backs_up_existing_command(self):
        tool = self.home / '.local/bin/sshbind'
        tool.parent.mkdir(parents=True)
        tool.write_text('original-local-command')
        self.install()
        backups = list(tool.parent.glob('sshbind.bindkit-backup-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'original-local-command')

    def test_user_state_and_existing_agent_guide_are_preserved(self):
        sentinels = ['.dbbind/config.json', '.dbbind/databases.json',
                     '.ssh/sshbind/servers.json', '.ssh/sshbind/keys/existing',
                     '.bindconsole/secret.json', '.dbbind/policy.json',
                     '.bindconsole/audit.log', '.dbbind/AGENT.md']
        for rel in sentinels:
            p = self.home / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('disposable-user-state-marker')
        self.install()
        self.assertEqual([p.read_text() for p in map(self.home.__truediv__, sentinels)],
                         ['disposable-user-state-marker'] * len(sentinels))

    def test_upgrade_refreshes_only_unmodified_installer_managed_agent_guides(self):
        self.install()
        managed = self.home / '.ssh/sshbind/AGENT.md'
        edited = self.home / '.dbbind/AGENT.md'
        edited.write_text('user-written guide must survive')
        original = Path.read_bytes
        new_guide = original(ROOT / 'AGENT.md') + b'\nSynthetic upgrade instruction.\n'
        def read(path):
            return new_guide if path == ROOT / 'AGENT.md' else original(path)
        with patch.object(Path, 'read_bytes', read):
            self.install()
        self.assertEqual(managed.read_bytes(), new_guide)
        self.assertEqual(edited.read_text(), 'user-written guide must survive')

    def test_failed_install_rolls_back_replaced_files(self):
        tool = self.home / '.local/bin/sshbind'
        tool.parent.mkdir(parents=True)
        tool.write_text('original-command')
        real_write = self.module.write_file
        count = 0
        def failing_write(*args):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError('disposable failure injection')
            return real_write(*args)
        with patch.object(self.module, 'write_file', side_effect=failing_write):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(tool.read_text(), 'original-command')
        self.assertFalse((self.home / '.local/bin/dbbind').exists())
        self.assertEqual(list(self.home.rglob('*.bindkit-backup-*')), [])

    def test_persistent_disk_full_restores_code_without_new_writes(self):
        import errno
        for name in ('sshbind', 'dbbind'):
            p = self.home / '.local/bin' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('original-' + name)
        real_write = self.module.atomic_write
        count = 0
        def disk_full(*args):
            nonlocal count
            count += 1
            if count >= 3:
                raise OSError(errno.ENOSPC, 'disposable disk-full injection')
            return real_write(*args)
        with patch.object(self.module, 'atomic_write', side_effect=disk_full):
            with self.assertRaises(OSError):
                self.install()
        for name in ('sshbind', 'dbbind'):
            self.assertEqual((self.home / '.local/bin' / name).read_text(), 'original-' + name)
        self.assertEqual(list(self.home.rglob('*.bindkit-backup-*')), [])

    def test_failed_backup_leaves_no_partial_backup(self):
        tool = self.home / '.local/bin/sshbind'
        tool.parent.mkdir(parents=True)
        tool.write_text('original-command')
        def incomplete(src, dst, **kwargs):
            Path(dst).write_text('incomplete-copy')
            raise OSError('disposable backup failure')
        with patch.object(self.module.shutil, 'copy2', side_effect=incomplete):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(tool.read_text(), 'original-command')
        self.assertEqual(list(self.home.rglob('*.bindkit-backup-*')), [])

    def test_uninstall_preserves_data_and_modified_code(self):
        self.install()
        data = self.home / '.dbbind/config.json'
        data.write_text('disposable-user-state-marker')
        modified = self.home / '.local/bin/sshbind'
        modified.write_text('user-modified-command')
        p = subprocess.run(['python3', str(self.home / '.local/share/bindkit/uninstall.py')],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(data.read_text(), 'disposable-user-state-marker')
        self.assertEqual(modified.read_text(), 'user-modified-command')
        self.assertFalse((self.home / '.local/bin/dbbind').exists())


if __name__ == '__main__':
    unittest.main()
