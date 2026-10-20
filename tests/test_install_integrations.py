"""Integration-runtime installation uses synthetic builders; never pip/network/keychain."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class IntegrationInstallTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('integration_installer', ROOT / 'scripts/install.py')
        self.install_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.install_module)
        self.tmp = tempfile.TemporaryDirectory(prefix='bindkit integration tests ')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "user's home"
        self.home.mkdir()
        self.home = self.home.resolve()
        self.env = patch.dict(os.environ, {'HOME': str(self.home), 'BINDCONSOLE_HOME': str(self.home / '.bindconsole')})
        self.env.start(); self.addCleanup(self.env.stop)
        self.built = []
    def builder(self, runtime, requirements):
        self.built.append(runtime)
        (runtime / 'bin').mkdir(parents=True, exist_ok=True)
        # Fake interpreter forwards to current Python; argv handling is real.
        interpreter = runtime / 'bin/python'
        interpreter.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
        interpreter.chmod(0o755)
    def install(self, enabled=False, builder=None):
        return self.install_module.install(ROOT, self.home, with_integrations=enabled,
                                           runtime_builder=builder or self.builder)
    def test_core_install_does_not_build_optional_runtime(self):
        result = self.install()
        self.assertFalse(self.built)
        self.assertFalse(result['integrations'])
        self.assertTrue((self.home / '.local/bin/sshbind').read_text().startswith('#!/usr/bin/env python3'))
    def test_enabled_runtime_launches_both_tools_with_spaces_and_quotes(self):
        result = self.install(True)
        self.assertTrue(result['integrations']); self.assertEqual(len(self.built), 1)
        for tool in ('sshbind', 'dbbind'):
            launcher = self.home / '.local/bin' / tool
            self.assertTrue(launcher.read_text().startswith('#!/bin/sh'))
            call = subprocess.run([str(launcher), '--help'], capture_output=True, timeout=10)
            self.assertEqual(call.returncode, 0, call.stderr)
        receipt = json.loads((self.home / '.local/share/bindkit/install-receipt.json').read_text())
        paths = {entry['path'] for entry in receipt['files']}
        for name in ('bindkit_vault.py', 'bindkit_privilege.py', 'bindkit_connections.py', 'bindkit_ai.py', 'bindkit_catalog.py', 'bindkit_imports.py', 'bindkit_admin.py', 'bindkit_orchestration.py'):
            self.assertIn(str(self.home / '.bindconsole/lib' / name), paths)
        self.assertNotIn(str(self.built[0] / 'bin/python'), paths)
    def test_plain_upgrade_preserves_enabled_runtime_without_builder(self):
        self.install(True)
        original = (self.home / '.local/bin/sshbind').read_bytes()
        result = self.install(False, builder=lambda *a: self.fail('plain upgrade must reuse working runtime'))
        self.assertTrue(result['integrations'])
        self.assertEqual((self.home / '.local/bin/sshbind').read_bytes(), original)
        self.assertEqual(list(self.home.rglob('*.bindkit-backup-*')), [])
    def test_failed_runtime_build_leaves_old_code_receipt_and_state_untouched(self):
        self.install()
        receipt = self.home / '.local/share/bindkit/install-receipt.json'
        tool = self.home / '.local/bin/sshbind'
        old_receipt, old_tool = receipt.read_bytes(), tool.read_bytes()
        sentinel = self.home / '.ssh/sshbind/keys/existing'
        sentinel.parent.mkdir(parents=True); sentinel.write_text('synthetic key')
        def failure(runtime, requirements):
            (runtime / 'partial').write_text('incomplete'); raise RuntimeError('synthetic build failure')
        with self.assertRaises(RuntimeError): self.install(True, failure)
        self.assertEqual(receipt.read_bytes(), old_receipt); self.assertEqual(tool.read_bytes(), old_tool)
        self.assertEqual(sentinel.read_text(), 'synthetic key')
        self.assertEqual(list(receipt.parent.glob('integrations-runtime-*')), [])
    def test_code_rollback_removes_only_new_runtime(self):
        self.install()
        original = (self.home / '.local/bin/sshbind').read_bytes()
        real_write = self.install_module.write_file
        count = 0
        def failure(*args):
            nonlocal count
            count += 1
            if count == 3: raise OSError('synthetic disk failure')
            return real_write(*args)
        with patch.object(self.install_module, 'write_file', side_effect=failure):
            with self.assertRaises(OSError): self.install(True)
        self.assertEqual((self.home / '.local/bin/sshbind').read_bytes(), original)
        self.assertFalse(self.built[0].exists())
    def test_uninstall_preserves_credentials_and_runtime_generated_files(self):
        self.install(True)
        sentinel = self.home / '.dbbind/config.json'; sentinel.write_text('synthetic state')
        call = subprocess.run([sys.executable, str(self.home / '.local/share/bindkit/uninstall.py')], capture_output=True, timeout=10)
        self.assertEqual(call.returncode, 0, call.stderr)
        self.assertEqual(sentinel.read_text(), 'synthetic state')
        self.assertTrue((self.built[0] / 'bin/python').exists())
        self.assertFalse((self.home / '.local/bin/sshbind').exists())
    def test_local_bootstrap_exposes_optional_flag_without_network(self):
        call = subprocess.run(['bash', str(ROOT / 'install.sh'), '--help'], capture_output=True, timeout=10)
        self.assertEqual(call.returncode, 0)
        self.assertIn(b'--with-integrations', call.stdout)
    def test_builder_uses_only_isolated_virtualenv_python_and_bounded_pip(self):
        runtime = self.home / 'fake venv'; runtime.mkdir()
        commands = []
        def run(command, **kwargs):
            commands.append((command, kwargs))
            if command[1:3] == ['-m', 'venv']:
                (runtime / 'bin').mkdir(); (runtime / 'bin/python').touch()
            return subprocess.CompletedProcess(command, 0)
        with patch.object(self.install_module.subprocess, 'run', side_effect=run):
            self.install_module.build_integrations_runtime(runtime, ROOT / 'requirements-integrations.txt')
        self.assertEqual(commands[0][0][0], sys.executable)
        pip = [call for call in commands if 'pip' in call[0]][0]
        self.assertEqual(pip[0][0], str(runtime / 'bin/python'))
        self.assertIn('--isolated', pip[0]); self.assertIn('--require-virtualenv', pip[0])
        self.assertTrue(all('timeout' in kwargs for _, kwargs in commands))

    def test_repeated_optional_install_reuses_same_runtime(self):
        first = self.install(True)
        second = self.install(True, builder=lambda *a: self.fail('same runtime must not rebuild'))
        self.assertEqual(first['runtime'], second['runtime'])
        self.assertEqual(list(self.home.rglob('*.bindkit-backup-*')), [])
    def test_missing_runtime_plain_upgrade_stops_before_code_changes(self):
        self.install(True)
        tool = self.home / '.local/bin/sshbind'; original = tool.read_bytes()
        (self.built[0] / 'bin/python').unlink()
        with self.assertRaisesRegex(RuntimeError, '--with-integrations'): self.install(False)
        self.assertEqual(tool.read_bytes(), original)
    def test_builder_strips_python_and_pip_environment_and_hides_errors(self):
        captured = []
        def failure(command, **kwargs):
            captured.append(kwargs['env'])
            raise subprocess.CalledProcessError(1, command, stderr='synthetic-secret')
        with patch.dict(os.environ, {'PIP_TARGET': '/outside', 'PYTHONPATH': '/outside', 'PIP_INDEX_URL': 'synthetic-secret'}), patch.object(self.install_module.subprocess, 'run', side_effect=failure):
            with self.assertRaises(RuntimeError) as error:
                self.install_module.build_integrations_runtime(self.home / 'runtime', ROOT / 'requirements-integrations.txt')
        self.assertNotIn('synthetic-secret', str(error.exception))
        self.assertFalse(any(key.startswith(('PIP_', 'PYTHON')) for key in captured[0]))


if __name__ == '__main__': unittest.main()
