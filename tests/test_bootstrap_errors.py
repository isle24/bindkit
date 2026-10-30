"""First-auth failures must remain useful and must never reflect credentials."""
import json
import os
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import test_cli_integrations as fixtures
import bindkit_vault
from test_password_transport import MemoryVault


class BootstrapErrorTests(unittest.TestCase):
    setUp = fixtures.CLIIntegrationTests.setUp
    synthetic_create_transport = fixtures.CLIIntegrationTests.synthetic_create_transport

    def body(self, **kwargs):
        return dict(name='literal-password', host='example.invalid', user='operator',
                    password='synthetic%$DO_NOT_EXPAND', **kwargs)

    def assert_safe_failure(self, body, code):
        with self.assertRaises(Exception) as error:
            self.ssh.console_ssh_create(body)
        self.assertEqual(getattr(error.exception, 'code', None), code)
        self.assertNotIn(body['password'], str(error.exception))
        self.assertNotIn('literal-password', self.ssh.load_state()['servers'])

    def test_password_authentication_failure_is_identified(self):
        with self.synthetic_create_transport(), patch.object(self.ssh, 'install_pubkey',
                return_value=(False, '认证失败：凭据不正确，或服务器不接受这种认证方式')):
            self.assert_safe_failure(self.body(), 'AUTHENTICATION_FAILED')

    def test_remote_home_failure_is_identified_after_password_authentication(self):
        with self.synthetic_create_transport(), patch.object(self.ssh, 'install_pubkey',
                return_value=(False, '服务器上该用户的家目录不存在或不可写，无法创建 ~/.ssh')):
            self.assert_safe_failure(self.body(), 'REMOTE_KEY_INSTALL_FAILED')

    def test_key_verification_failure_does_not_blame_password(self):
        with self.synthetic_create_transport(verify_ok=False):
            self.assert_safe_failure(self.body(), 'KEY_LOGIN_VERIFICATION_FAILED')

    def test_unknown_local_error_does_not_reflect_secret(self):
        with self.synthetic_create_transport(), patch.object(self.ssh, 'gen_keypair',
                side_effect=RuntimeError(self.body()['password'])):
            self.assert_safe_failure(self.body(), 'LOCAL_SETUP_FAILED')

    def test_import_password_retention_preserves_safe_failure_code(self):
        with self.synthetic_create_transport(verify_ok=False), \
                patch.object(bindkit_vault, 'Vault', return_value=MemoryVault()):
            self.assert_safe_failure(self.body(preserve_password=True), 'KEY_LOGIN_VERIFICATION_FAILED')

    def test_child_freeform_message_is_never_reflected(self):
        for code in ('AUTHENTICATION_FAILED', 'UNKNOWN_SECRET_CODE'):
            body = self.body()
            payload = 'SSHBIND_FAILURE ' + json.dumps({'code': code, 'message': body['password']})
            with self.subTest(code=code), patch.object(self.ssh, '_run_self', return_value=(1, payload, body['password'])):
                self.assert_safe_failure(body, code if code != 'UNKNOWN_SECRET_CODE' else 'CONNECTION_CREATE_FAILED')

    def test_remote_setup_permission_failures_emit_fixed_stage_marker(self):
        home = Path(self.temp.name)
        helpers = home / 'failing-tools'
        helpers.mkdir()
        for operation in ('mkdir', 'chmod', 'touch'):
            with self.subTest(operation=operation):
                command = helpers / operation
                command.write_text('#!/bin/sh\nprintf "synthetic filesystem Permission denied\\n" >&2\nexit 1\n')
                command.chmod(0o700)
                try:
                    result = subprocess.run(['/bin/sh', '-c', self.ssh.REMOTE_INSTALL],
                        env=dict(os.environ, HOME=str(home), PATH=str(helpers) + os.pathsep + os.defpath),
                        input=b'ssh-ed25519 synthetic-public', capture_output=True, timeout=5)
                finally:
                    command.unlink()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'SSHBIND_WRITE_FAILED', result.stdout)

    def test_remote_command_permission_denied_is_not_password_authentication(self):
        detail = self.ssh.classify_ssh_error(1, 'mkdir: Permission denied', '')
        self.assertFalse(detail.startswith('认证失败'))


if __name__ == '__main__': unittest.main()
