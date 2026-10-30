"""Password connections must never fall through to key bootstrap or key execution."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
import logging
import shlex
import shutil
from unittest.mock import patch

from test_password_transport import (IsolatedHome, MemoryVault, LocalPasswordConnectionServer,
                                     PASSWORDS, paramiko)
import bindkit_orchestration as orchestration
import bindkit_privilege as privilege
import bindkit_vault
import bindkit_password
import bindkit_askpass
from bindkit_connections import ConnectionError


class PasswordCLITests(IsolatedHome):
    def setUp(self):
        super().setUp()
        self.server = dict(name='password-demo', host='example.invalid', user='operator', port=22,
            key='', auth_type='password', login_credential_ref='synthetic-ref', installed=True,
            verification_status='verified', revision=1)
        self.ssh.save_state({'servers': {'password-demo': self.server}})

    def test_list_and_public_status_allow_verified_password_without_key(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.ssh.cmd_list(types.SimpleNamespace(json=True))
        rows = [json.loads(output.getvalue())['servers'][0], self.ssh.console_ssh_get('password-demo')]
        for row in rows:
            self.assertTrue(row['usable'])
            self.assertEqual(row['auth_type'], 'password')
            self.assertFalse(row['key_exists'])
            self.assertNotIn('synthetic-ref', json.dumps(row))

    def test_unverified_password_reference_does_not_make_connection_usable(self):
        self.server.pop('verification_status')
        result = self.ssh._console_ssh_item('password-demo', self.server, None)
        self.assertFalse(result['usable'])
        self.assertEqual(result['verification_status'], 'pending')

    def test_identity_digest_binds_password_type_and_both_credential_references(self):
        original = orchestration.connection_context(self.server)
        for field, value in [('auth_type', 'key'), ('login_credential_ref', 'replacement'),
                             ('encrypted_login_ref', 'encrypted-replacement'), ('revision', 2)]:
            self.assertNotEqual(original, orchestration.connection_context(dict(self.server, **{field: value})))
        self.assertNotIn('synthetic-ref', json.dumps(original))

    def test_password_record_never_gets_managed_ssh_identity_block(self):
        self.assertEqual(self.ssh.render_block({'password-demo': self.server}), '')

    def test_password_remove_never_revokes_or_deletes_even_with_legacy_key_field(self):
        key = Path(self.home) / 'unrelated-key'
        key.write_text('synthetic-key')
        self.server['key'] = str(key)
        self.ssh.save_state({'servers': {'password-demo': self.server}})
        args = types.SimpleNamespace(name='password-demo', no_revoke=False, delete_key=True,
            keep_key=False, yes=True, force=False)
        with patch.object(self.ssh, 'uninstall_pubkey') as revoke, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.ssh.cmd_remove(args), 0)
        revoke.assert_not_called()
        self.assertTrue(key.exists())

    def test_managed_transport_preserves_environment_and_command_input(self):
        script = self.home / 'managed.py'
        script.write_text('import os,re,sys\n'
            'assert os.environ["SYNTHETIC_ASKPASS_ENV"] == "broker"\n'
            'assert "SSH_ASKPASS" in os.environ\n'
            'marker=re.search(r"BINDKIT_STARTED_[a-f0-9]+",sys.argv[-1]).group()\n'
            'sys.stderr.write(marker+"\\n"); sys.stderr.flush()\n'
            'sys.stdout.buffer.write(sys.stdin.buffer.read())\n')
        argv = [sys.executable, str(script)]
        environment = dict(os.environ, SYNTHETIC_ASKPASS_ENV='broker', SSH_ASKPASS='synthetic-helper')
        plan = privilege.build_plan('cat', 'operator', as_user='app')
        with patch.object(self.ssh, 'ssh_with_key', side_effect=AssertionError('key transport')):
            result = privilege.execute_plan(self.ssh, self.server, plan, MemoryVault(),
                stdin_data='payload\n', timeout=5, transport=(argv, environment))
        self.assertEqual(result['exit_code'], 0)
        self.assertTrue(result['started'])
        self.assertEqual(result['stdout'], 'payload\n')
        self.assertEqual(argv, [sys.executable, str(script)])

    def test_pending_cli_test_stays_read_only(self):
        self.server['verification_status'] = 'pending'
        self.server['installed'] = False
        self.ssh.save_state({'servers': {'password-demo': self.server}})
        before = Path(self.ssh.STATE_FILE).read_bytes()
        with patch.object(bindkit_password, 'test') as probe, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.ssh.main(['test', 'password-demo']), 1)
        probe.assert_not_called()
        self.assertEqual(before, Path(self.ssh.STATE_FILE).read_bytes())

    def test_web_pending_password_domain_metadata_update_keeps_native_path(self):
        self.server.update(source='finalshell', verification_status='pending', installed=False)
        self.ssh.save_state({'servers': {'password-demo': self.server}})
        with patch.object(self.ssh, 'run_ssh', side_effect=AssertionError('unexpected network')) as network, \
             patch.object(self.ssh, 'install_pubkey', side_effect=AssertionError('unexpected key installation')), \
             patch.object(self.ssh, 'gen_keypair', side_effect=AssertionError('unexpected key generation')):
            result = self.ssh.console_ssh_update('password-demo', {
                'user': r'CORP\operator', 'sudo_auth': 'nopasswd', 'note': 'domain account'})
        network.assert_not_called()
        self.assertTrue(result['ok'])
        row = self.ssh.load_state()['servers']['password-demo']
        self.assertEqual(row['user'], r'CORP\operator')
        self.assertEqual(row['auth_type'], 'password')
        self.assertEqual(row['source'], 'finalshell')
        self.assertEqual(row['key'], '')
        self.assertEqual(row['revision'], 2)
        self.assertEqual(row['verification_status'], 'pending')
        self.assertFalse(row['installed'])
        self.assertEqual(self.ssh.console_ssh_get('password-demo')['note'], 'domain account')

    def test_web_key_update_retains_legacy_username_validation(self):
        self.server.update(auth_type='key', key=str(self.home / 'synthetic-key'))
        self.ssh.save_state({'servers': {'password-demo': self.server}})
        before = Path(self.ssh.STATE_FILE).read_bytes()
        with patch.object(self.ssh, 'run_ssh', side_effect=AssertionError('unexpected network')) as network:
            with self.assertRaises(Exception):
                self.ssh.console_ssh_update('password-demo', {'user': r'CORP\operator', 'note': 'must not save'})
        network.assert_not_called()
        self.assertEqual(before, Path(self.ssh.STATE_FILE).read_bytes())

    def test_locked_vault_returns_json_once_without_key_fallback(self):
        vault = MemoryVault()
        output = io.StringIO()
        with patch.object(bindkit_vault, 'Vault', return_value=vault), \
             patch.object(vault, 'get', side_effect=RuntimeError('synthetic-secret')) as lookup, \
             patch.object(self.ssh, 'ssh_with_key', side_effect=AssertionError('key fallback')), \
             patch.object(self.ssh, 'run_ssh') as remote, contextlib.redirect_stdout(output):
            self.assertEqual(self.ssh.main(['exec', '--json', 'password-demo', 'uptime']), 255)
        self.assertEqual(lookup.call_count, 1)
        remote.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['exit_code'], 255)
        self.assertNotIn('synthetic-secret', output.getvalue())

    def test_password_create_unexpected_error_never_reflects_secret(self):
        with patch.object(bindkit_password, 'create', side_effect=RuntimeError('synthetic-secret')):
            with self.assertRaises(Exception) as error:
                self.ssh.console_ssh_create(dict(name='new', host='example.invalid', password='synthetic-secret'))
        self.assertEqual(getattr(error.exception, 'code', None), 'CONNECTION_CREATE_FAILED')
        self.assertNotIn('synthetic-secret', str(error.exception))

    def test_password_create_retains_safe_actionable_error_codes(self):
        for code in ('VAULT_UNAVAILABLE', 'NEEDS_CREDENTIAL', 'CONNECTION_VERIFICATION_FAILED'):
            with self.subTest(code=code), \
                 patch.object(bindkit_password, 'create', side_effect=ConnectionError('synthetic-secret', code)):
                with self.assertRaises(Exception) as error:
                    self.ssh.console_ssh_create(dict(name='new', host='example.invalid', password='synthetic-secret'))
            self.assertEqual(getattr(error.exception, 'code', None), code)
            self.assertNotIn('synthetic-secret', str(error.exception))

    def test_invalid_private_key_field_cannot_turn_password_form_into_bootstrap(self):
        for private_key in ('   ', {'unexpected': 'object'}, 123):
            with self.subTest(private_key_type=type(private_key).__name__), \
                 patch.object(self.ssh, '_run_self', return_value=(0, '', '')) as child:
                with self.assertRaises(Exception):
                    self.ssh.console_ssh_create(dict(name='new', host='example.invalid',
                        password='synthetic-secret', private_key=private_key))
                child.assert_not_called()

    def test_password_managed_execution_resolves_uid_and_keeps_broker_alive(self):
        vault = MemoryVault(); vault.set('synthetic-ref', 'synthetic-login-password')
        policy = self.ssh._console_policy_module()
        policy.write_policy('ssh', {'version': 1, 'servers': {'password-demo': {'allowed_users': ['app']}}})
        def execute(module, server, plan, supplied_vault, **kwargs):
            argv, environment = kwargs['transport']
            self.assertEqual(plan['target_uid'], 1001)
            self.assertIn('PubkeyAuthentication=no', argv)
            self.assertIn('BatchMode=no', argv)
            self.assertTrue(Path(environment['SSH_ASKPASS']).exists())
            self.assertEqual(supplied_vault, vault)
            self.assertNotIn('synthetic-login-password', repr(argv) + repr(environment))
            self.helper_path = Path(environment['SSH_ASKPASS'])
            return dict(exit_code=0, stdout='managed\n', stderr='', started=True, authenticated=True, error=None)
        output = io.StringIO()
        with patch.object(bindkit_vault, 'Vault', return_value=vault), \
             patch.object(bindkit_password, 'run', return_value=(0, '1001\n', '')) as query, \
             patch.object(privilege, 'execute_plan', side_effect=execute), \
             patch.object(self.ssh, 'ssh_with_key', side_effect=AssertionError('key fallback')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(self.ssh.main(['exec', '--json', '--as-user', 'app', 'password-demo', 'id']), 0)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(query.call_args.args[2], 'id -u -- app')
        self.assertTrue(json.loads(output.getvalue())['started'])
        self.assertFalse(self.helper_path.exists())

    def execute_managed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.ssh.main(['exec', '--json', '--as-user', 'root', 'password-demo', 'id'])
        return code, json.loads(output.getvalue())

    def test_managed_password_prestart_vault_failure_releases_approval(self):
        policy = self.ssh._console_policy_module()
        policy.write_policy('ssh', {'version': 1, 'defaults': {'sudo': 'ask'}})
        vault = MemoryVault(); vault.set('synthetic-ref', 'synthetic-login-password')
        with patch.object(bindkit_password, 'run', return_value=(0, '0\n', '')), \
             patch.object(bindkit_vault, 'Vault', return_value=vault), \
             patch.object(privilege, 'execute_plan') as execution:
            code, first = self.execute_managed()
            self.assertEqual(code, 6)
            request = first['error']['request_id']; policy.approve('ssh', request)
            for expected, failure in (
                    ('VAULT_UNAVAILABLE', patch.object(vault, 'get', side_effect=RuntimeError('synthetic-secret'))),
                    ('NEEDS_CREDENTIAL', patch.object(vault, 'get', return_value=None)),
                    ('PASSWORD_TRANSPORT_FAILED', patch.object(bindkit_askpass, 'MemoryAskpass', side_effect=OSError('synthetic-secret')))):
                with self.subTest(code=expected), failure:
                    code, failed = self.execute_managed()
                self.assertEqual(code, 255)
                self.assertIs(failed['started'], False)
                self.assertEqual(failed['error']['code'], expected)
                self.assertNotIn('synthetic-secret', json.dumps(failed))
                self.assertEqual(policy.get_approval('ssh', request)['consumes_left'], 1)
        execution.assert_not_called()

    def test_managed_password_after_dispatch_exception_consumes_approval(self):
        policy = self.ssh._console_policy_module()
        policy.write_policy('ssh', {'version': 1, 'defaults': {'sudo': 'ask'}})
        vault = MemoryVault(); vault.set('synthetic-ref', 'synthetic-login-password')
        with patch.object(bindkit_password, 'run', return_value=(0, '0\n', '')), \
             patch.object(bindkit_vault, 'Vault', return_value=vault), \
             patch.object(privilege, 'execute_plan', side_effect=RuntimeError('synthetic transport loss')) as execution:
            _, first = self.execute_managed()
            request = first['error']['request_id']; policy.approve('ssh', request)
            code, failed = self.execute_managed()
        self.assertEqual(code, 255)
        self.assertIsNone(failed['started'])
        self.assertEqual(failed['error']['code'], 'EXECUTION_STATE_UNKNOWN')
        self.assertEqual(execution.call_count, 1)
        self.assertEqual(policy.get_approval('ssh', request)['status'], 'consumed')


@unittest.skipUnless(paramiko and shutil.which('ssh'), 'optional paramiko and OpenSSH required')
class RealPasswordConnectionTests(IsolatedHome):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.RSAKey.generate(2048)

    def test_web_password_create_then_cli_test_exec_and_user_discovery_without_keys(self):
        password = dict(PASSWORDS)['mixed']
        vault = MemoryVault()
        logger = logging.getLogger('paramiko.transport')
        old_level = logger.level; logger.setLevel(logging.CRITICAL)
        self.addCleanup(logger.setLevel, old_level)
        binary = shutil.which('ssh')
        bin_dir = self.home / 'bin'; bin_dir.mkdir()
        wrapper = bin_dir / 'ssh'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([binary, '-F', '/dev/null',
            '-o', 'UserKnownHostsFile=' + str(self.home / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentityAgent=none', '-o', 'LogLevel=ERROR']) + ' "$@"\n')
        wrapper.chmod(0o700)
        responses = [(b'SSHBIND_OK\n', 0), (b'SSHBIND_OK\n', 0),
                     (b'synthetic-output\n', 7), (b'app:x:1001:1001::/home/app:/bin/sh\n', 0)]
        with patch.dict(os.environ, {'PATH': str(bin_dir) + os.pathsep + os.environ.get('PATH', '')}), \
             patch.object(bindkit_vault, 'Vault', return_value=vault), \
             patch.object(self.ssh, 'gen_keypair', side_effect=AssertionError('unexpected key generation')), \
             patch.object(self.ssh, 'install_pubkey', side_effect=AssertionError('unexpected key installation')), \
             patch.object(self.ssh, 'ssh_with_key', side_effect=AssertionError('unexpected key login')), \
             LocalPasswordConnectionServer(self.host_key, password, responses) as server:
            result = self.ssh.console_ssh_create({'name': 'password-demo', 'host': '127.0.0.1',
                'user': 'synthetic', 'port': server.port, 'password': password})
            self.assertTrue(result['ok'])
            self.assertTrue(self.ssh.console_ssh_get('password-demo')['usable'])
            row = self.ssh.load_state()['servers']['password-demo']
            self.assertEqual(row['auth_type'], 'password'); self.assertEqual(row['key'], '')
            self.assertNotIn(password, Path(self.ssh.STATE_FILE).read_text())
            self.assertFalse(Path(self.ssh.SSH_CONFIG).exists() and 'Host password-demo' in Path(self.ssh.SSH_CONFIG).read_text())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(self.ssh.main(['test', 'password-demo']), 0)
            output = io.StringIO()
            payload = b'\x00\xffliteral command stdin\n'
            with patch.object(self.ssh.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(payload))), \
                 contextlib.redirect_stdout(output):
                code = self.ssh.main(['exec', '--json', '--stdin', 'password-demo', 'cat'])
            self.assertEqual(code, 7)
            envelope = json.loads(output.getvalue())
            self.assertEqual(envelope['exit_code'], 7)
            self.assertEqual(envelope['stdout'], 'synthetic-output\n')
            self.assertNotIn(password, output.getvalue())
            self.assertEqual(self.ssh.console_ssh_users('password-demo')['users'][0]['uid'], 1001)
        self.assertEqual(server.authentication, [True] * 4)
        self.assertEqual(server.key_authentication, [])
        self.assertEqual(server.payloads, [b'', b'', payload, b''])
        self.assertEqual(server.commands[-2:], [b'cat', b'getent passwd'])
        self.assertTrue(all(b'SSHBIND_OK' in command for command in server.commands[:2]))
        self.assertFalse(server.errors)


if __name__ == '__main__': unittest.main()
