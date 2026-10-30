"""Synthetic password transport checks; never use developer SSH state or keychain."""
import contextlib
import importlib.machinery
import importlib.util
import io
import logging
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindconsole'))
import bindkit_connections as connections
import bindkit_pending as pending

try:
    import paramiko
except ImportError:
    paramiko = None


# All values are deliberately synthetic. Subtest labels never expose passwords.
PASSWORDS = (
    ('percent', 'synthetic%credential'),
    ('percent_tokens', 'synthetic%h%p%r%%credential'),
    ('dollar_variable', 'synthetic$PASSWORD_TRANSPORT_VAR'),
    ('dollar_braces', 'synthetic${PASSWORD_TRANSPORT_VAR}'),
    ('dollar_pid', 'synthetic$$credential'),
    ('quotes', 'synthetic\'"credential'),
    ('backslash', 'synthetic\\credential\\'),
    ('unicode', 'synthetic口令🔐'),
    ('spaces', '  synthetic credential  '),
    ('mixed', '  synthetic%$PASSWORD_TRANSPORT_VAR${PASSWORD_TRANSPORT_VAR}$$\'"\\口令  '),
)


def load_ssh():
    loader = importlib.machinery.SourceFileLoader('password_transport_ssh', str(ROOT / 'sshbind/sshbind'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class IsolatedHome(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bindkit-password-test-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        environment = patch.dict(os.environ, {
            'HOME': str(self.home), 'BINDCONSOLE_HOME': str(self.home / '.bindconsole'),
            'PASSWORD_TRANSPORT_VAR': 'must-not-expand',
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.ssh = load_ssh()


class IsolatedPasswordTests(IsolatedHome):
    def test_explicit_password_auth_disables_inherited_batchmode(self):
        auth = self.ssh.make_auth('password', password=dict(PASSWORDS)['mixed'])
        options, handle = self.ssh.auth_ssh_opts(auth)
        with handle:
            self.assertIn('BatchMode=no', options)

    def test_explicit_password_auth_enables_config_disabled_methods(self):
        auth = self.ssh.make_auth('password', password=dict(PASSWORDS)['mixed'])
        options, handle = self.ssh.auth_ssh_opts(auth)
        with handle:
            for option in ('PasswordAuthentication=yes', 'KbdInteractiveAuthentication=yes'):
                with self.subTest(option=option):
                    self.assertIn(option, options)

    def test_explicit_private_key_passphrase_disables_inherited_batchmode(self):
        auth = self.ssh.make_auth('key', identities=[str(self.home / 'synthetic-key')],
            passphrase=dict(PASSWORDS)['mixed'])
        options, handle = self.ssh.auth_ssh_opts(auth)
        with handle:
            self.assertIn('BatchMode=no', options)

    def test_normal_key_execution_retains_batchmode(self):
        command = self.ssh.ssh_with_key('127.0.0.1', 'synthetic', 22, str(self.home / 'synthetic-key'))
        self.assertIn('BatchMode=yes', command)
        self.assertNotIn('BatchMode=no', command)

    def test_cli_stdin_and_interactive_input_preserve_literal_characters(self):
        for label, password in PASSWORDS:
            with self.subTest(vector=label, input='stdin'):
                with patch.object(sys, 'stdin', io.StringIO(password + '\n')):
                    auth = self.ssh.resolve_auth(types.SimpleNamespace(password_stdin=True))
                self.assertTrue(auth['password'] == password, 'stdin changed a synthetic credential')
            with self.subTest(vector=label, input='getpass'):
                with patch.object(sys.stdin, 'isatty', return_value=True), \
                     patch.object(self.ssh.getpass, 'getpass', return_value=password):
                    auth = self.ssh.resolve_auth(types.SimpleNamespace())
                self.assertTrue(auth['password'] == password, 'getpass changed a synthetic credential')

    def test_console_create_uses_child_stdin_without_password_argv(self):
        # The real subprocess helper is exercised. This child reads stdin only,
        # compares in memory, and returns no credential content.
        child = self.home / 'stdin_probe.py'
        child.write_text(
            'import os, sys\n'
            'value = sys.stdin.buffer.read().decode("utf-8")\n'
            'expected = os.environ["PASSWORD_TRANSPORT_EXPECTED"] + "\\n"\n'
            'raise SystemExit(0 if value == expected and "--password-stdin" in sys.argv else 1)\n',
            encoding='utf-8')
        for label, password in PASSWORDS:
            with self.subTest(vector=label), \
                 patch.dict(os.environ, {'PASSWORD_TRANSPORT_EXPECTED': password}), \
                 patch.object(self.ssh, '_self_script', return_value=str(child)), \
                 patch.object(self.ssh.subprocess, 'run', wraps=subprocess.run) as run:
                result = self.ssh._console_ssh_create({
                    'name': 'synthetic', 'host': '127.0.0.1', 'user': 'synthetic',
                    'auth': {'password': password},
                })
                self.assertTrue(result['ok'])
                self.assertTrue(all(password not in str(arg) for arg in run.call_args.args[0]),
                                'credential was put in argv')
                self.assertTrue(run.call_args.kwargs['input'] == (password + '\n').encode('utf-8'))
                self.assertNotIn('shell', run.call_args.kwargs)


if paramiko:
    class PasswordOnlySession(paramiko.ServerInterface):
        def __init__(self, owner):
            self.owner = owner
            self.executed = threading.Event()

        def get_allowed_auths(self, username):
            return 'keyboard-interactive' if self.owner.interactive else 'password'

        def check_auth_password(self, username, password):
            correct = username == 'synthetic' and password == self.owner.password
            self.owner.authentication.append(correct)
            return paramiko.AUTH_SUCCESSFUL if correct else paramiko.AUTH_FAILED

        def check_auth_interactive(self, username, submethods):
            prompts = [('Password: ', False)]
            if self.owner.multifactor:
                prompts.append(('Verification code: ', False))
            return paramiko.InteractiveQuery('Synthetic authentication', '', *prompts)

        def check_auth_interactive_response(self, responses):
            self.owner.interactive_response_matches.append(tuple(value == self.owner.password for value in responses))
            expected = [self.owner.password]
            if self.owner.multifactor:
                expected.append('synthetic-distinct-one-time-code')
            correct = responses == expected
            self.owner.authentication.append(correct)
            return paramiko.AUTH_SUCCESSFUL if correct else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            self.owner.commands.append(command)
            self.executed.set()
            return True

    class BootstrapSession(PasswordOnlySession):
        def __init__(self, owner, phase):
            super().__init__(owner)
            self.phase = phase

        def get_allowed_auths(self, username):
            return 'password' if self.phase == 0 else 'publickey'

        def check_auth_password(self, username, password):
            correct = self.phase == 0 and username == 'synthetic' and password == self.owner.password
            self.owner.authentication.append(correct)
            return paramiko.AUTH_SUCCESSFUL if correct else paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            correct = (self.phase == 1 and username == 'synthetic' and
                (key.get_name(), key.get_base64()) in self.owner.authorized_keys)
            self.owner.key_authentication.append(correct)
            return paramiko.AUTH_SUCCESSFUL if correct else paramiko.AUTH_FAILED


class LocalPasswordServer:
    """One localhost SSH session, with an in-memory host key and password check."""
    def __init__(self, host_key, password, output=b'AUTH_OK\n', status=0, interactive=False, multifactor=False):
        self.host_key = host_key
        self.password = password
        self.output = output
        self.status = status
        self.interactive = interactive
        self.multifactor = multifactor
        self.authentication = []
        self.interactive_response_matches = []
        self.commands = []
        self.stdin = b''
        self.errors = []
        self.transport = None
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def serve(self):
        try:
            client, _ = self.listener.accept()
            with client:
                self.transport = paramiko.Transport(client)
                self.transport.add_server_key(self.host_key)
                session = PasswordOnlySession(self)
                self.transport.start_server(server=session)
                channel = self.transport.accept(10)
                if channel is None:
                    return
                with channel:
                    channel.settimeout(10)
                    if not session.executed.wait(10):
                        return
                    while True:
                        chunk = channel.recv(4096)
                        if not chunk:
                            break
                        self.stdin += chunk
                    channel.sendall(self.output)
                    channel.send_exit_status(self.status)
                    channel.shutdown_write()
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            if self.transport:
                self.transport.close()

    def __exit__(self, *exc):
        if self.transport:
            self.transport.close()
        self.listener.close()
        self.thread.join(12)
        if self.thread.is_alive():
            raise RuntimeError('Synthetic SSH server did not terminate')


class LocalBootstrapServer(LocalPasswordServer):
    """Two real SSH logins; authorize the received key in RAM only.

    Command payloads are captured, never executed as remote shell scripts.
    """
    def __init__(self, host_key, password):
        super().__init__(host_key, password)
        self.authorized_keys = set()
        self.key_authentication = []
        self.payloads = []

    def serve(self):
        try:
            for phase in range(2):
                client, _ = self.listener.accept()
                with client:
                    self.transport = paramiko.Transport(client)
                    self.transport.add_server_key(self.host_key)
                    session = BootstrapSession(self, phase)
                    self.transport.start_server(server=session)
                    channel = self.transport.accept(10)
                    if channel is None:
                        return
                    with channel:
                        channel.settimeout(10)
                        if not session.executed.wait(10):
                            return
                        payload = b''
                        while True:
                            chunk = channel.recv(4096)
                            if not chunk:
                                break
                            payload += chunk
                        self.payloads.append(payload)
                        if phase == 0:
                            parts = payload.decode('utf-8').split()
                            if len(parts) < 2 or parts[0] != 'ssh-ed25519':
                                channel.sendall(b'SSHBIND_EMPTY_KEY\n')
                                channel.send_exit_status(1)
                                return
                            self.authorized_keys.add((parts[0], parts[1]))
                            output = b'SSHBIND_ADDED\n'
                        else:
                            output = b'SSHBIND_OK\nsynthetic-host\nsynthetic\n'
                        channel.sendall(output)
                        channel.send_exit_status(0)
                        channel.shutdown_write()
                self.transport.close()
                self.transport = None
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            if self.transport:
                self.transport.close()


class MemoryVault:
    """Synthetic keychain; never calls a platform credential backend."""
    def __init__(self):
        self.values = {}

    def status(self):
        return {'available': True}

    def new_ref(self, prefix='credential'):
        return prefix + '-' + str(len(self.values))

    def set(self, ref, value):
        self.values[ref] = value

    def get(self, ref):
        return self.values.get(ref)

    def delete(self, ref):
        self.values.pop(ref, None)


@unittest.skipUnless(paramiko and shutil.which('ssh'), 'optional paramiko and OpenSSH required')
class OpenSSHPasswordTests(IsolatedHome):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.RSAKey.generate(2048)

    def setUp(self):
        super().setUp()
        # Suppress authentication-disconnect noise, without logging secret data.
        logger = logging.getLogger('paramiko.transport')
        old_level = logger.level
        logger.setLevel(logging.CRITICAL)
        self.addCleanup(logger.setLevel, old_level)
        self.ssh_binary = shutil.which('ssh')
        self.isolation_options = ['-F', '/dev/null',
            '-o', 'UserKnownHostsFile=' + str(self.home / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no',
            '-o', 'IdentityAgent=none', '-o', 'LogLevel=ERROR']

    def command(self, server, extra_options=()):
        return [self.ssh_binary, *self.isolation_options, *extra_options,
                '-p', str(server.port)]

    def authenticate(self, server, password, stdin=None, extra_options=()):
        auth = self.ssh.make_auth('password', password=password)
        options, handle = self.ssh.auth_ssh_opts(auth)
        command = self.command(server, extra_options) + options + ['synthetic@127.0.0.1', 'synthetic-command']
        self.assertTrue(all(password not in arg for arg in command), 'credential was put in argv')
        with handle:
            result = self.ssh.run_ssh(command, secret_handle=handle, stdin_data=stdin, timeout=15)
        self.assertFalse(Path(handle.dir).exists())
        return result

    def assert_authenticated(self, server, result):
        self.assertEqual(result[0], 0, 'isolated OpenSSH authentication failed: ' + result[2])
        self.assertEqual(server.authentication, [True], 'server did not receive the expected literal credential')
        self.assertFalse(server.errors, 'synthetic SSH server failed')

    def test_real_askpass_preserves_special_password_and_remote_stdin(self):
        payload = 'ssh-ed25519 synthetic-public-key % $VAR \\ " 口令\n'
        for label, password in PASSWORDS:
            with self.subTest(vector=label):
                with LocalPasswordServer(self.host_key, password) as server:
                    result = self.authenticate(server, password, stdin=payload)
                    self.assert_authenticated(server, result)
                    self.assertEqual(server.stdin, payload.encode('utf-8'))
                    self.assertEqual(result[1], 'AUTH_OK\n')

    def test_forced_askpass_works_with_display_missing_or_empty(self):
        password = dict(PASSWORDS)['mixed']
        for display in (None, ''):
            with self.subTest(display='missing' if display is None else 'empty'):
                environment = dict(os.environ)
                if display is None:
                    environment.pop('DISPLAY', None)
                else:
                    environment['DISPLAY'] = display
                with patch.dict(os.environ, environment, clear=True), \
                     LocalPasswordServer(self.host_key, password) as server:
                    self.assert_authenticated(server, self.authenticate(server, password))
                    self.assertEqual(server.stdin, b'')

    def test_real_keyboard_interactive_password_prompt_preserves_special_password(self):
        password = dict(PASSWORDS)['mixed']
        with LocalPasswordServer(self.host_key, password, interactive=True) as server:
            self.assert_authenticated(server, self.authenticate(server, password))

    def test_distinct_interactive_challenges_cannot_use_single_password_helper(self):
        password = dict(PASSWORDS)['mixed']
        with LocalPasswordServer(self.host_key, password, interactive=True, multifactor=True) as server:
            result = self.authenticate(server, password)
            self.assertNotEqual(result[0], 0)
            self.assertEqual(server.authentication, [False])
            # The current helper returns its single stored value for each
            # prompt; this establishes the multifactor limitation explicitly.
            self.assertEqual(server.interactive_response_matches, [(True, True)])

    def test_install_public_key_keeps_password_separate_from_key_payload(self):
        password = dict(PASSWORDS)['mixed']
        public_key = 'ssh-ed25519 synthetic-public-key synthetic-comment'
        with LocalPasswordServer(self.host_key, password, output=b'SSHBIND_ADDED\n') as server, \
             patch.object(self.ssh, 'ssh_base', side_effect=lambda *args: self.command(server)):
            valid, _ = self.ssh.install_pubkey('127.0.0.1', 'synthetic', server.port,
                self.ssh.make_auth('password', password=password), public_key)
            self.assertTrue(valid)
            self.assertEqual(server.authentication, [True])
            self.assertEqual(server.stdin, public_key.encode('utf-8'))
            self.assertEqual(server.commands, [self.ssh.REMOTE_INSTALL.encode('utf-8')])

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'OpenSSH ssh-keygen required')
    def test_console_bootstrap_really_verifies_the_password_installed_public_key(self):
        password = dict(PASSWORDS)['mixed']
        bin_dir = self.home / 'bin'
        bin_dir.mkdir()
        wrapper = bin_dir / 'ssh'
        for inherited_batchmode in (False, True):
            with self.subTest(inherited_batchmode=inherited_batchmode):
                options = list(self.isolation_options)
                if inherited_batchmode:
                    config = self.home / 'bootstrap_client_config'
                    config.write_text('Host *\n  BatchMode yes\n', encoding='utf-8')
                    options[1] = str(config)
                wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([self.ssh_binary, *options]) + ' "$@"\n', encoding='utf-8')
                wrapper.chmod(0o700)
                name = 'bootstrap-inherited' if inherited_batchmode else 'bootstrap-default'
                # The source CLI is launched by the real _run_self. No CLI,
                # key generation, authentication or verification helper is stubbed.
                with patch.dict(os.environ, {'PATH': str(bin_dir) + os.pathsep + os.environ.get('PATH', '')}), \
                     LocalBootstrapServer(self.host_key, password) as server:
                    result = self.ssh.console_ssh_create({'name': name, 'host': '127.0.0.1',
                        'user': 'synthetic', 'port': server.port, 'password': password})
                self.assertTrue(result['ok'])
                self.assertEqual(server.authentication, [True])
                self.assertTrue(server.key_authentication, 'No public-key authentication was attempted')
                self.assertTrue(all(server.key_authentication), 'The verification key did not match the installed key')
                self.assertEqual(len(server.authorized_keys), 1)
                self.assertEqual(server.commands, [self.ssh.REMOTE_INSTALL.encode('utf-8'),
                    b'echo SSHBIND_OK && hostname && whoami'])
                self.assertEqual(len(server.payloads), 2)
                self.assertTrue(server.payloads[0].startswith(b'ssh-ed25519 '))
                self.assertEqual(server.payloads[1], b'')
                self.assertFalse(server.errors)
                row = self.ssh.load_state()['servers'][name]
                self.assertTrue(row['installed'])
                self.assertTrue(Path(row['key']).is_file())
                self.assertTrue(self.ssh.console_ssh_get(name)['usable'])

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'OpenSSH ssh-keygen required')
    def test_console_create_child_cli_reaches_real_password_authentication(self):
        password = dict(PASSWORDS)['mixed']
        # Real child CLI, key generation, askpass and SSH password exchange.
        # Only subsequent public-key verification is stubbed: this server
        # intentionally accepts password authentication only.
        helper = self.home / 'sshbind_test_child.py'
        helper.write_text(
            'import importlib.machinery, importlib.util, sys\n'
            'loader = importlib.machinery.SourceFileLoader("synthetic_ssh", ' + repr(str(ROOT / 'sshbind/sshbind')) + ')\n'
            'spec = importlib.util.spec_from_loader(loader.name, loader)\n'
            'module = importlib.util.module_from_spec(spec)\n'
            'loader.exec_module(module)\n'
            'module.test_connection = lambda *a, **kw: (True, ["synthetic-verification-stub"])\n'
            'raise SystemExit(module.main())\n', encoding='utf-8')
        bin_dir = self.home / 'bin'
        bin_dir.mkdir()
        wrapper = bin_dir / 'ssh'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([self.ssh_binary, *self.isolation_options]) + ' "$@"\n', encoding='utf-8')
        wrapper.chmod(0o700)
        with patch.dict(os.environ, {'PATH': str(bin_dir) + os.pathsep + os.environ.get('PATH', '')}), \
             patch.object(self.ssh, '_self_script', return_value=str(helper)), \
             LocalPasswordServer(self.host_key, password, output=b'SSHBIND_ADDED\n') as server:
            result = self.ssh._console_ssh_create({'name': 'synthetic', 'host': '127.0.0.1',
                'user': 'synthetic', 'port': server.port, 'password': password})
            self.assertTrue(result['ok'])
            self.assertEqual(server.authentication, [True])
            self.assertTrue(server.stdin.startswith(b'ssh-ed25519 '))
            self.assertNotIn(password.encode('utf-8'), server.stdin)
            self.assertTrue(self.ssh.load_state()['servers']['synthetic']['installed'])

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'OpenSSH ssh-keygen required')
    def test_edit_login_password_reaches_real_password_authentication(self):
        password = dict(PASSWORDS)['mixed']
        self.ssh.ensure_dirs()
        old_key = Path(self.ssh.KEYS_DIR) / 'old'
        old_key.write_text('synthetic-old-key')
        with LocalPasswordServer(self.host_key, password, output=b'SSHBIND_ADDED\n') as server, \
             patch.object(self.ssh, 'ssh_base', side_effect=lambda *args: self.command(server)), \
             patch.object(self.ssh, 'test_connection', return_value=(True, ['synthetic-verification-stub'])), \
             contextlib.redirect_stdout(io.StringIO()):
            row = self.ssh._record('synthetic', '127.0.0.1', 'synthetic', server.port,
                str(old_key), 'synthetic-fingerprint', 'ed25519', False, None, 'generated', True)
            self.ssh.save_state({'servers': {'synthetic': row}})
            result = connections.update_connection(self.ssh, 'synthetic', {'login_password': password}, MemoryVault())
            self.assertTrue(result['ok'])
            self.assertEqual(server.authentication, [True])
            self.assertTrue(server.stdin.startswith(b'ssh-ed25519 '))
            self.assertTrue(old_key.exists())

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'OpenSSH ssh-keygen required')
    def test_saved_pending_password_reaches_real_password_authentication(self):
        password = dict(PASSWORDS)['mixed']
        vault = MemoryVault()
        with LocalPasswordServer(self.host_key, password, output=b'SSHBIND_ADDED\n') as server, \
             patch.object(self.ssh, 'ssh_base', side_effect=lambda *args: self.command(server)), \
             patch.object(self.ssh, 'test_connection', return_value=(True, ['synthetic-verification-stub'])), \
             contextlib.redirect_stdout(io.StringIO()):
            pending.create_unverified(self.ssh, {'name': 'synthetic', 'host': '127.0.0.1',
                'user': 'synthetic', 'port': server.port, 'password': password}, vault)
            self.assertEqual(server.authentication, [])
            result = pending.verify_pending(self.ssh, 'synthetic', vault)
            self.assertTrue(result['ok'])
            self.assertTrue(result['usable'])
            self.assertEqual(server.authentication, [True])
            self.assertTrue(server.stdin.startswith(b'ssh-ed25519 '))

    def test_authenticated_no_home_is_not_password_failure(self):
        password = dict(PASSWORDS)['mixed']
        with LocalPasswordServer(self.host_key, password, output=b'SSHBIND_NO_HOME\n', status=1) as server, \
             patch.object(self.ssh, 'ssh_base', side_effect=lambda *args: self.command(server)):
            valid, message = self.ssh.install_pubkey('127.0.0.1', 'synthetic', server.port,
                self.ssh.make_auth('password', password=password), 'ssh-ed25519 synthetic')
            self.assertFalse(valid)
            self.assertEqual(server.authentication, [True])
            self.assertIn('家目录', message)

    def test_explicit_password_overrides_inherited_config_batchmode(self):
        # Supplying a credential must allow its use despite unrelated client
        # automation settings. Never access the developer's ~/.ssh/config.
        config = self.home / 'batchmode_config'
        config.write_text('Host *\n  BatchMode yes\n', encoding='utf-8')
        self.isolation_options[1] = str(config)
        for label, password in [('ordinary', 'synthetic-ordinary-password'), ('special', dict(PASSWORDS)['mixed'])]:
            with self.subTest(vector=label):
                with LocalPasswordServer(self.host_key, password) as server:
                    result = self.authenticate(server, password)
                    self.assert_authenticated(server, result)

    def test_explicit_password_overrides_config_disabled_password_methods(self):
        config = self.home / 'disabled_password_methods_config'
        config.write_text('Host *\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n', encoding='utf-8')
        self.isolation_options[1] = str(config)
        password = dict(PASSWORDS)['mixed']
        for interactive in (False, True):
            with self.subTest(method='keyboard-interactive' if interactive else 'password'):
                with LocalPasswordServer(self.host_key, password, interactive=interactive) as server:
                    result = self.authenticate(server, password)
                    self.assert_authenticated(server, result)

    def test_explicit_leading_cli_batchmode_retains_openssh_first_value_precedence(self):
        # OpenSSH gives the first command-line option value precedence. This
        # control is distinct from a BatchMode value inherited from a config.
        password = dict(PASSWORDS)['mixed']
        with LocalPasswordServer(self.host_key, password) as server:
            result = self.authenticate(server, password, extra_options=['-o', 'BatchMode=yes'])
            self.assertNotEqual(result[0], 0)
            self.assertEqual(server.authentication, [])
            self.assertIn('Permission denied', result[2])


if __name__ == '__main__':
    unittest.main()
