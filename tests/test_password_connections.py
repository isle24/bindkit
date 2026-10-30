"""Password lifecycle contracts; all state and credentials are synthetic."""
import copy
import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bindconsole'))
from test_pending_connections import SSH as BaseSSH, Vault
import bindkit_connections as connections
import bindkit_pending as pending
try:
    import bindkit_password as password
except ImportError:
    password = None

SECRET = 'test % $ ` " \\ ! 中文'


class Handle:
    def __init__(self, secret): self.secret = secret; self.closed = False
    def env(self): return {'SYNTHETIC_ASKPASS': 'memory'}
    def close(self): self.closed = True
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class SSH(BaseSSH):
    def __init__(self, base):
        super().__init__(base); self.calls = []; self.handles = []; self.result = None
    def ssh_base(self, host, user, port): return ['ssh', '-o', 'StrictHostKeyChecking=accept-new', '-p', str(port)]
    def auth_ssh_opts(self, auth):
        assert auth['mode'] == 'password'
        handle = Handle(auth['password']); self.handles.append(handle)
        return ['-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1'], handle
    def run_ssh(self, argv, secret_handle=None, stdin_data=None, timeout=120):
        self.calls.append((list(argv), secret_handle.env(), stdin_data, timeout))
        if self.result is not None: return self.result
        if not self.valid: return 255, '', 'sensitive-secret-diagnostic'
        return 0, 'SSHBIND_OK\n', ''


class PasswordConnectionsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(password, 'genuine password lifecycle module is required')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {'HOME': self.temp.name}); env.start(); self.addCleanup(env.stop)
        self.ssh = SSH(self.temp.name); self.vault = Vault()
    def create(self, **fields):
        return password.create(self.ssh, dict(name='demo', host='example.invalid', user='operator', password=SECRET, **fields), self.vault)
    def update(self, **fields):
        return connections.update_connection(self.ssh, 'demo', fields, self.vault)
    def assert_no_keys(self):
        self.assertFalse(self.ssh.generated); self.assertFalse(self.ssh.installs)
        self.assertFalse(list(Path(self.ssh.KEYS_DIR).glob('*')))
    def test_create_verifies_password_without_creating_or_installing_keys(self):
        result = self.create(); row = self.ssh.state['servers']['demo']
        self.assertTrue(result['ok']); self.assertTrue(result['usable'])
        self.assertEqual(row['auth_type'], 'password'); self.assertEqual(row['key'], '')
        self.assertTrue(row['installed']); self.assertEqual(row['verification_status'], 'verified')
        self.assertEqual(row['revision'], 1); self.assertTrue(row['id'])
        self.assertEqual(self.vault.values[row['login_credential_ref']], SECRET)
        self.assertEqual(self.ssh.handles[0].secret, SECRET); self.assertTrue(self.ssh.handles[0].closed)
        self.assertEqual(len(self.ssh.calls), 1); self.assertEqual(self.ssh.calls[0][0][-1], "printf 'SSHBIND_OK\\n'")
        self.assertNotIn(SECRET, json.dumps(self.ssh.calls)); self.assertNotIn('opaque-', json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(self.ssh.state)); self.assert_no_keys()
    def test_unavailable_vault_fails_before_connecting_or_registering(self):
        self.vault.available = False
        with self.assertRaises(connections.ConnectionError) as caught: self.create()
        self.assertEqual(caught.exception.code, 'VAULT_UNAVAILABLE')
        self.assertFalse(self.ssh.calls); self.assertFalse(self.ssh.state['servers']); self.assert_no_keys()
    def test_failed_authentication_leaves_no_partial_state_or_secret(self):
        self.ssh.valid = False
        with self.assertRaises(connections.ConnectionError) as caught: self.create()
        self.assertEqual(caught.exception.code, 'CONNECTION_VERIFICATION_FAILED')
        self.assertNotIn('sensitive-secret', str(caught.exception)); self.assertFalse(self.vault.values)
        self.assertFalse(self.ssh.state['servers']); self.assert_no_keys()
    def test_failed_secret_write_or_state_save_rolls_back(self):
        for fail_set, fail_save in ((True, False), (False, True)):
            self.vault.fail_set = fail_set; self.ssh.fail_save = fail_save
            with self.assertRaises(connections.ConnectionError): self.create()
            self.assertFalse(self.ssh.state['servers']); self.assertFalse(self.vault.values); self.assertFalse(self.ssh.config)
        self.assert_no_keys()
    def test_mode_inference_never_converts_existing_key_records(self):
        self.assertTrue(password.is_password({'auth_type': 'password'}))
        self.assertTrue(password.is_password({'key': '', 'login_credential_ref': 'opaque'}))
        self.assertTrue(password.is_password({'key': '', 'encrypted_login_ref': 'opaque'}))
        self.assertFalse(password.is_password({'key': '/old', 'login_credential_ref': 'opaque'}))
        self.assertFalse(password.is_password({'auth_type': 'key', 'login_credential_ref': 'opaque'}))
    def test_run_preserves_stdin_stdout_stderr_and_exit_status(self):
        self.create(); row = self.ssh.state['servers']['demo']; self.ssh.result = (37, 'output\n', 'error\n')
        result = password.run(self.ssh, row, 'cat; exit 37', stdin_data=b'input\x00', timeout=9, vault=self.vault)
        self.assertEqual(result, (37, 'output\n', 'error\n'))
        self.assertEqual(self.ssh.calls[-1][2:], (b'input\x00', 9)); self.assertEqual(self.ssh.calls[-1][0][-2], 'operator@example.invalid')
        self.assertTrue(self.ssh.handles[-1].closed)
    def test_transport_closes_handle_after_failure(self):
        self.create(); row = self.ssh.state['servers']['demo']
        with self.assertRaises(RuntimeError):
            with password.transport(self.ssh, row, self.vault) as (argv, env):
                self.assertIn('PubkeyAuthentication=no', argv); self.assertEqual(env, {'SYNTHETIC_ASKPASS': 'memory'})
                raise RuntimeError('consumer failure')
        self.assertTrue(self.ssh.handles[-1].closed)
    def test_test_has_safe_error_and_does_not_mutate_state(self):
        self.create(); before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values); self.ssh.valid = False
        ok, details = password.test(self.ssh, before['servers']['demo'], self.vault)
        self.assertFalse(ok); self.assertNotIn('sensitive-secret', json.dumps(details))
        self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
    def test_active_edit_verifies_and_swaps_reference_then_retires_old_secret(self):
        self.create(); old = copy.deepcopy(self.ssh.state['servers']['demo'])
        result = self.update(host='new.invalid', login_password='new synthetic password')
        row = self.ssh.state['servers']['demo']; self.assertTrue(result['ok'])
        self.assertEqual(row['id'], old['id']); self.assertEqual(row['revision'], 2)
        self.assertEqual(row['host'], 'new.invalid'); self.assertEqual(row['auth_type'], 'password')
        self.assertEqual(self.vault.values[row['login_credential_ref']], 'new synthetic password')
        self.assertNotIn(old['login_credential_ref'], self.vault.values); self.assert_no_keys()
    def test_failed_active_edit_preserves_old_state_and_secret(self):
        self.create(); before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values); self.ssh.valid = False
        with self.assertRaises(connections.ConnectionError): self.update(host='new.invalid', login_password='new secret')
        self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved); self.assert_no_keys()
    def test_failed_edit_save_preserves_old_state_and_secret(self):
        self.create(); before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values); self.ssh.fail_save = True
        with self.assertRaises(connections.ConnectionError): self.update(login_password='new secret', sudo_password='separate secret')
        self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved); self.assert_no_keys()
    def test_metadata_only_pending_edit_stays_pending_without_network_or_vault(self):
        pending.create_unverified(self.ssh, {'name':'demo', 'host':'example.invalid'}, self.vault)
        self.vault.available = False
        result = self.update(host='new.invalid')
        row = self.ssh.state['servers']['demo']; self.assertTrue(result['ok']); self.assertFalse(row['installed'])
        self.assertEqual(row['verification_status'], 'pending'); self.assertFalse(self.ssh.calls); self.assert_no_keys()
    def test_pending_login_edit_verifies_password_without_bootstrapping(self):
        pending.create_unverified(self.ssh, {'name':'demo', 'host':'example.invalid'}, self.vault)
        self.update(login_password=SECRET)
        row = self.ssh.state['servers']['demo']; self.assertTrue(row['installed']); self.assertEqual(row['key'], '')
        self.assertEqual(row['verification_status'], 'verified'); self.assert_no_keys()
    def test_pending_native_verify_uses_saved_password_and_no_remote_mutation(self):
        pending.create_unverified(self.ssh, {'name':'demo', 'host':'example.invalid', 'password':SECRET}, self.vault)
        old = copy.deepcopy(self.ssh.state['servers']['demo'])
        self.assertEqual(old['auth_type'], 'password')
        result = pending.verify_pending(self.ssh, 'demo', self.vault)
        row = self.ssh.state['servers']['demo']; self.assertTrue(result['ok']); self.assertEqual(row['key'], '')
        self.assertEqual(row['id'], old['id']); self.assertEqual(row['revision'], 2); self.assert_no_keys()
    def test_private_key_edit_explicitly_changes_password_connection_to_key(self):
        self.create(); self.update(private_key='synthetic-private')
        row = self.ssh.state['servers']['demo']; self.assertEqual(row['auth_type'], 'key')
        self.assertTrue(Path(row['key']).exists()); self.assertFalse(self.ssh.installs)
    def test_sudo_only_edit_does_not_require_login_or_remote_access(self):
        self.create(); count = len(self.ssh.calls)
        self.update(sudo_password='synthetic sudo')
        row = self.ssh.state['servers']['demo']; self.assertEqual(len(self.ssh.calls), count)
        self.assertEqual(self.vault.values[row['sudo_credential_ref']], 'synthetic sudo')
        self.assertEqual(self.vault.values[row['login_credential_ref']], SECRET)
        self.update(clear_sudo_password=True)
        self.assertEqual(list(self.vault.values.values()), [SECRET]); self.assert_no_keys()

    def test_host_only_active_edit_reuses_saved_password_and_reference(self):
        self.create(); old = copy.deepcopy(self.ssh.state['servers']['demo'])
        self.update(host='new.invalid', port=2222)
        row = self.ssh.state['servers']['demo']
        self.assertEqual(row['login_credential_ref'], old['login_credential_ref'])
        self.assertEqual(self.ssh.handles[-1].secret, SECRET)
        self.assertEqual(self.ssh.calls[-1][0][-2], 'operator@new.invalid'); self.assert_no_keys()
    def test_pending_failed_password_edit_retains_pending_state(self):
        pending.create_unverified(self.ssh, {'name':'demo', 'host':'example.invalid'}, self.vault)
        before = copy.deepcopy(self.ssh.state); self.ssh.valid = False
        with self.assertRaises(connections.ConnectionError): self.update(login_password=SECRET)
        self.assertEqual(self.ssh.state, before); self.assertFalse(self.vault.values); self.assert_no_keys()
    def test_uncertain_create_save_keeps_any_live_credential_reference(self):
        def save(state):
            if state['servers']: self.ssh.state = copy.deepcopy(state)
            raise OSError('synthetic persistence failure')
        with patch.object(self.ssh, 'save_state', side_effect=save):
            with self.assertRaises(connections.ConnectionError) as caught: self.create()
        self.assertEqual(caught.exception.code, 'ROLLBACK_FAILED')
        row = self.ssh.state['servers']['demo']
        self.assertEqual(self.vault.values[row['login_credential_ref']], SECRET); self.assert_no_keys()
    def test_uncertain_update_keeps_new_live_credential_and_original_secret(self):
        self.create(); old = copy.deepcopy(self.ssh.state['servers']['demo'])
        def save(state):
            if state['servers']['demo'].get('revision') == 2: self.ssh.state = copy.deepcopy(state)
            raise OSError('synthetic persistence failure')
        with patch.object(self.ssh, 'save_state', side_effect=save):
            with self.assertRaises(connections.ConnectionError) as caught: self.update(login_password='replacement')
        self.assertEqual(caught.exception.code, 'ROLLBACK_FAILED')
        row = self.ssh.state['servers']['demo']
        self.assertEqual(self.vault.values[row['login_credential_ref']], 'replacement')
        self.assertEqual(self.vault.values[old['login_credential_ref']], SECRET)
    def test_replacement_keeps_original_reference_when_another_connection_uses_it(self):
        self.create(); other = copy.deepcopy(self.ssh.state['servers']['demo']); other['name'] = 'other'
        self.ssh.state['servers']['other'] = other
        self.update(login_password='replacement')
        self.assertEqual(self.vault.values[other['login_credential_ref']], SECRET)
    def test_failed_sudo_clear_save_restores_independent_sudo_secret(self):
        self.create(); self.update(sudo_password='synthetic sudo')
        before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values); self.ssh.fail_save = True
        with self.assertRaises(connections.ConnectionError): self.update(clear_sudo_password=True)
        self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
    def test_missing_vault_entry_fails_before_starting_transport(self):
        self.create(); row = self.ssh.state['servers']['demo']; self.vault.values.clear(); count = len(self.ssh.calls)
        ok, details = password.test(self.ssh, row, self.vault)
        self.assertFalse(ok); self.assertEqual(len(self.ssh.calls), count)
    def test_control_characters_and_invalid_auth_mode_fail_before_network(self):
        for value in ('bad\npassword', 'bad\rpassword', 'bad\x00password'):
            with self.assertRaises(connections.ConnectionError):
                password.create(self.ssh, {'name':'demo', 'host':'example.invalid', 'password':value}, self.vault)
        with self.assertRaises(connections.ConnectionError): self.create(auth_type='unknown')
        self.assertFalse(self.ssh.calls); self.assertFalse(self.vault.values)
    def test_real_askpass_callback_preserves_special_password_and_command_stdin(self):
        from test_pending_connections import load, ROOT
        ssh = load('native_password_callback_ssh', ROOT / 'sshbind/sshbind')
        script = Path(self.temp.name) / 'fake_ssh.py'
        script.write_text("""import hashlib, os, subprocess, sys
assert 'PubkeyAuthentication=no' in sys.argv
assert 'PasswordAuthentication=yes' in sys.argv
assert 'NumberOfPasswordPrompts=1' in sys.argv
secret = subprocess.check_output([os.environ['SSH_ASKPASS'], 'Password:']).rstrip(b'\\n')
assert hashlib.sha256(secret).hexdigest() == %r
if sys.argv[-1] == "printf 'SSHBIND_OK\\\\n'":
    print('SSHBIND_OK')
else:
    sys.stdout.buffer.write(sys.stdin.buffer.read())
    sys.stderr.write('synthetic error\\n')
    sys.exit(23)
""" % hashlib.sha256(SECRET.encode()).hexdigest())
        with patch.object(ssh, 'ssh_base', return_value=[sys.executable, str(script)]), \
             patch.object(ssh, 'gen_keypair', side_effect=AssertionError('No key generation')), \
             patch.object(ssh, 'install_pubkey', side_effect=AssertionError('No key installation')):
            result = password.create(ssh, {'name':'demo', 'host':'example.invalid', 'user':'operator', 'password':SECRET}, self.vault)
            row = ssh.load_state()['servers']['demo']
            self.assertTrue(result['usable']); self.assertTrue(password.test(ssh, row, self.vault)[0])
            rc, out, err = password.run(ssh, row, 'echo', stdin_data='exact stdin % \n', vault=self.vault)
        self.assertEqual((rc, out, err), (23, 'exact stdin % \n', 'synthetic error\n'))
        self.assertEqual(row['key'], '')


    def test_policy_write_failure_after_persistence_rolls_back_policy_and_secret(self):
        original = {'servers': {'other': {'sudo': 'deny'}}}
        class Policy:
            data = copy.deepcopy(original)
            failed = False
            def read_policy(self, tool): return {'exists': True, 'data': copy.deepcopy(self.data)}
            def default_policy(self, tool): return {'servers': {}}
            def write_policy(self, tool, value):
                self.data = copy.deepcopy(value)
                if not self.failed:
                    self.failed = True
                    raise OSError('synthetic policy write failure')
        policy = Policy()
        self.ssh._console_policy_module = lambda: policy
        self.ssh._console_clean_ssh_policy = lambda value: value
        with self.assertRaises(connections.ConnectionError): self.create(sudo='deny')
        self.assertEqual(policy.data, original)
        self.assertFalse(self.ssh.state['servers']); self.assertFalse(self.vault.values)

    def test_probe_sanitizes_even_typed_backend_errors(self):
        self.create(); row = self.ssh.state['servers']['demo']
        with patch.object(self.ssh, 'run_ssh', side_effect=connections.ConnectionError(SECRET, 'BACKEND_FAILURE')):
            ok, details = password.test(self.ssh, row, self.vault)
        self.assertFalse(ok); self.assertNotIn(SECRET, '\n'.join(details))



    def test_native_password_edit_accepts_created_domain_and_email_users(self):
        for index, user in enumerate((r'CORP\operator', 'operator@example.invalid', 'a' * 128)):
            name = 'native-' + str(index)
            password.create(self.ssh, dict(name=name, host='example.invalid', user=user, password=SECRET), self.vault)
            result = password.update(self.ssh, name, {'host':'new.invalid', 'user':user}, self.vault)
            self.assertTrue(result['ok']); self.assertEqual(self.ssh.state['servers'][name]['user'], user)
            self.assertEqual(self.ssh.calls[-1][0][-2], user + '@new.invalid')
        self.assert_no_keys()
    def test_native_password_edit_rejects_invalid_user_before_connecting(self):
        self.create(); count = len(self.ssh.calls)
        for user in ('', '-operator', 'bad user', 'bad\nuser', 'bad\x00user', 'a' * 129):
            with self.assertRaises(connections.ConnectionError): self.update(user=user)
        self.assertEqual(len(self.ssh.calls), count); self.assert_no_keys()


# A live OpenSSH master must not turn a candidate password probe into a reused
# session. This fixture accepts concurrent loopback connections and keeps the
# first authenticated master alive while later clients authenticate separately.
import logging
import shutil
import socket
import subprocess
import threading
import time
import test_password_transport as transport_fixtures
from test_password_transport import IsolatedHome, paramiko
PasswordOnlySession = getattr(transport_fixtures, 'PasswordOnlySession', None)


class _MultiplexPasswordServer:
    def __init__(self, host_key, secret):
        self.host_key = host_key; self.password = secret
        self.interactive = False; self.multifactor = False
        self.authentication = []; self.key_authentication = []; self.commands = []
        self.errors = []; self.transports = []; self.workers = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(8); self.listener.settimeout(.1)
        self.thread = threading.Thread(target=self._accept, daemon=True)
    def __enter__(self):
        self.thread.start(); return self
    def _accept(self):
        while not self.stop.is_set():
            try: client, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            worker = threading.Thread(target=self._serve, args=(client,), daemon=True)
            self.workers.append(worker); worker.start()
    def _serve(self, client):
        transport = paramiko.Transport(client); self.transports.append(transport)
        try:
            transport.add_server_key(self.host_key)
            session = PasswordOnlySession(self)
            transport.start_server(server=session)
            while not self.stop.is_set() and transport.is_active():
                channel = transport.accept(.1)
                if channel is None: continue
                with channel:
                    channel.settimeout(5)
                    while channel.recv(4096): pass
                    channel.sendall(b'SSHBIND_OK\n')
                    channel.send_exit_status(0); channel.shutdown_write(); channel.close()
        except (EOFError, OSError):
            pass  # Failed auth and deliberate master termination close the socket.
        except Exception as exc:
            if not self.stop.is_set(): self.errors.append(type(exc).__name__)
        finally:
            transport.close(); client.close()
    def __exit__(self, *exc):
        self.stop.set(); self.listener.close(); self.thread.join(2)
        for transport in self.transports: transport.close()
        for worker in self.workers: worker.join(2)
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise RuntimeError('Synthetic multiplex server did not terminate')


@unittest.skipUnless(paramiko and shutil.which('ssh'), 'optional paramiko and OpenSSH required')
class PasswordMultiplexTests(IsolatedHome):
    @classmethod
    def setUpClass(cls): cls.host_key = paramiko.RSAKey.generate(2048)
    def setUp(self):
        super().setUp()
        self.vault = Vault()
        logger = logging.getLogger('paramiko.transport')
        old_level = logger.level; logger.setLevel(logging.CRITICAL)
        self.addCleanup(logger.setLevel, old_level)
    def _exercise(self, operation):
        with _MultiplexPasswordServer(self.host_key, SECRET) as server:
            # -F makes the entire test independent of the user's actual SSH config.
            config = self.home / 'mux.conf'
            socket_dir = tempfile.TemporaryDirectory(prefix='bkmux-', dir='/tmp')
            self.addCleanup(socket_dir.cleanup)
            control = Path(socket_dir.name) / 'mux.sock'
            config.write_text('Host *\n    ControlMaster auto\n    ControlPersist yes\n'
                              '    ControlPath ' + str(control) + '\n'
                              '    UserKnownHostsFile ' + str(self.home / 'known_hosts') + '\n'
                              '    GlobalKnownHostsFile /dev/null\n    IdentityAgent none\n    LogLevel ERROR\n')
            original_base = self.ssh.ssh_base
            def base(host, user, port):
                args = original_base(host, user, port)
                return args[:1] + ['-F', str(config)] + args[1:]
            body = dict(name='existing', host='127.0.0.1', user='synthetic', port=server.port, password=SECRET)
            with patch.object(self.ssh, 'ssh_base', side_effect=base), \
                 patch.object(self.ssh, 'gen_keypair', side_effect=AssertionError('No key generation')), \
                 patch.object(self.ssh, 'install_pubkey', side_effect=AssertionError('No key installation')):
                # Explicitly disable reuse for setup; the regression exercises the
                # product defaults only after the independent master is established.
                setup_base = lambda host, user, port: base(host, user, port) + ['-o', 'ControlPath=none']
                with patch.object(self.ssh, 'ssh_base', side_effect=setup_base):
                    password.create(self.ssh, body, self.vault)
                opts, handle = self.ssh.auth_ssh_opts(self.ssh.make_auth('password', password=SECRET))
                with handle:
                    master = subprocess.Popen(base(body['host'], body['user'], body['port']) + opts +
                        ['-M', '-N', '-o', 'ControlPersist=no', 'synthetic@127.0.0.1'],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        env=handle.env())
                    try:
                        deadline = time.monotonic() + 5
                        while not control.exists() and time.monotonic() < deadline and master.poll() is None:
                            time.sleep(.02)
                        self.assertIsNone(master.poll(), 'Synthetic OpenSSH master exited during setup')
                        self.assertTrue(control.exists(), 'Synthetic OpenSSH master did not create its private socket')
                        before = self.ssh.load_state(); saved = dict(self.vault.values)
                        attempts = len(server.authentication)
                        self.assertEqual(server.authentication, [True, True])
                        with self.assertRaises(connections.ConnectionError) as caught:
                            if operation == 'create':
                                password.create(self.ssh, dict(body, name='wrong', password='wrong synthetic password'), self.vault)
                            else:
                                password.update(self.ssh, 'existing', {'login_password': 'wrong synthetic password'}, self.vault)
                        self.assertEqual(caught.exception.code, 'CONNECTION_VERIFICATION_FAILED')
                        self.assertEqual(self.ssh.load_state(), before); self.assertEqual(self.vault.values, saved)
                        self.assertGreater(len(server.authentication), attempts)
                        self.assertFalse(server.authentication[-1]); self.assertFalse(server.key_authentication)
                    finally:
                        master.terminate()
                        try: master.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            master.kill(); master.wait(timeout=5)
            self.assertFalse(server.errors)
    def test_existing_master_cannot_verify_wrong_password_create(self): self._exercise('create')
    def test_existing_master_cannot_verify_wrong_password_update(self): self._exercise('update')


if __name__ == '__main__': unittest.main()
