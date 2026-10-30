import contextlib
import base64
import copy
import importlib.machinery
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindconsole'))
import bindkit_connections as connections
import bindkit_vault
try:
    from Crypto.Cipher import ARC4
except ImportError:
    ARC4 = None
try:
    import bindkit_pending as pending
except ImportError:
    pending = None


class Vault:
    def __init__(self):
        self.values = {}; self.available = True; self.fail_set = False; self.counter = 0
    def status(self): return {'available': self.available}
    def new_ref(self, prefix='credential'):
        self.counter += 1
        return 'opaque-' + prefix + '-' + str(self.counter)
    def set(self, ref, value):
        if not self.available or self.fail_set: raise RuntimeError('secret backend error')
        self.values[ref] = value
    def get(self, ref):
        if not self.available: raise RuntimeError('secret backend error')
        return self.values.get(ref)
    def delete(self, ref): self.values.pop(ref, None)


class SSH:
    def __init__(self, base):
        self.KEYS_DIR = str(Path(base) / 'keys'); self.STATE_FILE = str(Path(base) / 'state.json')
        self.state = {'version': 1, 'servers': {}}; self.config = {}; self.installs = []; self.tests = []
        self.valid = True; self.install_ok = True; self.fail_save = False; self.generated = []; self.password_calls = []
    def load_state(self): return copy.deepcopy(self.state)
    def save_state(self, state):
        if self.fail_save: raise OSError('synthetic write failure')
        self.state = copy.deepcopy(state)
    def write_ssh_config(self, servers): self.config = copy.deepcopy(servers)
    def gen_keypair(self, name):
        self.generated.append(name)
        private = str(Path(self.KEYS_DIR) / name)
        Path(private).write_text('synthetic-private'); os.chmod(private, 0o600)
        Path(private + '.pub').write_text('ssh-ed25519 synthetic-public')
        return private, private + '.pub'
    def read_pubkey_for(self, key): return 'ssh-ed25519 synthetic-public'
    def fingerprint_of(self, pub): return 'SHA256:synthetic'
    def make_auth(self, mode, password=None): return {'mode': mode, 'password': password}
    def ssh_base(self, host, user, port): return ['ssh', '-p', str(port)]
    def auth_ssh_opts(self, auth):
        self.password_calls.append(auth)
        return ['-o', 'PubkeyAuthentication=no'], types.SimpleNamespace(env=lambda: {}, close=lambda: None)
    def run_ssh(self, argv, **kwargs):
        assert argv[-1] == "printf 'SSHBIND_OK\\n'"
        return (0, 'SSHBIND_OK\n', '') if self.valid else (255, '', 'sensitive diagnostic')
    def install_pubkey(self, *args, **kwargs):
        self.installs.append((args, kwargs)); return self.install_ok, 'synthetic'
    def test_connection(self, *args, **kwargs):
        self.tests.append((args, kwargs)); return self.valid, ['sensitive-secret-diagnostic']


class PendingConnectionsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pending, 'pending connection lifecycle module is required')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        environment = patch.dict(os.environ, {'HOME': self.temp.name})
        environment.start(); self.addCleanup(environment.stop)
        self.ssh = SSH(self.temp.name); self.vault = Vault()
    def create(self, **fields):
        body = dict(name='demo', host='example.invalid', user='operator', port=22)
        body.update(fields)
        return pending.create_unverified(self.ssh, body, self.vault)
    def verify(self): return pending.verify_pending(self.ssh, 'demo', self.vault)
    def test_offline_metadata_requires_no_network_or_keychain(self):
        self.vault.available = False
        result = self.create(note='later', sudo='ask')
        row = self.ssh.state['servers']['demo']
        self.assertTrue(result['ok']); self.assertFalse(result['usable'])
        self.assertFalse(row['installed']); self.assertEqual(row['verification_status'], 'pending')
        self.assertEqual(row['key'], ''); self.assertTrue(row['id']); self.assertEqual(row['revision'], 1)
        self.assertEqual(row['note'], 'later'); self.assertEqual(row['sudo'], 'ask')
        self.assertFalse(self.ssh.installs); self.assertFalse(self.ssh.tests); self.assertFalse(self.ssh.generated)
    def test_password_and_unknown_cipher_only_persist_as_keychain_refs(self):
        self.create(password='synthetic-login', encrypted_login={'encrypted_password': 'synthetic-cipher', 'version': '7.1'})
        row = self.ssh.state['servers']['demo']; state_text = json.dumps(self.ssh.state)
        self.assertEqual(self.vault.values[row['login_credential_ref']], 'synthetic-login')
        self.assertEqual(json.loads(self.vault.values[row['encrypted_login_ref']]), {'encrypted_password': 'synthetic-cipher', 'version': '7.1'})
        self.assertNotIn('synthetic-login', state_text); self.assertNotIn('synthetic-cipher', state_text)
        self.assertFalse(self.ssh.installs); self.assertFalse(self.ssh.tests)
    def test_private_key_is_unique_private_file_and_old_files_are_retained(self):
        Path(self.ssh.KEYS_DIR).mkdir(); old = Path(self.ssh.KEYS_DIR) / 'demo'; old.write_text('keep-old')
        self.create(private_key='synthetic-private')
        row = self.ssh.state['servers']['demo']; key = Path(row['key'])
        self.assertNotEqual(key, old); self.assertEqual(old.read_text(), 'keep-old')
        self.assertEqual(key.read_text(), 'synthetic-private\n'); self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('synthetic-private', json.dumps(self.ssh.state))
        self.assertFalse(self.ssh.tests)
    def test_duplicate_is_rejected_without_credential_mutation(self):
        self.create(password='synthetic-login'); before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values)
        with self.assertRaises(connections.ConnectionError): self.create(password='other')
        self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
    def test_bad_metadata_is_rejected_before_side_effects(self):
        for fields in ({'name': '../bad'}, {'host': '-option'}, {'user': 'bad user'}, {'port': True}, {'port': 0}, {'port': 65536}, {'password': 123}, {'encrypted_login': {'password': 'unexpected'}}):
            with self.assertRaises(connections.ConnectionError, msg=str(fields)): self.create(**fields)
        self.assertFalse(self.ssh.state['servers']); self.assertFalse(self.vault.values); self.assertFalse(self.ssh.installs)
    def test_import_alias_and_domain_username_ranges_are_accepted_offline(self):
        for name, user in (('a' * 67, 'operator'), ('domain-user', r'CORP\operator'),
                           ('email-user', 'operator@example.invalid'), ('b' * 128, 'operator')):
            with self.subTest(name_length=len(name), user=user):
                result = self.create(name=name, user=user)
                self.assertTrue(result['ok']); self.assertFalse(result['usable'])
                self.assertEqual(self.ssh.state['servers'][name]['user'], user)
        self.assertFalse(self.ssh.installs); self.assertFalse(self.ssh.tests)
    def test_import_username_controls_and_leading_dash_stay_invalid(self):
        for user in ('-operator', 'CORP\noperator', 'operator\tname', 'operator\x00name', 'operator name', 'a' * 129):
            with self.subTest(user=user):
                with self.assertRaises(connections.ConnectionError): self.create(user=user)
        with self.assertRaises(connections.ConnectionError): self.create(name='a' * 129)
        self.assertFalse(self.ssh.state['servers']); self.assertFalse(self.ssh.installs)
    def test_keychain_unavailable_or_failed_write_cannot_fallback_to_disk(self):
        for availability, failure in ((False, False), (True, True)):
            self.vault.available = availability; self.vault.fail_set = failure
            with self.assertRaises(connections.ConnectionError): self.create(password='synthetic-login', private_key='synthetic-private')
            self.assertFalse(self.ssh.state['servers']); self.assertFalse(self.vault.values)
            self.assertFalse(list(Path(self.ssh.KEYS_DIR).glob('*')))
    def test_save_failure_rolls_back_config_secrets_and_only_new_key(self):
        Path(self.ssh.KEYS_DIR).mkdir(); old = Path(self.ssh.KEYS_DIR) / 'old'; old.write_text('keep-old')
        self.ssh.fail_save = True
        with self.assertRaises(connections.ConnectionError): self.create(password='synthetic-login', private_key='synthetic-private')
        self.assertFalse(self.ssh.state['servers']); self.assertFalse(self.ssh.config); self.assertFalse(self.vault.values)
        self.assertEqual(list(Path(self.ssh.KEYS_DIR).iterdir()), [old])
    def test_saved_password_installs_and_verifies_then_activates_same_id(self):
        self.create(password='synthetic-login', auth_type='key'); old = copy.deepcopy(self.ssh.state['servers']['demo'])
        result = self.verify(); row = self.ssh.state['servers']['demo']
        self.assertTrue(result['ok']); self.assertTrue(result['usable']); self.assertTrue(row['installed'])
        self.assertEqual(row['verification_status'], 'verified'); self.assertEqual(row['id'], old['id']); self.assertEqual(row['revision'], 2)
        self.assertEqual(self.ssh.installs[0][0][3]['password'], 'synthetic-login'); self.assertEqual(len(self.ssh.tests), 1)
        self.assertEqual(self.vault.values[row['login_credential_ref']], 'synthetic-login')
        self.assertNotIn('synthetic-login', json.dumps(result)); self.assertNotIn('sensitive-secret-diagnostic', json.dumps(result))
    def test_failed_install_or_verification_keeps_pending_and_saved_credentials(self):
        self.create(password='synthetic-login', auth_type='key'); before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values)
        for install_ok, valid in ((False, True), (True, False)):
            self.ssh.install_ok = install_ok; self.ssh.valid = valid
            result = self.verify()
            self.assertFalse(result['ok']); self.assertFalse(result['usable']); self.assertEqual(result['verification_status'], 'pending')
            self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
            self.assertFalse(list(Path(self.ssh.KEYS_DIR).glob('*')))
    def test_saved_private_key_verifies_without_login_secret(self):
        self.create(private_key='synthetic-private'); path = self.ssh.state['servers']['demo']['key']
        self.assertTrue(self.verify()['usable']); self.assertFalse(self.ssh.installs)
        self.assertEqual(self.ssh.tests[0][0][3], path); self.assertEqual(Path(path).read_text(), 'synthetic-private\n')
    def test_missing_or_encrypted_only_credential_needs_explicit_credential(self):
        self.create(encrypted_login={'encrypted_password': 'synthetic-cipher', 'version': '7.1'})
        before = copy.deepcopy(self.ssh.state); result = self.verify()
        self.assertFalse(result['ok']); self.assertTrue(result['needs_credential']); self.assertEqual(result['code'], 'NEEDS_CREDENTIAL')
        self.assertFalse(self.ssh.installs); self.assertFalse(self.ssh.tests); self.assertEqual(self.ssh.state, before)
    def test_locked_saved_password_keeps_pending_without_auth_attempt(self):
        self.create(password='synthetic-login'); before = copy.deepcopy(self.ssh.state); self.vault.available = False
        result = self.verify()
        self.assertFalse(result['usable']); self.assertEqual(result['code'], 'VAULT_UNAVAILABLE')
        self.assertFalse(self.ssh.installs); self.assertEqual(self.ssh.state, before)
    def test_activation_save_failure_keeps_original_key_and_state(self):
        self.create(private_key='synthetic-private'); before = copy.deepcopy(self.ssh.state); self.ssh.fail_save = True
        result = self.verify()
        self.assertFalse(result['ok']); self.assertEqual(self.ssh.state, before); self.assertEqual(self.ssh.config, before['servers'])
        self.assertTrue(Path(before['servers']['demo']['key']).exists())
    def test_uncertain_activation_commit_keeps_any_persisted_key_reference(self):
        self.create(password='synthetic-login', auth_type='key')
        def uncertain_save(state):
            if state['servers']['demo'].get('installed'):
                self.ssh.state = copy.deepcopy(state)
            raise OSError('synthetic uncertain persistence')
        with patch.object(self.ssh, 'save_state', side_effect=uncertain_save):
            result = self.verify()
        row = self.ssh.state['servers']['demo']
        self.assertEqual(result['code'], 'ROLLBACK_FAILED')
        self.assertTrue(Path(row['key']).exists()); self.assertIn(row['login_credential_ref'], self.vault.values)
    def test_unlock_wrong_context_keeps_saved_cipher_and_connection_unchanged(self):
        self.create(encrypted_login={'encrypted_password': 'synthetic-cipher', 'version': '7.1'})
        before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values)
        decoder = types.SimpleNamespace(recover_password=lambda *args, **kwargs: {'status': 'invalid'})
        with patch.dict(sys.modules, {'bindkit_xshell_crypto': decoder}):
            result = pending.unlock_credentials(self.ssh, 'demo', {'master_password': 'synthetic-wrong'}, self.vault)
        self.assertFalse(result['ok']); self.assertEqual(result['code'], 'CREDENTIAL_UNLOCK_FAILED')
        self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
        self.assertNotIn('synthetic-wrong', json.dumps(result)); self.assertFalse(self.ssh.tests)
    def test_unlock_retains_login_secret_then_test_activates_without_retyping(self):
        self.create(encrypted_login={'encrypted_password': 'synthetic-cipher', 'version': '7.1'})
        old = copy.deepcopy(self.ssh.state['servers']['demo'])
        decoder = types.SimpleNamespace(recover_password=lambda *args, **kwargs: {'status': 'available', 'password': 'synthetic-login'})
        with patch.dict(sys.modules, {'bindkit_xshell_crypto': decoder}):
            result = pending.unlock_credentials(self.ssh, 'demo', {'master_password': 'synthetic-master'}, self.vault)
        row = self.ssh.state['servers']['demo']; self.assertTrue(result['ok']); self.assertTrue(result['has_login_credential'])
        self.assertEqual(row['id'], old['id']); self.assertEqual(row['revision'], 2); self.assertEqual(row['verification_status'], 'pending')
        self.assertEqual(row['encrypted_login_ref'], old['encrypted_login_ref']); self.assertFalse(self.ssh.installs)
        self.assertEqual(self.vault.values[row['login_credential_ref']], 'synthetic-login')
        self.assertNotIn('synthetic-master', json.dumps(self.vault.values)); self.assertNotIn('synthetic-login', json.dumps(result))
        self.assertTrue(self.verify()['usable']); self.assertEqual(self.ssh.state['servers']['demo']['revision'], 3)
    def test_unlock_storage_failure_keeps_old_refs_and_does_not_install_key(self):
        self.create(encrypted_login={'encrypted_password': 'synthetic-cipher', 'version': '7.1'})
        before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values); self.ssh.fail_save = True
        decoder = types.SimpleNamespace(recover_password=lambda *args, **kwargs: {'status': 'available', 'password': 'synthetic-login'})
        with patch.dict(sys.modules, {'bindkit_xshell_crypto': decoder}):
            result = pending.unlock_credentials(self.ssh, 'demo', {'master_password': 'synthetic-master'}, self.vault)
        self.assertFalse(result['ok']); self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
        self.assertFalse(self.ssh.installs)
    @unittest.skipUnless(ARC4, 'optional pycryptodome required for cipher vector')
    def test_real_cipher_wrong_and_correct_master_then_activation(self):
        password = b'synthetic-login'; master = 'synthetic-master'
        ciphertext = ARC4.new(hashlib.sha256(master.encode()).digest()).encrypt(password)
        encoded = base64.b64encode(ciphertext + hashlib.sha256(password).digest()).decode()
        self.create(encrypted_login={'encrypted_password': encoded, 'version': '7.1'})
        before = copy.deepcopy(self.ssh.state); saved = dict(self.vault.values)
        wrong = pending.unlock_credentials(self.ssh, 'demo', {'master_password': 'wrong'}, self.vault)
        self.assertFalse(wrong['ok']); self.assertEqual(self.ssh.state, before); self.assertEqual(self.vault.values, saved)
        correct = pending.unlock_credentials(self.ssh, 'demo', {'master_password': master}, self.vault)
        self.assertTrue(correct['ok']); self.assertFalse(self.ssh.installs); self.assertTrue(self.verify()['usable'])
        self.assertFalse(self.ssh.installs); self.assertFalse(self.ssh.generated)
        self.assertEqual(self.ssh.password_calls[-1]['password'], password.decode())


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path)); spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec); loader.exec_module(module); return module


class PendingConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        environment = patch.dict(os.environ, {'HOME': self.temp.name, 'BINDCONSOLE_HOME': str(Path(self.temp.name) / '.bindconsole')})
        environment.start(); self.addCleanup(environment.stop)
        self.ssh = load('pending_ssh', ROOT / 'sshbind/sshbind')
        self.ssh._POLICY_MODULE = load('pending_policy', ROOT / 'bindconsole/bindkit_policy.py')
        self.vault = Vault(); self.vault_patch = patch.object(bindkit_vault, 'Vault', return_value=self.vault)
        self.vault_patch.start(); self.addCleanup(self.vault_patch.stop)
        self.transport = patch.object(self.ssh, 'run_ssh', side_effect=AssertionError('Unexpected SSH'))
        self.transport.start(); self.addCleanup(self.transport.stop)
    def test_pending_handler_and_public_items_never_expose_credential_refs(self):
        handler = self.ssh.build_console_handlers().get('create_unverified')
        self.assertTrue(callable(handler), 'explicit offline create callback is required')
        self.assertTrue(callable(self.ssh.build_console_handlers().get('unlock')), 'saved encrypted credential unlock callback is required')
        handler({'name': 'demo', 'host': 'example.invalid', 'password': 'synthetic-login', 'sudo': 'deny', 'note': 'later'})
        item = self.ssh.console_ssh_get('demo'); self.assertFalse(item['usable']); self.assertEqual(item['verification_status'], 'pending')
        self.assertTrue(item['has_login_credential']); self.assertFalse(item['has_encrypted_login']); self.assertEqual(item['sudo'], 'deny')
        serialized = json.dumps(item); self.assertNotIn('opaque-', serialized); self.assertNotIn('synthetic-login', serialized)
        with contextlib.redirect_stdout(io.StringIO()) as output: self.ssh.cmd_list(types.SimpleNamespace(json=True))
        listed = json.loads(output.getvalue())['servers'][0]
        self.assertFalse(listed['usable']); self.assertTrue(listed['has_login_credential']); self.assertNotIn('opaque-', output.getvalue())
        config = Path(self.ssh.SSH_CONFIG)
        self.assertNotIn('Host demo', config.read_text() if config.exists() else '')
    def test_exec_rejects_pending_even_with_existing_key(self):
        self.ssh.ensure_dirs(); key = Path(self.ssh.KEYS_DIR) / 'demo'; key.write_text('synthetic')
        self.ssh.save_state({'servers': {'demo': {'name': 'demo', 'host': 'example.invalid', 'user': 'root', 'port': 22, 'key': str(key), 'installed': False, 'verification_status': 'pending'}}})
        args = types.SimpleNamespace(name='demo', command=['id'], json=True, timeout=1, as_user=None, stdin=False)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()): self.ssh.cmd_exec(args)
    def test_cli_test_pending_is_readonly_and_directs_user_to_web(self):
        self.ssh.console_ssh_create_unverified({'name': 'password-pending', 'host': 'example.invalid', 'password': 'synthetic-login'})
        self.ssh.console_ssh_create_unverified({'name': 'key-pending', 'host': 'example.invalid', 'private_key': 'synthetic-private'})
        before = copy.deepcopy(self.ssh.load_state()); saved = dict(self.vault.values)
        with patch.object(pending, 'verify_pending', return_value={'ok': True, 'message': 'activated'}) as activation, \
             patch.object(self.ssh, 'test_connection', return_value=(True, ['synthetic'])) as probe, \
             patch.object(self.vault, 'get', wraps=self.vault.get) as read_credential, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = self.ssh.main(['test', '--all'])
        self.assertEqual(code, 1); self.assertIn('Web', output.getvalue())
        activation.assert_not_called(); probe.assert_not_called(); read_credential.assert_not_called()
        self.assertEqual(self.ssh.load_state(), before); self.assertEqual(self.vault.values, saved)
        self.ssh.run_ssh.assert_not_called()
    def test_cli_test_existing_verified_connection_does_not_modify_state(self):
        self.ssh.ensure_dirs(); key = Path(self.ssh.KEYS_DIR) / 'demo'; key.write_text('synthetic')
        row = self.ssh._record('demo', 'example.invalid', 'operator', 22, str(key), 'fake', 'ed25519', False, None, 'generated', True)
        self.ssh.save_state({'servers': {'demo': row}}); before = copy.deepcopy(self.ssh.load_state())
        with patch.object(pending, 'verify_pending') as activation, \
             patch.object(self.ssh, 'test_connection', return_value=(True, ['synthetic'])) as probe, \
             contextlib.redirect_stdout(io.StringIO()):
            code = self.ssh.main(['test', 'demo'])
        self.assertEqual(code, 0); activation.assert_not_called(); probe.assert_called_once()
        self.assertEqual(self.ssh.load_state(), before); self.assertEqual(key.read_text(), 'synthetic')
    def test_remove_keyless_pending_preserves_unrelated_cwd_pub_file(self):
        workspace = Path(self.temp.name) / 'working'; workspace.mkdir()
        unrelated = workspace / '.pub'; previous_cwd = os.getcwd()
        try:
            os.chdir(workspace)
            for credentials in ({}, {'password': 'synthetic-login'}):
                with self.subTest(has_password=bool(credentials)):
                    unrelated.write_text('unrelated-user-public-file')
                    self.ssh.console_ssh_create_unverified(dict(name='demo', host='example.invalid', **credentials))
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = self.ssh.main(['remove', 'demo', '--no-revoke', '--yes'])
                    self.assertEqual(code, 0); self.assertTrue(unrelated.exists())
                    self.assertEqual(unrelated.read_text(), 'unrelated-user-public-file')
                    self.assertNotIn('demo', self.ssh.load_state()['servers'])
            self.ssh.run_ssh.assert_not_called()
        finally:
            os.chdir(previous_cwd)
    def test_normal_create_with_password_retention_fails_before_ssh_if_vault_unavailable(self):
        self.vault.available = False
        with self.assertRaises(Exception):
            self.ssh.console_ssh_create({'name': 'demo', 'host': 'example.invalid', 'password': 'synthetic-login', 'preserve_password': True, 'auth_type': 'key'})
        self.assertFalse(self.ssh.load_state()['servers']); self.assertFalse(self.vault.values)
        self.ssh.run_ssh.assert_not_called()
    def test_verified_create_retains_password_only_after_successful_state_commit(self):
        self.ssh.ensure_dirs(); key = Path(self.ssh.KEYS_DIR) / 'demo'; key.write_text('synthetic')
        def create(body):
            self.ssh.save_state({'servers': {'demo': self.ssh._record('demo', 'example.invalid', 'root', 22, str(key), 'fake', 'ed25519', False, None, 'generated', True)}})
            return {'ok': True, 'name': 'demo'}
        with patch.object(self.ssh, '_console_ssh_create', side_effect=create):
            result = self.ssh.console_ssh_create({'name': 'demo', 'host': 'example.invalid', 'password': 'synthetic-login', 'preserve_password': True, 'auth_type': 'key'})
        row = self.ssh.load_state()['servers']['demo']; self.assertTrue(result['ok'])
        self.assertEqual(self.vault.values[row['login_credential_ref']], 'synthetic-login')
        self.assertTrue(self.ssh.console_ssh_get('demo')['has_login_credential']); self.assertNotIn('opaque-', json.dumps(result))
    def test_failed_verified_create_removes_staged_secret(self):
        with patch.object(self.ssh, '_console_ssh_create', side_effect=RuntimeError('synthetic')):
            with self.assertRaises(Exception): self.ssh.console_ssh_create({'name': 'demo', 'host': 'example.invalid', 'password': 'synthetic-login', 'preserve_password': True, 'auth_type': 'key'})
        self.assertFalse(self.vault.values)
    def test_retention_attach_save_failure_returns_failure_and_preserves_old_keys(self):
        self.ssh.ensure_dirs(); key = Path(self.ssh.KEYS_DIR) / 'demo'; key.write_text('synthetic')
        original_save = self.ssh.save_state
        def create(body):
            original_save({'servers': {'demo': self.ssh._record('demo', 'example.invalid', 'root', 22, str(key), 'fake', 'ed25519', False, None, 'generated', True)}})
            return {'ok': True, 'name': 'demo'}
        def save(state):
            if state['servers'].get('demo', {}).get('login_credential_ref'): raise OSError('synthetic retention save failure')
            return original_save(state)
        with patch.object(self.ssh, '_console_ssh_create', side_effect=create), patch.object(self.ssh, 'save_state', side_effect=save):
            with self.assertRaises(Exception):
                self.ssh.console_ssh_create({'name': 'demo', 'host': 'example.invalid', 'password': 'synthetic-login', 'preserve_password': True, 'auth_type': 'key'})
        self.assertFalse(self.ssh.load_state()['servers']); self.assertFalse(self.vault.values); self.assertTrue(key.exists())
    def test_retention_refuses_changed_identity_without_removing_replacement(self):
        self.ssh.ensure_dirs(); key = Path(self.ssh.KEYS_DIR) / 'demo'; key.write_text('synthetic')
        row = self.ssh._record('demo', 'other.invalid', 'root', 22, str(key), 'fake', 'ed25519', False, None, 'generated', True)
        def create(body):
            self.ssh.save_state({'servers': {'demo': row}})
            return {'ok': True, 'name': 'demo', 'id': 'prior-created-id'}
        with patch.object(self.ssh, '_console_ssh_create', side_effect=create):
            with self.assertRaises(Exception):
                self.ssh.console_ssh_create({'name': 'demo', 'host': 'example.invalid', 'password': 'synthetic-login', 'preserve_password': True, 'auth_type': 'key'})
        self.assertEqual(self.ssh.load_state()['servers']['demo'], row); self.assertFalse(self.vault.values)


if __name__ == '__main__': unittest.main()
