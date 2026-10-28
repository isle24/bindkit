import importlib.util
import io
import json
import os
import struct
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindconsole'))
SPEC = importlib.util.spec_from_file_location('imports_under_test', ROOT / 'bindconsole/bindkit_imports.py')
IMPORTS = None
if Path(SPEC.origin).exists():
    IMPORTS = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(IMPORTS)


def xsh(host='synthetic.example', protocol='SSH', extra=''):
    return ('[CONNECTION]\nHost=' + host + '\nPort=2202\nProtocol=' + protocol
            + '\n[CONNECTION:AUTHENTICATION]\nUserName=demo\n' + extra).encode()


def archive(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return out.getvalue()


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(IMPORTS, 'session parser must be implemented')
        self.tmp = tempfile.TemporaryDirectory(prefix='bindkit-import-test-home-')
        self.addCleanup(self.tmp.cleanup)
        home = patch.dict(os.environ, {'HOME': self.tmp.name})
        home.start()
        self.addCleanup(home.stop)

    def parse(self, content, name='demo.xsh', **kwargs):
        return IMPORTS.parse_import_files([{'name': name, 'content': content}], **kwargs)

    def test_utf8_xshell_metadata_and_safe_field_contract(self):
        result = self.parse(xsh(extra='Password=synthetic-secret\nPasswordV2=encrypted-secret\n'))
        self.assertEqual(result['count'], 1)
        item = result['items'][0]
        self.assertEqual(set(item), {'id', 'name', 'host', 'port', 'user', 'source', 'auth_type', 'requires_credentials', 'key_hint', 'warnings', 'credential_status', 'has_imported_password'})
        self.assertEqual((item['name'], item['host'], item['port'], item['user']), ('demo', 'synthetic.example', 2202, 'demo'))
        self.assertTrue(item['requires_credentials'])
        self.assertEqual(item['source'], 'xshell')
        self.assertEqual(item['auth_type'], 'password')
        self.assertNotIn('secret', json.dumps(result))

    def test_utf16_xshell_and_key_path_is_hint_only(self):
        content = xsh(extra='UserKey=C:\\synthetic\\fake_id_ed25519\n').decode().encode('utf-16')
        with patch('builtins.open', side_effect=AssertionError('preview must not read files')):
            result = self.parse(content)
        item = result['items'][0]
        self.assertEqual(item['auth_type'], 'private_key')
        self.assertEqual(item['key_hint'], 'fake_id_ed25519')
        self.assertNotIn('C:', json.dumps(result))

    def test_non_ssh_protocol_and_invalid_endpoints_are_excluded(self):
        for content in (xsh(protocol='TELNET'), xsh(protocol='SFTP'), xsh(host='bad host'),
                        xsh().replace(b'Port=2202', b'Port=0'), xsh().replace(b'Port=2202', b'Port=65536')):
            with self.subTest(content=content):
                result = self.parse(content)
                self.assertEqual(result['count'], 0)
                self.assertTrue(result['warnings'])

    def test_plain_zip_and_zip_backed_xts_only_read_xsh(self):
        content = archive([('folder/demo.xsh', xsh()), ('ignore.txt', b'not a session'),
                           ('nested.zip', archive([('inner.xsh', xsh())]))])
        for name in ('sessions.zip', 'sessions.xts'):
            with self.subTest(name=name):
                result = self.parse(content, name)
                self.assertEqual(result['count'], 1)
                self.assertEqual(result['items'][0]['name'], 'demo')

    def test_unknown_xts_protection_is_actionable(self):
        result = self.parse(b'protected synthetic container', 'sessions.xts')
        self.assertEqual(result['count'], 0)
        self.assertIn('unsupported', ' '.join(result['warnings']).lower())
        self.assertIn('.xsh', ' '.join(result['warnings']))
        self.assertIn('ZIP', ' '.join(result['warnings']))

    def test_archive_traversal_absolute_paths_and_symlinks_are_rejected(self):
        for name in ('../demo.xsh', '/demo.xsh', 'C:\\demo.xsh', 'a\\..\\demo.xsh'):
            result = self.parse(archive([(name, xsh())]), 'sessions.zip')
            self.assertEqual(result['count'], 0)
            self.assertTrue(result['warnings'])
        info = zipfile.ZipInfo('linked.xsh')
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        result = self.parse(archive([(info, xsh())]), 'sessions.zip')
        self.assertEqual(result['count'], 0)
        self.assertTrue(result['warnings'])

    def test_zip_member_count_and_compression_bomb_are_bounded(self):
        for content in (archive([('%d.xsh' % n, xsh()) for n in range(IMPORTS.MAX_ARCHIVE_ENTRIES + 1)]),
                        archive([('bomb.xsh', b'A' * (2 * 1024 * 1024))])):
            result = self.parse(content, 'sessions.zip')
            self.assertEqual(result['count'], 0)
            self.assertTrue(result['warnings'])

    def test_encrypted_archive_and_corrupt_compressed_member_are_safe_warnings(self):
        original = archive([('demo.xsh', xsh())])
        encrypted = bytearray(original)
        for signature, flag_offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
            start = encrypted.find(signature)
            flags = struct.unpack_from('<H', encrypted, start + flag_offset)[0]
            struct.pack_into('<H', encrypted, start + flag_offset, flags | 1)
        self.assertEqual(self.parse(bytes(encrypted), 'sessions.zip')['count'], 0)
        damaged = bytearray(original)
        name_length, extra_length = struct.unpack_from('<HH', damaged, 26)
        payload_offset = 30 + name_length + extra_length
        damaged[payload_offset] = 0xff  # invalid deflate block header
        result = self.parse(bytes(damaged), 'sessions.zip')
        self.assertEqual(result['count'], 0)
        self.assertTrue(result['warnings'])

    def test_total_expanded_budget_spans_multiple_archives(self):
        content = archive([('demo.xsh', xsh())])
        files = [{'name': 'one.zip', 'content': content}, {'name': 'two.zip', 'content': content}]
        with patch.object(IMPORTS, 'MAX_EXPANDED_BYTES', len(xsh()) + 1):
            result = IMPORTS.parse_import_files(files)
        self.assertEqual(result['count'], 1)
        self.assertTrue(result['warnings'])

    def test_finalshell_json_never_returns_stored_secrets(self):
        content = json.dumps({'name': 'final', 'host': 'synthetic.example', 'port': 22,
                              'user_name': 'demo', 'type': 100, 'password': 'synthetic-secret',
                              'encryptedPassword': 'encrypted-secret'}).encode()
        result = self.parse(content, 'connection.json')
        self.assertEqual(result['items'][0]['source'], 'finalshell')
        self.assertEqual(result['items'][0]['name'], 'final')
        self.assertNotIn('secret', json.dumps(result))

    def test_finalshell_rejects_non_ssh_type(self):
        for protocol in (101, 'rdp', 'telnet'):
            result = self.parse(json.dumps({'host': 'synthetic.example', 'type': protocol}).encode(), 'connection.json')
            self.assertEqual(result['count'], 0)
            self.assertTrue(result['warnings'])

    def test_openssh_multiple_hosts_defaults_and_dangerous_commands(self):
        content = b'''Host *
  User default-user
  Port 2222
  ProxyCommand touch /must-not-exist
Host first second
  HostName synthetic.example
  IdentityFile ~/.ssh/synthetic-key
  LocalCommand touch /must-not-exist
Host wildcard-*
  HostName wildcard.example
Host third
  HostName another.example
  User special
'''
        with patch('builtins.open', side_effect=AssertionError('preview may not open key/include files')):
            result = self.parse(content, 'config')
        self.assertEqual([r['name'] for r in result['items']], ['first', 'second', 'third'])
        self.assertEqual([r['port'] for r in result['items']], [2222, 2222, 2222])
        self.assertEqual(result['items'][0]['user'], 'default-user')
        self.assertEqual(result['items'][2]['user'], 'default-user')
        self.assertEqual(result['items'][0]['key_hint'], 'synthetic-key')
        self.assertNotIn('touch', json.dumps(result))
        self.assertTrue(result['warnings'])

    def test_openssh_include_match_and_dynamic_hostname_are_not_resolved(self):
        result = self.parse(b'Include /synthetic/config\nHost good\n HostName synthetic.example\nMatch exec "touch /bad"\n HostName changed.example\nHost dynamic\n HostName %h.example\n', 'config')
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['items'][0]['host'], 'synthetic.example')
        self.assertTrue(result['warnings'])

    def test_alias_collisions_renamed_and_ids_are_stable(self):
        files = [{'name': 'demo.xsh', 'content': xsh()}, {'name': 'demo.xsh', 'content': xsh()}]
        one = IMPORTS.parse_import_files(files, reserved_names=('demo',))
        two = IMPORTS.parse_import_files(files, reserved_names=('demo',))
        self.assertEqual([r['name'] for r in one['items']], ['demo-2', 'demo-3'])
        self.assertEqual(one, two)
        self.assertEqual(len({r['id'] for r in one['items']}), 2)
        self.assertTrue(one['items'][0]['warnings'])

    def test_malformed_files_report_warnings_without_content(self):
        for content, name in ((b'not json secret-marker', 'session.json'), (b'\xff', 'demo.xsh'),
                              (b'bad zip secret-marker', 'session.zip'), (b'[CONNECTION]\n', 'demo.xsh')):
            result = self.parse(content, name)
            self.assertEqual(result['count'], 0)
            self.assertTrue(result['warnings'])
            self.assertNotIn('secret-marker', json.dumps(result))

    def test_input_type_count_size_and_unknown_format_are_bounded(self):
        for files in ([{'name': 'demo.xsh', 'content': 'text'}],
                      [{'name': 'demo.xsh', 'content': b'x' * (IMPORTS.MAX_FILE_BYTES + 1)}],
                      [{'name': 'demo.xsh', 'content': b''}] * (IMPORTS.MAX_FILES + 1)):
            with self.assertRaises(ValueError):
                IMPORTS.parse_import_files(files)
        with self.assertRaises(ValueError):
            self.parse(xsh(), format='unknown')

    def test_explicit_formats_and_preview_has_no_filesystem_side_effects(self):
        for fmt, name, content in (('xshell', 'unknown', xsh()),
                                   ('finalshell', 'unknown', b'{"host":"synthetic.example"}'),
                                   ('openssh', 'unknown', b'Host demo\n HostName synthetic.example\n')):
            with self.subTest(fmt=fmt), patch('builtins.open', side_effect=AssertionError('preview is memory-only')):
                self.assertEqual(self.parse(content, name, format=fmt)['count'], 1)

    def test_more_than_64_files_and_1024_zip_members_are_supported(self):
        files = [{'name': 'directory/%d.xsh' % n, 'content': xsh()} for n in range(1024)]
        result = IMPORTS.parse_import_files(files)
        self.assertEqual(result['count'], 1024)
        result = self.parse(archive([('nested/%d.xsh' % n, xsh()) for n in range(1024)]), 'batch.xts')
        self.assertEqual(result['count'], 1024)

    def test_request_file_limit_is_16mib_and_member_limit_stays_4mib(self):
        self.assertEqual(IMPORTS.MAX_FILE_BYTES, 16 * 1024 * 1024)
        self.assertEqual(IMPORTS.MAX_FILES, 1024)
        self.assertEqual(IMPORTS.MAX_ARCHIVE_ENTRIES, 1024)
        # Avoid compression-ratio rejection obscuring the member-size check.
        with patch.object(IMPORTS, 'MAX_COMPRESSION_RATIO', 100000):
            result = self.parse(archive([('large.xsh', b'A' * (4 * 1024 * 1024 + 1))]), 'large.zip')
        self.assertEqual(result['count'], 0)
        self.assertIn('member', ' '.join(result['warnings']).lower())

    def test_saved_password_needs_context_and_private_descriptor_uses_final_id(self):
        value = 'Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=='
        content = xsh(extra='Password=' + value + '\n') + b'[SessionInfo]\nVersion=6.0\n'
        captured = {}
        result = self.parse(content, reserved_names=['demo'], credential_sink=captured.__setitem__)
        item = result['items'][0]
        self.assertEqual(item['name'], 'demo-2')
        self.assertEqual(item['credential_status'], 'needs_context')
        self.assertFalse(item['has_imported_password'])
        self.assertTrue(item['requires_credentials'])
        self.assertEqual(captured, {item['id']: {'encrypted_password': value, 'version': '6.0'}})
        self.assertNotIn(value, json.dumps(result))

    def test_empty_saved_password_missing_and_finalshell_cipher_unsupported(self):
        captured = {}
        for content in (xsh(), xsh(extra='Password=\nPasswordSaved=1\n')):
            result = self.parse(content, credential_sink=captured.__setitem__)
            self.assertEqual(result['items'][0]['credential_status'], 'missing')
            self.assertFalse(result['items'][0]['has_imported_password'])
        self.assertEqual(captured, {})
        result = self.parse(b'{"host":"synthetic.example","password":"vendor-encrypted"}', 'final.json', credential_sink=captured.__setitem__)
        self.assertEqual(result['items'][0]['credential_status'], 'unsupported')
        self.assertEqual(captured, {})

    def test_missing_backend_warns_how_to_enable_recovery_and_retains_cipher(self):
        captured = {}
        value = '/6KaTrKwm0cmhr0yAWQ='
        content = xsh(extra='Password=' + value + '\n') + b'[SessionInfo]\nVersion=5.0\n'
        with patch.dict(sys.modules, {'Crypto': None, 'Crypto.Cipher': None, 'Crypto.Cipher.ARC4': None}):
            result = self.parse(content, credential_sink=captured.__setitem__)
        item = result['items'][0]
        self.assertEqual(item['credential_status'], 'unsupported')
        self.assertIn('pycryptodome', ' '.join(item['warnings']).lower())
        self.assertEqual(captured[item['id']]['encrypted_password'], value)

    def test_master_unlocks_zip_batch_without_reflecting_secrets(self):
        try:
            from Crypto.Cipher import ARC4  # noqa: F401
        except ImportError:
            self.skipTest('optional pycryptodome required for cipher vectors')
        value = 'Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=='
        content = xsh(extra='Password=' + value + '\n') + b'[SessionInfo]\nVersion=6.0\n'
        captured = {}
        result = self.parse(archive([('nested/one.xsh', content), ('two.xsh', content)]), 'batch.xts',
                            credentials={'master_password': '123123'}, credential_sink=captured.__setitem__)
        self.assertEqual(result['count'], 2)
        for item in result['items']:
            self.assertEqual(item['credential_status'], 'available')
            self.assertTrue(item['has_imported_password'])
            self.assertFalse(item['requires_credentials'])
            self.assertEqual(captured[item['id']], {'password': 'This is a test'})
        public = json.dumps(result)
        for secret in (value, '123123', 'This is a test', 'encrypted_password'):
            self.assertNotIn(secret, public)

    def test_password_value_does_not_influence_candidate_id(self):
        try:
            from Crypto.Cipher import ARC4  # noqa: F401
        except ImportError:
            self.skipTest('optional pycryptodome required for cipher vectors')
        value = 'Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=='
        content = xsh(extra='Password=' + value + '\n') + b'[SessionInfo]\nVersion=6.0\n'
        locked = self.parse(content)
        unlocked = self.parse(content, credentials={'master_password': '123123'})
        self.assertEqual(locked['items'][0]['id'], unlocked['items'][0]['id'])

    def test_invalid_or_unknown_saved_password_has_explicit_safe_status(self):
        cases = [('6.0', 'not-base64!', 'invalid'), ('9.0', '/6KaTrKwm0cmhr0yAWQ=', 'unsupported'),
                 ('version-secret', '/6KaTrKwm0cmhr0yAWQ=', 'unsupported')]
        for version, value, expected in cases:
            with self.subTest(version=version):
                content = xsh(extra='Password=' + value + '\n') + ('[SessionInfo]\nVersion=' + version + '\n').encode()
                result = self.parse(content, credentials={'master_password': 'private-master'})
                self.assertEqual(result['items'][0]['credential_status'], expected)
                for secret in (value, version if 'secret' in version else 'unrelated', 'private-master'):
                    self.assertNotIn(secret, json.dumps(result))

    def test_unknown_version_and_passwordv2_preserve_bounded_cipher_with_unknown_marker(self):
        value = '/6KaTrKwm0cmhr0yAWQ='
        for field, extra in [('Password', ''), ('PasswordV2', '[SessionInfo]\nVersion=7.1\n')]:
            with self.subTest(field=field):
                captured = {}
                result = self.parse(xsh(extra=field + '=' + value + '\n') + extra.encode(),
                                    credential_sink=captured.__setitem__)
                item = result['items'][0]
                self.assertEqual(item['credential_status'], 'unsupported')
                self.assertEqual(captured[item['id']], {'encrypted_password': value, 'version': 'unknown'})

    def test_wrong_batch_unlock_retains_cipher_and_source_identity_unlocks_utf16(self):
        try:
            from Crypto.Cipher import ARC4  # noqa: F401
        except ImportError:
            self.skipTest('optional pycryptodome required for cipher vectors')
        value = 'zv21O1x43qRs3c5NckDHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=='
        content = (xsh(extra='Password=' + value + '\n').decode() + '[SessionInfo]\nVersion=5.3\n').encode('utf-16')
        captured = {}
        result = self.parse(content, credentials={'master_password': 'wrong-private-master'}, credential_sink=captured.__setitem__)
        item = result['items'][0]
        self.assertEqual(item['credential_status'], 'invalid')
        self.assertEqual(captured[item['id']], {'encrypted_password': value, 'version': '5.3'})
        result = self.parse(content, credentials={'source_username': 'Administrator',
                            'source_sid': 'S-1-5-21-917267712-1342860078-1792151419-512'}, credential_sink=captured.__setitem__)
        self.assertEqual(result['items'][0]['credential_status'], 'available')
        self.assertEqual(captured[item['id']], {'password': 'This is a test'})

    def test_oversized_cipher_is_not_retained_and_sink_must_be_callable(self):
        captured = {}
        result = self.parse(xsh(extra='Password=' + 'A' * 10000 + '\n') + b'[SessionInfo]\nVersion=6.0\n',
                            credential_sink=captured.__setitem__)
        self.assertEqual(result['items'][0]['credential_status'], 'invalid')
        self.assertEqual(captured, {})
        with self.assertRaises(ValueError):
            self.parse(xsh(), credential_sink='unsafe')


if __name__ == '__main__':
    unittest.main()
