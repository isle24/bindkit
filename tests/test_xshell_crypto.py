"""Synthetic and published demonstration vectors only; no Windows/user I/O."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindconsole'))
SPEC = importlib.util.spec_from_file_location('crypto_under_test', ROOT / 'bindconsole/bindkit_xshell_crypto.py')
CRYPTO = None
if Path(SPEC.origin).exists():
    CRYPTO = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(CRYPTO)
try:
    from Crypto.Cipher import ARC4
except ImportError:
    ARC4 = None

SID = 'S-1-5-21-917267712-1342860078-1792151419-512'  # Published example identity.
IDENTITY = {'source_username': 'Administrator', 'source_sid': SID}


def synthetic_ciphertext(password=b' synthetic-password \xe9\x9b\xaa ', key_material='batch-master'):
    """Build fixtures using the external cipher, independent of recovery code."""
    encrypted = ARC4.new(hashlib.sha256(key_material.encode()).digest()).encrypt(password)
    return base64.b64encode(encrypted + hashlib.sha256(password).digest()).decode()


class XshellCryptoTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CRYPTO, 'Xshell recovery module must be implemented')
        tmp = tempfile.TemporaryDirectory(prefix='bindkit-crypto-test-home-')
        self.addCleanup(tmp.cleanup)
        home = patch.dict(os.environ, {'HOME': tmp.name})
        home.start()
        self.addCleanup(home.stop)

    @unittest.skipUnless(ARC4, 'optional pycryptodome required for cipher vectors')
    def test_published_legacy_sid_username_and_master_vectors(self):
        vectors = [
            ('5.0', '/6KaTrKwm0cmhr0yAWQ=', {}),
            ('5.1', 'hIMxIyQ3HbJsVIdbbunHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==', IDENTITY),
            ('5.2', 'hIMxIyQ3HbJsVIdbbunHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==', IDENTITY),
            ('5.3', 'zv21O1x43qRs3c5NckDHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==', IDENTITY),
            ('6.0', 'Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==', {'master_password': '123123'}),
        ]
        for version, value, context in vectors:
            with self.subTest(version=version):
                self.assertEqual(CRYPTO.recover_password(value, version, context),
                                 {'status': 'available', 'password': 'This is a test'})

    @unittest.skipUnless(ARC4, 'optional pycryptodome required for cipher vectors')
    def test_version_70_uses_old_identity_and_71_80_reverse_sid(self):
        for version, material in [('7.0', 'Administrator' + SID),
                                  ('7.1', SID[::-1] + 'Administrator'),
                                  ('7.1.0001', SID[::-1] + 'Administrator'),
                                  ('8.0', SID[::-1] + 'Administrator')]:
            with self.subTest(version=version):
                value = synthetic_ciphertext(key_material=material)
                result = CRYPTO.recover_password(value, version, IDENTITY)
                self.assertEqual(result, {'status': 'available', 'password': ' synthetic-password 雪 '})

    @unittest.skipUnless(ARC4, 'optional pycryptodome required for cipher vectors')
    def test_both_explicit_master_and_identity_support_mixed_batches(self):
        context = dict(IDENTITY, master_password='batch-master')
        for material in ('batch-master', 'Administrator' + SID):
            self.assertEqual(CRYPTO.recover_password(synthetic_ciphertext(key_material=material), '6.0', context)['status'], 'available')

    def test_missing_context_does_not_guess_local_identity(self):
        value = 'hIMxIyQ3HbJsVIdbbunHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=='
        for context in (None, {}, {'source_username': 'Administrator'}):
            with self.subTest(context=context), patch('subprocess.run', side_effect=AssertionError('no OS identity calls')):
                self.assertEqual(CRYPTO.recover_password(value, '6.0', context), {'status': 'needs_context'})

    @unittest.skipUnless(ARC4, 'optional pycryptodome required for cipher vectors')
    def test_wrong_context_case_or_modified_digest_never_returns_password(self):
        value = synthetic_ciphertext()
        damaged = base64.b64decode(value)[:-1] + b'\x00'
        for encoded, context in [(value, {'master_password': 'wrong'}),
                                 (value, {'master_password': 'BATCH-MASTER'}),
                                 (base64.b64encode(damaged).decode(), {'master_password': 'batch-master'})]:
            with self.subTest(encoded=encoded):
                self.assertEqual(CRYPTO.recover_password(encoded, '6.0', context), {'status': 'invalid'})

    @unittest.skipUnless(ARC4, 'optional pycryptodome required for cipher vectors')
    def test_verified_non_utf8_nul_and_oversized_plaintext_rejected(self):
        for password in (b'\xff', b'abc\x00def', b'x' * 4097):
            with self.subTest(length=len(password)):
                result = CRYPTO.recover_password(synthetic_ciphertext(password), '6.0', {'master_password': 'batch-master'})
                self.assertEqual(result, {'status': 'invalid'})

    def test_empty_malformed_and_truncated_ciphertext_fail_safely(self):
        self.assertEqual(CRYPTO.recover_password('', '6.0'), {'status': 'missing'})
        for value in ('not base64!', 'A', 'A' * 10000, base64.b64encode(b'x' * 31).decode()):
            with self.subTest(length=len(value)):
                self.assertEqual(CRYPTO.recover_password(value, '6.0', {'master_password': 'batch-master'}), {'status': 'invalid'})

    def test_unknown_and_absent_versions_are_unsupported(self):
        for version in (None, '', 'future-secret', '9.0', '999999999999999999.1', 'nan', '5..1'):
            with self.subTest(version=version):
                self.assertEqual(CRYPTO.recover_password('/6KaTrKwm0cmhr0yAWQ=', version), {'status': 'unsupported'})

    def test_missing_optional_backend_is_explicit_and_does_not_crash(self):
        with patch.dict(sys.modules, {'Crypto': None, 'Crypto.Cipher': None, 'Crypto.Cipher.ARC4': None}):
            result = CRYPTO.recover_password('/6KaTrKwm0cmhr0yAWQ=', '5.0')
        self.assertEqual(result, {'status': 'unsupported', 'reason': 'backend_missing'})

    def test_invalid_context_is_bounded_and_never_reflected(self):
        for context in ([], {'master_password': 3}, {'master_password': 'x' * 4097},
                        {'source_username': 'x\x00y'}, {'source_sid': ['secret']}):
            result = CRYPTO.recover_password('hIMxIyQ3HbJsVIdbbunHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==', '6.0', context)
            self.assertEqual(result, {'status': 'invalid'})


if __name__ == '__main__':
    unittest.main()
