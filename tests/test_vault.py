import sys
import os
import tempfile
import unittest
import types
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bindconsole'))
import bindkit_vault as vault

class Backend:
    priority = 1
    def __init__(self): self.values = {}
    def get_password(self, service, ref): return self.values.get((service, ref))
    def set_password(self, service, ref, value): self.values[service, ref] = value
    def delete_password(self, service, ref): self.values.pop((service, ref), None)

class VaultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        environ = patch.dict(os.environ, {'HOME':temporary.name}); environ.start(); self.addCleanup(environ.stop)
    def test_roundtrip_opaque_reference(self):
        v = vault.Vault(backend=Backend())
        ref = v.new_ref('sudo')
        self.assertNotEqual(ref, v.new_ref('sudo'))
        v.set(ref, 'synthetic-secret')
        self.assertEqual(v.get(ref), 'synthetic-secret')
        self.assertNotIn('synthetic-secret', str(v.status()))
        v.delete(ref)
        self.assertIsNone(v.get(ref))
    def test_unavailable_no_fallback(self):
        with patch.dict(sys.modules, {'keyring': None}):
            v = vault.Vault()
            self.assertFalse(v.status()['available'])
            with self.assertRaises(vault.VaultError): v.set('ref', 'secret')
    def test_locked_backend_does_not_expose_exception(self):
        class Locked(Backend):
            def get_password(self, *args): raise RuntimeError('secret diagnostic')
        v = vault.Vault(backend=Locked())
        with self.assertRaises(vault.VaultError) as error: v.get('ref')
        self.assertNotIn('secret diagnostic', str(error.exception))
        self.assertEqual(error.exception.code, 'VAULT_LOCKED_OR_UNAVAILABLE')
    def test_autodiscovered_unknown_backend_is_not_trusted(self):
        with patch.dict(sys.modules, {'keyring': types.SimpleNamespace(get_keyring=lambda: Backend())}):
            self.assertFalse(vault.Vault().status()['available'])
    def test_plaintext_backend_rejected(self):
        cls = type('PlaintextKeyring', (Backend,), {'__module__': 'keyrings.alt.file'})
        self.assertFalse(vault.Vault(backend=cls()).status()['available'])

if __name__ == '__main__': unittest.main()
