"""Native OpenSSH database routes must not misroute keychain-only aliases."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class PasswordDBBoundaryTests(unittest.TestCase):
    def test_password_alias_never_falls_through_to_unrelated_native_ssh_alias(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'HOME': folder}):
            path = Path(folder) / '.ssh/sshbind/servers.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({'servers': {'synthetic': {'auth_type': 'password', 'login_credential_ref': 'opaque'}}}))
            loader = importlib.machinery.SourceFileLoader('password_boundary_db', str(ROOT / 'dbbind/dbbind'))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            db = importlib.util.module_from_spec(spec); loader.exec_module(db)
            for rec in ({'via': 'ssh', 'via_ssh': 'synthetic'}, {'via': 'docker', 'docker_exec': 'synthetic:db'}):
                with self.subTest(via=rec['via']):
                    with self.assertRaises(db.DbbindError) as error:
                        db.build_invocation(dict(rec, engine='mysql'), [], 'select 1')
                    self.assertEqual(error.exception.code, 'UNSUPPORTED')
