import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        p = ROOT / 'install.sh'
        self.assertTrue(p.is_file(), 'standalone installer must exist')
        code = p.read_text().split("<<'PYTHON_BOOTSTRAP'\n", 1)[1].rsplit('\nPYTHON_BOOTSTRAP', 1)[0]
        self.ns = {'__name__': 'bindkit_bootstrap'}
        exec(compile(code, str(p), 'exec'), self.ns)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, members):
        p = self.root / 'package.tar.gz'
        with tarfile.open(p, 'w:gz') as tf:
            for name, kind in members:
                info = tarfile.TarInfo(name)
                info.mode = 0o644
                if kind == 'link':
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/tmp/outside'
                    tf.addfile(info)
                else:
                    info.size = 2
                    tf.addfile(info, io.BytesIO(b'ok'))
        return p

    def test_checksum_mismatch_extracts_nothing(self):
        p = self.archive([('package/file', 'file')])
        with self.assertRaises(ValueError):
            self.ns['unpack'](p, '0' * 64, self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_unsafe_members_extract_nothing(self):
        for members in ([('package/../../outside', 'file')],
                        [('/tmp/outside', 'file')], [('package/link', 'link')],
                        [('package/file', 'file'), ('package/file', 'file')]):
            with self.subTest(members=members):
                p = self.archive(members)
                with self.assertRaises(ValueError):
                    self.ns['unpack'](p, hashlib.sha256(p.read_bytes()).hexdigest(), self.root / 'out')
                self.assertFalse((self.root / 'out').exists())

    def test_valid_archive_extracts(self):
        p = self.archive([('package/file', 'file')])
        self.ns['unpack'](p, hashlib.sha256(p.read_bytes()).hexdigest(), self.root / 'out')
        self.assertEqual((self.root / 'out/package/file').read_bytes(), b'ok')


if __name__ == '__main__':
    unittest.main()
