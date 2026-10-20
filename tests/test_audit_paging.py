import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('catalog_under_test', ROOT / 'bindconsole/bindkit_catalog.py')
CATALOG = None
if Path(SPEC.origin).exists():
    CATALOG = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(CATALOG)


class AuditPagingTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CATALOG, 'audit paging module must be implemented')
        self.tmp = tempfile.TemporaryDirectory(prefix='bindkit-audit-test-')
        self.addCleanup(self.tmp.cleanup)
        home = patch.dict(os.environ, {'HOME': self.tmp.name})
        home.start()
        self.addCleanup(home.stop)
        self.path = Path(self.tmp.name) / 'audit.log'

    def append(self, *records):
        with self.path.open('ab') as out:
            for record in records:
                out.write(json.dumps(record).encode() + b'\n')

    def read(self, **kwargs):
        return CATALOG.read_audit_page(self.path, **kwargs)

    def test_more_than_thousand_events_are_really_paginated(self):
        self.append(*[{'n': n, 'tool': 'ssh'} for n in range(1307)])
        page = self.read(page=7, page_size=200)
        self.assertEqual(page['total'], 1307)
        self.assertEqual([e['n'] for e in page['entries']], list(range(106, -1, -1)))
        self.assertEqual((page['pages'], page['has_next'], page['has_prev']), (7, False, True))

    def test_filters_apply_before_count_and_page(self):
        self.append(*[{'n': n, 'tool': 'ssh' if n % 2 else 'db', 'actor': 'human',
                       'decision': 'allow' if n % 3 else 'deny', 'alias': 'synthetic'}
                      for n in range(50)])
        page = self.read(tool='ssh', actor='human', decision='deny', alias='synthetic', page_size=3)
        self.assertEqual(page['total'], 8)
        self.assertEqual([r['n'] for r in page['entries']], [45, 39, 33])
        self.assertEqual(self.read(actor='other')['total'], 0)

    def test_invalid_parameters_are_rejected(self):
        for params in ({'page': 0}, {'page': True}, {'page': '2'}, {'page': 1.5},
                       {'page_size': 0}, {'page_size': 201}, {'tool': 'bogus'},
                       {'snapshot': 'bad'}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.read(**params)

    def test_absent_and_empty_log(self):
        page = self.read()
        self.assertEqual((page['entries'], page['total'], page['pages']), ([], 0, 0))
        self.assertFalse(page['has_next'])
        self.assertFalse(page['has_prev'])
        self.assertFalse(self.path.exists())
        self.path.touch()
        self.assertEqual(self.read()['entries'], [])

    def test_snapshot_is_stable_when_new_events_are_appended(self):
        self.append(*[{'n': n} for n in range(12)])
        first = self.read(page_size=5)
        self.append({'n': 12}, {'n': 13})
        second = self.read(page=2, page_size=5, snapshot=first['snapshot'])
        self.assertEqual(second['total'], 12)
        self.assertEqual([r['n'] for r in second['entries']], [6, 5, 4, 3, 2])
        self.assertEqual(self.read()['total'], 14)

    def test_incomplete_final_line_is_indexed_only_when_completed(self):
        self.append({'n': 0})
        with self.path.open('ab') as out:
            out.write(b'{"n": 1}')
        old = self.read()
        self.assertEqual(old['total'], 1)
        with self.path.open('ab') as out:
            out.write(b'\n')
        self.assertEqual(self.read()['total'], 2)
        self.assertEqual(self.read(snapshot=old['snapshot'])['total'], 1)

    def test_corrupt_non_object_and_oversized_lines_are_skipped(self):
        self.path.write_bytes(b'no json\n[1,2]\n{"n":0}\n\xff\n' + b'x' * (2 * 1024 * 1024) + b'\n{"n":1}\n')
        self.assertEqual([r['n'] for r in self.read()['entries']], [1, 0])

    def test_rotation_invalidates_snapshot_and_rebuilds(self):
        self.append({'n': 1})
        old = self.read()
        self.path.rename(self.path.with_name('rotated.log'))
        self.append({'n': 2})
        self.assertEqual(self.read()['entries'], [{'n': 2}])
        with self.assertRaisesRegex(ValueError, 'snapshot'):
            self.read(snapshot=old['snapshot'])

    def test_truncate_and_same_size_overwrite_rebuild(self):
        self.append({'n': 1}, {'n': 2})
        old = self.read()
        self.path.write_bytes(b'{"n":3}\n')
        self.assertEqual(self.read()['entries'], [{'n': 3}])
        self.path.write_bytes(b'{"n":4}\n')
        self.assertEqual(self.read()['entries'], [{'n': 4}])
        with self.assertRaises(ValueError):
            self.read(snapshot=old['snapshot'])

    def test_runtime_index_is_private_and_stores_offsets(self):
        self.append({'n': 1})
        self.read()
        files = [p for p in self.path.parent.iterdir() if p != self.path]
        self.assertTrue(files)
        for p in files:
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        index = next(p for p in files if p.suffix == '.sqlite3')
        with sqlite3.connect(index) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM entries').fetchone()[0], 1)
        self.append({'n': 2})
        self.read()
        with sqlite3.connect(index) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM entries').fetchone()[0], 2)

    def test_warm_index_reads_only_boundaries_page_and_new_lines(self):
        self.append(*[{'n': n, 'tool': 'ssh', 'note': 'synthetic ' * 20} for n in range(6000)])
        self.read()
        original = open
        read_sizes = []

        class CountedFile:
            def __init__(self, stream):
                self.stream = stream
            def __getattr__(self, key):
                return getattr(self.stream, key)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def read(self, size=-1):
                self.assert_bound(size)
                raw = self.stream.read(size)
                read_sizes.append(len(raw))
                return raw
            def readline(self, size=-1):
                self.assert_bound(size)
                raw = self.stream.readline(size)
                read_sizes.append(len(raw))
                return raw
            @staticmethod
            def assert_bound(size):
                if size < 0 or size > CATALOG.MAX_LINE_BYTES + 1:
                    raise AssertionError('unbounded audit source read')

        def tracked(path, mode='r', *args, **kwargs):
            stream = original(path, mode, *args, **kwargs)
            return CountedFile(stream) if Path(path) == self.path and mode == 'rb' else stream

        self.append({'n': 6000})
        with patch('builtins.open', side_effect=tracked):
            result = self.read(page_size=1)
        self.assertEqual(result['total'], 6001)
        self.assertLess(sum(read_sizes), 20000)

    def test_index_symlink_is_rejected(self):
        self.append({'n': 1})
        target = self.path.parent / 'untouched'
        target.write_text('synthetic sentinel')
        Path(str(self.path) + '.index.sqlite3').symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            self.read()
        self.assertEqual(target.read_text(), 'synthetic sentinel')


if __name__ == '__main__':
    unittest.main()
