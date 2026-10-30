#!/usr/bin/env python3
"""2026-10-19 acceptance regressions; all state and databases are disposable."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[2]
DBBIND = PROJECT.parent / 'dbbind' / 'dbbind'
SSHBIND = Path(os.environ.get('BIND_AUDIT_SSHBIND', str(PROJECT.parent / 'sshbind' / 'sshbind')))


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class AcceptanceRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bind-acceptance-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {'HOME': str(self.home),
                                          'BINDCONSOLE_HOME': str(self.home / '.bindconsole')})
        self.env.start()
        self.addCleanup(self.env.stop)
        lib = self.home / '.bindconsole/lib'
        lib.mkdir(parents=True)
        shutil.copy(PROJECT / 'bindkit_policy.py', lib)
        self.policy = load(lib / 'bindkit_policy.py', 'acceptance_policy')
        self.db = load(DBBIND, 'acceptance_db')
        self.db._POLICY_MODULE = self.policy
        self.ssh = load(SSHBIND, 'acceptance_ssh')
        self.ssh._POLICY_MODULE = self.policy
        self.dbfile = self.home / 'sandbox.sqlite'
        with sqlite3.connect(self.dbfile) as conn:
            conn.execute('CREATE TABLE allowed(id INTEGER)')
            conn.execute('CREATE TABLE private(id INTEGER)')
            conn.execute('INSERT INTO private VALUES (42)')
        cfg = self.home / '.dbbind/config.json'
        cfg.parent.mkdir(exist_ok=True)
        cfg.write_text(json.dumps({'version': 1, 'databases': {
            'fixture': {'engine': 'sqlite', 'file': str(self.dbfile)}}}))
        self.config = cfg

    def cli(self, *args):
        proc = subprocess.run([str(DBBIND), '--config', str(self.config), *args],
                              cwd=self.home, capture_output=True, text=True, timeout=10)
        return proc, json.loads(proc.stdout)

    def test_export_obeys_table_policy_and_does_not_create_output(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {
            'max_level': 'read', 'allowed_tables': ['allowed']}})
        out = self.home / 'forbidden.json'
        proc, data = self.cli('export', '--json', '--format', 'json', '--out', str(out),
                              'fixture', 'SELECT * FROM private')
        self.assertEqual(proc.returncode, 5, data)
        self.assertEqual(data['error']['code'], 'AUTHZ_DENIED')
        self.assertFalse(out.exists())

    def test_database_override_is_checked_before_connection(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {
            'max_level': 'read', 'allowed_databases': ['testdb']}})
        self.config.write_text(json.dumps({'version': 1, 'databases': {
            'fixture': {'engine': 'mysql', 'host': '127.0.0.1', 'port': 1,
                        'user': 'fixture', 'database': 'testdb'}}}))
        # The gate must reject before running a client; no MySQL dependency is needed here.
        with patch.dict(os.environ, {'DBBIND_MYSQL': shutil.which('true')}):
            proc, data = self.cli('exec', '--json', '--database', 'forbidden',
                                  'fixture', 'SELECT 1')
        self.assertEqual(proc.returncode, 5, data)
        self.assertEqual(data['error']['code'], 'AUTHZ_DENIED')

    def test_create_persists_policy_from_form(self):
        self.db.console_db_create({'alias': 'new', 'engine': 'sqlite',
                                   'file': str(self.dbfile), 'max_level': 'write',
                                   'allowed_tables': ['allowed'],
                                   'approval': {'write': True, 'ddl': True}})
        item = self.db.console_db_get('new')
        self.assertEqual(item['max_level'], 'write')
        self.assertEqual(item['allowed_tables'], ['allowed'])
        self.assertTrue(item['approval']['write'])

    def test_invalid_create_policy_leaves_no_alias(self):
        with self.assertRaises(Exception):
            self.db.console_db_create({'alias': 'bad', 'engine': 'sqlite',
                                       'file': str(self.dbfile), 'max_level': 'invalid'})
        self.assertNotIn('bad', self.db.load_state()['databases'])

    def test_edit_sqlite_path_persists(self):
        self.db.console_db_create({'alias': 'new', 'engine': 'sqlite',
                                   'file': str(self.dbfile)})
        other = self.home / 'other.sqlite'
        other.touch()
        self.db.console_db_update('new', {'file': str(other)})
        self.assertEqual(self.db.console_db_get('new')['file'], str(other))

    def test_imported_private_key_survives_adopt_and_failure_cleans_it(self):
        key = 'disposable-key-marker\n'
        seen = []
        def adopt(argv, **kwargs):
            path = Path(argv[argv.index('--identity') + 1])
            self.assertEqual(path.read_text(), key)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            seen.append(path)
            return 0, '', ''
        with patch.object(self.ssh, '_run_self', side_effect=adopt):
            self.ssh.console_ssh_create({'name': 'new', 'host': '127.0.0.1',
                                         'private_key': key})
        self.assertTrue(seen[0].is_file(), 'adopt only registers the key path')
        self.assertEqual(seen[0].read_text(), key)
        failed = []
        def reject(argv, **kwargs):
            failed.append(Path(argv[argv.index('--identity') + 1]))
            return 1, '', 'fixture rejected'
        with patch.object(self.ssh, '_run_self', side_effect=reject):
            with self.assertRaises(Exception):
                self.ssh.console_ssh_create({'name': 'fail', 'host': '127.0.0.1',
                                             'private_key': key})
        self.assertFalse(failed[0].exists())

    def test_approval_is_bound_to_engine_and_database(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {
            'max_level': 'write', 'approval': {'write': True}}})
        sql = 'UPDATE allowed SET id=1'
        first = self.policy.gate_db('fixture', sql, 'mysql', 'db_a', requested_write=True)
        self.policy.approve('db', first['request_id'])
        other = self.policy.gate_db('fixture', sql, 'mysql', 'db_b', requested_write=True)
        self.assertEqual(other['decision'], 'ask', other)
        self.assertNotEqual(other.get('request_id'), first['request_id'])
        retry = self.policy.gate_db('fixture', sql, 'mysql', 'db_a', requested_write=True)
        self.assertEqual(retry['decision'], 'allow', retry)

    def test_mysql_double_minus_arithmetic_keeps_target_visible(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {
            'max_level': 'read', 'allowed_databases': ['allowed']}})
        result = self.policy.gate_db('fixture',
            'SELECT id, 1--1 FROM forbidden.private', 'mysql', 'allowed')
        self.assertEqual(result['decision'], 'deny', result)

    def test_forbidden_system_database_is_checked_as_default(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {'max_level': 'read'}})
        result = self.policy.gate_db('fixture', 'SELECT * FROM user', 'mysql', 'mysql')
        self.assertEqual(result['decision'], 'deny', result)

    def test_ssh_create_saves_selected_policy(self):
        def add(argv, **kwargs):
            state = self.ssh.load_state()
            state['servers']['new'] = {'name': 'new', 'host': '127.0.0.1', 'user': 'fixture'}
            self.ssh.save_state(state)
            return 0, '', ''
        with patch.object(self.ssh, '_run_self', side_effect=add):
            self.ssh.console_ssh_create({'name': 'new', 'host': '127.0.0.1', 'auth_type': 'key',
                                         'password': 'disposable-fixture', 'sudo': 'deny'})
        result = self.policy.gate_ssh('new', 'sudo true')
        self.assertEqual(result['decision'], 'deny', result)

    def test_invalid_ssh_create_policy_does_not_connect(self):
        with patch.object(self.ssh, '_run_self') as run:
            with self.assertRaises(Exception):
                self.ssh.console_ssh_create({'name': 'bad', 'host': '127.0.0.1',
                                             'password': 'disposable-fixture', 'sudo': 'invalid'})
            run.assert_not_called()

    def test_pg_search_path_modifiers_obey_schema_policy(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {
            'max_level': 'read', 'allowed_schemas': ['public']}})
        for modifier in ('SESSION', 'LOCAL'):
            with self.subTest(modifier=modifier):
                result = self.policy.gate_db('fixture',
                    'SET %s search_path TO private; SELECT * FROM secret' % modifier,
                    'postgres', 'app')
                self.assertEqual(result['decision'], 'deny', result)

    def test_pg_only_parentheses_obey_schema_policy(self):
        self.policy.write_policy('db', {'version': 1, 'defaults': {
            'max_level': 'read', 'allowed_schemas': ['public']}})
        result = self.policy.gate_db('fixture', 'SELECT * FROM ONLY (private.secret)',
                                     'postgres', 'app')
        self.assertEqual(result['decision'], 'deny', result)

    def test_credentials_are_redacted_in_sql_and_connection_uris(self):
        marker = 'disposable-fixture-secret'
        samples = ["ALTER USER demo WITH PASSWORD '%s'" % marker,
                   'postgres://demo:%s@localhost/app' % marker,
                   "ALTER USER demo WITH PASSWORD 'escaped''%s'" % marker]
        for text in samples:
            for fn in (self.policy.redact, self.db.redact):
                with self.subTest(text=text, fn=fn.__module__):
                    self.assertNotIn(marker, fn(text))

    def test_private_key_import_runs_real_adopt_with_isolated_transport(self):
        original = self.home / 'generated-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(original)],
                       check=True, capture_output=True, timeout=10)
        fake_bin = self.home / 'bin'
        fake_bin.mkdir()
        transport = fake_bin / 'ssh'
        transport.write_text("#!/bin/sh\nprintf 'SSHBIND_OK\\nfixture-host\\nfixture-user\\n'\n")
        transport.chmod(0o700)
        with patch.dict(os.environ, {'PATH': str(fake_bin) + os.pathsep + os.environ['PATH']}), \
                patch.object(self.ssh, '_self_script', return_value=str(SSHBIND)):
            self.ssh.console_ssh_create({'name': 'imported', 'host': '127.0.0.1',
                                         'private_key': original.read_text(), 'sudo': 'deny'})
        stored = Path(self.ssh.load_state()['servers']['imported']['key'])
        self.assertTrue(stored.is_file())
        self.assertEqual(stored.read_bytes(), original.read_bytes())
        self.assertTrue(self.ssh.console_ssh_get('imported')['usable'])
        self.assertEqual(self.policy.gate_ssh('imported', 'sudo true')['decision'], 'deny')

    def test_failed_ssh_create_does_not_enable_global_policy(self):
        for credentials in ({}, {'password': 'disposable-fixture'}):
            with self.subTest(credentials=bool(credentials)):
                with patch.object(self.ssh, '_run_self', return_value=(1, '', 'fixture failure')):
                    with self.assertRaises(Exception):
                        self.ssh.console_ssh_create(dict(name='failed', host='127.0.0.1', auth_type='key',
                                                         sudo='deny', **credentials))
                self.assertFalse(Path(self.policy.TOOL_PATHS['ssh']['policy']).exists())

    def test_partial_adopt_failure_retains_registered_key(self):
        saved = []
        def partial(argv, **kwargs):
            key = Path(argv[argv.index('--identity') + 1])
            state = self.ssh.load_state()
            state['servers']['partial'] = {'name': 'partial', 'key': str(key)}
            self.ssh.save_state(state)
            saved.append(key)
            return 1, '', 'fixture config write failed after registration'
        with patch.object(self.ssh, '_run_self', side_effect=partial):
            with self.assertRaises(Exception):
                self.ssh.console_ssh_create({'name': 'partial', 'host': '127.0.0.1',
                    'private_key': 'disposable-key-marker', 'sudo': 'deny'})
        self.assertTrue(saved[0].is_file())
        self.assertEqual(self.policy.gate_ssh('partial', 'sudo true')['decision'], 'deny')

    def test_policy_write_failure_does_not_change_database_connection(self):
        self.db.console_db_create({'alias': 'new', 'engine': 'sqlite', 'file': str(self.dbfile)})
        with patch.object(self.db, '_console_policy_put', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError):
                self.db.console_db_update('new', {'file': str(self.home / 'other.sqlite'),
                                                   'max_level': 'write'})
        self.assertEqual(self.db.console_db_get('new')['file'], str(self.dbfile))

    def test_version_respects_json_in_either_option_order(self):
        for args in (['--json', '--version'], ['--version', '--json']):
            proc = subprocess.run([str(DBBIND), *args], cwd=self.home,
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(proc.stdout.lstrip().startswith('{'), proc.stdout)
            self.assertEqual(json.loads(proc.stdout)['version'], self.db.VERSION)

    def test_ssh_console_uses_its_own_executable(self):
        with patch.object(self.ssh.shutil, 'which', return_value='/unrelated/sshbind'):
            self.assertEqual(Path(self.ssh._self_script()).resolve(), SSHBIND.resolve())


if __name__ == '__main__':
    unittest.main(verbosity=2)
