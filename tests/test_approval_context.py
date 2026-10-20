import importlib.util
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ApprovalContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {'HOME': self.tmp.name,
            'BINDCONSOLE_HOME': str(Path(self.tmp.name) / '.bindconsole')})
        self.env.start()
        self.addCleanup(self.env.stop)
        spec = importlib.util.spec_from_file_location('context_policy', ROOT / 'bindconsole/bindkit_policy.py')
        self.p = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.p)
        self.p.write_policy('ssh', {'version': 1, 'defaults': {'sudo': 'ask'},
                                  'servers': {'demo': {'allowed_users': ['app']}}})
        self.context = {'managed': True, 'target_user': 'root', 'target_uid': 0,
                        'command': 'id', 'connection': {'host': 'server.example.com',
                            'user': 'operator', 'port': 22, 'revision': 1}}

    def gate(self, command='id', context=None):
        self.assertIn('context', inspect.signature(self.p.gate_ssh).parameters,
                      'SSH gate must bind the execution identity/context')
        return self.p.gate_ssh('demo', command, context=context or self.context)

    def approve(self, result):
        self.p.approve('ssh', result['request_id'])

    def test_root_plan_requires_approval_even_without_sudo_text(self):
        self.assertEqual(self.gate()['decision'], 'ask')

    def test_allowlisted_ordinary_target_is_exempt_but_uid_zero_is_not(self):
        ordinary = dict(self.context, target_user='app', target_uid=1001, approval_exempt=True)
        self.assertEqual(self.gate(context=ordinary)['decision'], 'allow')
        disguised = dict(ordinary, target_uid=0)
        self.assertEqual(self.gate(context=disguised)['decision'], 'ask')

    def test_changed_connection_does_not_consume_prior_approval(self):
        first = self.gate()
        self.approve(first)
        changed = dict(self.context, connection=dict(self.context['connection'], revision=2))
        result = self.gate(context=changed)
        self.assertEqual(result['decision'], 'ask')
        self.assertNotEqual(first['request_id'], result['request_id'])

    def test_authentication_failure_releases_reserved_approval(self):
        first = self.gate()
        self.approve(first)
        permitted = self.gate()
        self.assertTrue(permitted.get('approval_lease'))
        self.p.finish_approval('ssh', permitted['consumed_approval'],
                               permitted['approval_lease'], started=False)
        retry = self.gate()
        self.assertEqual(retry['decision'], 'allow')
        self.assertTrue(retry.get('approval_lease'))

    def test_reserved_approval_is_not_audited_as_execution_consumed(self):
        first = self.gate()
        self.approve(first)
        permitted = self.gate()
        decisions = [row['decision'] for row in self.p.read_audit('ssh')]
        self.assertIn('reserve', decisions)
        self.assertNotIn('consume', decisions)
        self.p.finish_approval('ssh', first['request_id'], permitted['approval_lease'], started=None)
        self.assertEqual(self.p.get_approval('ssh', first['request_id'])['status'], 'consumed')

    def test_database_approval_binds_connection_and_policy(self):
        self.p.write_policy('db', {'version': 1, 'defaults': {'max_level': 'write', 'approval': {'write': True}}})
        sql = 'UPDATE items SET value=1'
        first = self.p.gate_db('demo', sql, 'mysql', 'demo', requested_write=True,
                               context={'connection': {'host': 'db.example.com', 'revision': 1}, 'operation': 'exec'})
        self.p.approve('db', first['request_id'])
        changed = self.p.gate_db('demo', sql, 'mysql', 'demo', requested_write=True,
                               context={'connection': {'host': 'db.example.com', 'revision': 2}, 'operation': 'exec'})
        self.assertEqual(changed['decision'], 'ask')
        self.assertNotEqual(first['request_id'], changed['request_id'])

    def test_concurrent_request_cannot_share_execution_lease(self):
        first = self.gate()
        self.approve(first)
        permitted = self.gate()
        blocked = self.gate()
        self.assertEqual(blocked['decision'], 'ask')
        self.assertEqual(blocked['request_id'], first['request_id'])
        self.assertEqual(len(self.p.list_approvals('ssh')), 1)
        self.p.finish_approval('ssh', first['request_id'], permitted['approval_lease'], started=True)
        self.assertEqual(self.p.get_approval('ssh', first['request_id'])['status'], 'consumed')

    def test_execution_lease_blocks_duplicate_after_authorization_expiry(self):
        first = self.gate()
        self.approve(first)
        permitted = self.gate()
        ap = self.p.get_approval('ssh', first['request_id'])
        ap['expires_at'] = self.p._iso(self.p._now() - self.p.timedelta(seconds=1))
        self.p._save_approval('ssh', ap)
        blocked = self.gate()
        self.assertTrue(blocked.get('busy'), blocked)
        self.assertEqual(blocked['request_id'], first['request_id'])
        self.assertEqual(len(self.p.list_approvals('ssh')), 1)
        self.p.finish_approval('ssh', first['request_id'], permitted['approval_lease'], started=None)

    def test_approval_lock_failure_cannot_decide_or_execute(self):
        first = self.gate()
        with patch('fcntl.flock', side_effect=OSError('synthetic lock failure')):
            with self.assertRaises(OSError):
                self.p.approve('ssh', first['request_id'])
            blocked = self.gate()
            self.assertEqual(blocked['decision'], 'deny')
        self.assertEqual(self.p.get_approval('ssh', first['request_id'])['status'], 'pending')

    def test_ai_compare_and_set_rejects_stale_request_or_policy(self):
        first = self.gate()
        self.assertIn('expected_fingerprint', inspect.signature(self.p.approve).parameters)
        with self.assertRaises(ValueError):
            self.p.approve('ssh', first['request_id'], expected_fingerprint='different')
        revision = self.p.policy_revision('ssh')
        self.p.write_policy('ssh', {'version': 1, 'defaults': {'sudo': 'deny'}})
        with self.assertRaises(ValueError):
            self.p.approve('ssh', first['request_id'], expected_policy_revision=revision)
        self.assertEqual(self.p.get_approval('ssh', first['request_id'])['status'], 'pending')

    def test_ai_decider_is_recorded_as_ai_in_audit(self):
        first = self.gate()
        self.p.approve('ssh', first['request_id'], decided_by='ai')
        entries = self.p.read_audit('ssh')
        decided = [x for x in entries if x.get('decision') == 'approve']
        self.assertEqual(decided[-1]['actor'], 'ai')


if __name__ == '__main__':
    unittest.main()
