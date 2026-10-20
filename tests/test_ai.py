import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindconsole'))


class FakeVault:
    def __init__(self): self.values = {}
    def status(self): return {'available': True, 'backend': 'fake', 'reason': None}
    def get(self, ref): return self.values.get(ref)
    def set(self, ref, value): self.values[ref] = value
    def delete(self, ref): self.values.pop(ref, None)


class FakePolicy:
    def __init__(self):
        self.data = {'max_level': 'read'}
        self.ap = {'id': 'apr_test', 'status': 'pending', 'fingerprint': 'abc', 'alias': 'lab'}
        self.calls = []
    def read_policy(self, tool): return {'data': self.data, 'corrupt': False}
    def get_approval(self, tool, rid): return copy.deepcopy(self.ap)
    def approve(self, tool, rid, **kwargs):
        if self.ap['status'] != 'pending': raise ValueError('already decided')
        self.calls.append(kwargs); self.ap['status'] = 'approved'; return dict(self.ap)
    def reject(self, tool, rid, **kwargs):
        if self.ap['status'] != 'pending': raise ValueError('already decided')
        self.calls.append(kwargs); self.ap['status'] = 'denied'; return dict(self.ap)


class FakeProvider:
    def __init__(self): self.response = {'decision': 'approve', 'reason': 'safe'}; self.payloads = []; self.hook = None
    def review(self, payload, timeout):
        self.payloads.append(payload)
        if self.hook: self.hook()
        if isinstance(self.response, Exception): raise self.response
        return self.response
    def list_models(self, timeout): return ['synthetic']
    def test_connection(self, timeout): return {'connected': True}


class AITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {'HOME': self.tmp.name, 'BINDCONSOLE_HOME': self.tmp.name + '/console'})
        self.env.start()
        self.addCleanup(self.env.stop); self.addCleanup(self.tmp.cleanup)
        self.assertIsNotNone(importlib.util.find_spec('bindkit_ai'), 'AI review module must exist')
        import bindkit_ai
        self.ai = bindkit_ai
        self.vault = FakeVault(); self.provider = FakeProvider(); self.policy = FakePolicy()
        self.c = self.ai.ReviewController(home=Path(self.tmp.name) / 'ai', vault=self.vault, provider=self.provider)
        self.ctx = {'fingerprint': 'abc', 'policy_revision': self.ai.policy_revision(self.policy, 'ssh'), 'operation': 'exec', 'command': 'id', 'resource': {'alias': 'lab'}, 'target_user': 'root', 'target_uid': 0, 'effective_level': 'read', 'hard_allowed': True, 'protected': False}
    def enable(self, **kwargs):
        body = {'mode': 'auto', 'scopes': {'ssh': ['lab'], 'db': []}, 'model': 'synthetic'}; body.update(kwargs)
        return self.c.save_config(body)
    def review(self, **kwargs): return self.c.review('ssh', 'apr_test', self.ctx, self.policy, **kwargs)
    def test_off_is_default_and_does_not_call_provider(self):
        self.assertEqual(self.c.get_config()['mode'], 'off')
        self.assertEqual(self.review()['decision'], 'human'); self.assertFalse(self.provider.payloads)
    def test_keychain_only_and_public_config_never_returns_secret(self):
        result = self.enable(api_key='synthetic-secret')
        self.assertTrue(result['has_api_key'])
        self.assertNotIn('synthetic-secret', json.dumps(result))
        self.assertNotIn('synthetic-secret', (self.c.home / 'config.json').read_text())
        self.assertEqual(list(self.vault.values.values()), ['synthetic-secret'])
        self.c.save_config({'clear_api_key': True}); self.assertFalse(self.vault.values)
    def test_auto_one_use_bounded_ttl(self):
        self.enable(ttl_s=300)
        self.assertEqual(self.review()['decision'], 'approve')
        self.assertEqual(self.policy.calls[0]['consumes'], 1)
        self.assertEqual(self.policy.calls[0]['ttl_s'], 300)
        self.assertEqual(self.policy.calls[0]['decided_by'], 'ai')
        self.assertEqual(self.policy.calls[0]['expected_fingerprint'], 'abc')
        self.assertEqual(self.review()['decision'], 'human')
    def test_suggest_never_changes_approval(self):
        self.enable(mode='suggest'); result = self.review()
        self.assertEqual(result['decision'], 'human'); self.assertEqual(result['suggestion'], 'approve')
        self.assertFalse(self.policy.calls)
    def test_scope_hard_deny_and_protected_fail_closed(self):
        self.enable()
        for change in ({'hard_allowed': False}, {'protected': True}, {'resource': {'alias': 'other'}}, {'operation': 'policy_update'}):
            with self.subTest(change=change):
                old = self.ctx; self.ctx = dict(old, **change)
                self.assertEqual(self.review()['decision'], 'human'); self.ctx = old
        self.assertFalse(self.provider.payloads)
    def test_provider_invalid_or_exception_goes_human(self):
        self.enable()
        for output in ({'decision': 'approve', 'reason': 'x', 'ttl': 999}, {'decision': 'allow', 'reason': 'x'}, {'decision': 'approve'}, RuntimeError('SECRET')):
            self.provider.response = output
            result = self.review(); self.assertEqual(result['decision'], 'human'); self.assertNotIn('SECRET', json.dumps(result))
        self.assertFalse(self.policy.calls)
    def test_policy_request_manual_decision_and_config_changes_during_network(self):
        self.enable()
        for hook in (lambda: self.policy.data.update(x=1), lambda: self.policy.ap.update(fingerprint='changed'), lambda: self.policy.ap.update(status='denied'), lambda: self.c.save_config({'mode': 'off'})):
            self.policy = FakePolicy(); self.enable(); self.provider.hook = hook
            self.assertEqual(self.review()['decision'], 'human')
            self.assertFalse(self.policy.calls)
    def test_timeout_never_commits_late_result(self):
        self.enable(); self.provider.hook = lambda: time.sleep(.12)
        self.assertEqual(self.review(timeout=.02)['decision'], 'human')
        time.sleep(.15); self.assertFalse(self.policy.calls)
    def test_redaction_and_allowlisted_context_only(self):
        self.enable(); self.ctx.update(command="PASSWORD='top-secret' curl -H 'Authorization: Bearer bearer-secret'", password='field-secret', chat_history=['chat-secret'])
        self.review(); text = json.dumps(self.provider.payloads)
        for secret in ('top-secret', 'bearer-secret', 'field-secret', 'chat-secret'):
            self.assertNotIn(secret, text)
    def test_models_and_test_use_injected_provider(self):
        self.assertEqual(self.c.list_models()['models'], ['synthetic'])
        self.assertTrue(self.c.test_connection()['connected'])

    def test_queue_deduplicates_and_persists_only_redacted_bounded_jobs(self):
        self.enable(); self.ctx['command'] = 'password=synthetic-secret id'
        first = self.c.enqueue('ssh', 'apr_test', self.ctx)
        self.assertEqual(first, self.c.enqueue('ssh', 'apr_test', self.ctx))
        self.assertNotIn(b'synthetic-secret', (self.c.home / 'jobs.sqlite').read_bytes())
        self.assertEqual((self.c.home / 'jobs.sqlite').stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.c.process_one(self.policy))
        self.assertEqual(self.c.job_result(first)['decision'], 'approve')
        self.assertFalse(self.c.process_one(self.policy))
    def test_cancel_during_model_call_prevents_approval(self):
        self.enable(); job = self.c.enqueue('ssh', 'apr_test', self.ctx)
        self.provider.hook = lambda: self.c.cancel(job)
        self.c.process_one(self.policy)
        self.assertFalse(self.policy.calls)
        self.assertEqual(self.c.job_result(job)['decision'], 'human')
    def test_expired_job_never_calls_provider(self):
        self.enable(); job = self.c.enqueue('ssh', 'apr_test', self.ctx, lifetime=.01)
        time.sleep(.02); self.c.process_one(self.policy)
        self.assertFalse(self.provider.payloads)
        self.assertEqual(self.c.job_result(job)['decision'], 'human')
    def test_queue_bound_and_invalid_request_id(self):
        self.enable()
        with self.assertRaises(ValueError): self.c.enqueue('ssh', '../bad', self.ctx)
        huge = dict(self.ctx, command='x' * 20000)
        with self.assertRaises(ValueError): self.c.enqueue('ssh', 'apr_test', huge)
    def test_single_worker_start_stop_in_temporary_home(self):
        first = self.c.service_start()
        self.addCleanup(self.c.service_stop)
        self.assertTrue(first['running'])
        second = self.c.service_start()
        self.assertEqual(first['pid'], second['pid'])
        self.assertTrue(self.c.service_status()['running'])
        self.assertFalse(self.c.service_stop()['running'])

    def test_queue_has_a_hard_capacity(self):
        for index in range(256): self.c.enqueue('ssh', 'apr_' + str(index), self.ctx)
        with self.assertRaises(ValueError): self.c.enqueue('ssh', 'apr_overflow', self.ctx)
    def test_expired_lease_is_not_replayed(self):
        self.enable(); job = self.c.enqueue('ssh', 'apr_test', self.ctx)
        with self.c._db() as db:
            db.execute("UPDATE jobs SET state='running', lease='lost', lease_until=?", (time.time() - 1,)); db.commit()
        self.assertFalse(self.c.process_one(self.policy))
        self.assertFalse(self.provider.payloads)
        self.assertEqual(self.c.job_result(job)['decision'], 'human')
    def test_reject_is_atomic_and_one_decision_only(self):
        self.enable(); self.provider.response = {'decision': 'reject', 'reason': 'risky'}
        self.assertEqual(self.review()['decision'], 'reject')
        self.assertEqual(self.policy.ap['status'], 'denied')
        self.assertEqual(self.review()['decision'], 'human')
    def test_configuration_validation_rejects_scope_and_plaintext_endpoint_credentials(self):
        for body in ({'scopes': {'ssh': ['*'], 'db': []}}, {'base_url': 'https://user:secret@example.invalid/v1'}, {'base_url': 'http://remote.invalid/v1'}, {'key_ref': 'foreign'}, {'ttl_s': 500}):
            with self.subTest(body=body), self.assertRaises(ValueError): self.c.save_config(body)
    def test_sdk_contract_uses_bounded_no_tools_request(self):
        from types import SimpleNamespace
        calls = {}
        class Client:
            def __init__(self, **kwargs):
                calls['client'] = kwargs
                self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))
                self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id='synthetic')]), retrieve=lambda model: None)
            def with_options(self, **kwargs): calls['options'] = kwargs; return self
            def create(self, **kwargs):
                calls['request'] = kwargs
                calls['probe'] = 'chat'
                return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='{"decision":"human","reason":"uncertain"}'))])
        self.vault.set('ref', 'test-key')
        with mock.patch.dict(sys.modules, {'openai': SimpleNamespace(OpenAI=Client)}):
            provider = self.ai.OpenAIProvider({'key_ref': 'ref', 'base_url': 'https://example.invalid/v1', 'model': 'synthetic'}, self.vault)
            self.assertEqual(provider.list_models(3), ['synthetic'])
            self.assertTrue(provider.test_connection(3)['connected'])
            self.assertIn('chat', calls['probe'])
            self.assertEqual(provider.review({'operation': 'exec'}, 3)['decision'], 'human')
        self.assertEqual(calls['client']['max_retries'], 0)
        self.assertNotIn('tools', calls['request'])
        self.assertEqual(len(calls['request']['messages']), 2)
        self.assertEqual(calls['request']['response_format'], {'type': 'json_object'})
        self.assertEqual(calls['request']['max_tokens'], 300)
    def test_synthetic_provider_child_process_completes_real_queue(self):
        import subprocess
        self.enable(); job = self.c.enqueue('ssh', 'apr_test', self.ctx)
        script = """import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from test_ai import FakeVault, FakeProvider, FakePolicy
from bindkit_ai import ReviewController
controller = ReviewController(home=sys.argv[3], vault=FakeVault(), provider=FakeProvider())
assert controller.process_one(FakePolicy())
"""
        result = subprocess.run([sys.executable, '-c', script, str(ROOT / 'bindconsole'), str(ROOT / 'tests'), str(self.c.user_home)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.c.job_result(job)['decision'], 'approve')

    def test_config_update_is_serialized_with_final_approval_commit(self):
        self.enable(); finished = threading.Event(); observed = []
        original = self.policy.approve
        thread = threading.Thread(target=lambda: (self.c.save_config({'mode': 'off'}), finished.set()))
        def approve(*args, **kwargs):
            thread.start(); observed.append(finished.wait(.05))
            return original(*args, **kwargs)
        self.policy.approve = approve
        self.review(); thread.join(2)
        self.assertEqual(observed, [False], 'config changes must not interleave final approval validation and commit')
        self.assertTrue(finished.is_set())

    def test_explicit_console_home_and_real_policy_cas(self):
        console_home = Path(self.tmp.name) / 'custom-console'
        controller = self.ai.ReviewController(home=self.tmp.name, console_home=console_home, vault=self.vault, provider=self.provider)
        self.assertEqual(controller.home, console_home / 'ai')
        controller.save_config({'mode': 'auto', 'scopes': {'ssh': ['lab'], 'db': []}, 'model': 'synthetic'})
        spec = importlib.util.spec_from_file_location('isolated_ai_policy', ROOT / 'bindconsole' / 'bindkit_policy.py')
        policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
        policy.write_policy('ssh', {'version': 1})
        approval = policy._create_approval('ssh', 'lab', 'sudo', 'id', 'abc', 120, 'ai')
        context = dict(self.ctx, policy_revision=self.ai.policy_revision(policy, 'ssh'))
        result = controller.review('ssh', approval['id'], context, policy)
        self.assertEqual(result['decision'], 'approve')
        saved = policy.get_approval('ssh', approval['id'])
        self.assertEqual(saved['decided_by'], 'ai')
        self.assertEqual(saved['consumes_left'], 1)


if __name__ == '__main__': unittest.main()
