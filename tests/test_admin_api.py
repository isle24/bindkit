import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindconsole'))
sys.path.insert(0, str(ROOT / 'bindconsole/tests/backend'))
import bindkit_console as bc
import bindkit_ai as ai
from test_console import TestClient


class FakeVault:
    def __init__(self): self.values = {}
    def status(self): return {'available': True, 'backend': 'test-only', 'reason': None}
    def set(self, ref, value): self.values[ref] = value
    def get(self, ref): return self.values.get(ref)
    def delete(self, ref): self.values.pop(ref, None)


class AdminAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bindkit-admin-test-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.created = []
        self.items = [{'name': 'existing', 'host': 'existing.example.com', 'user': 'ops', 'port': 22}]
        def create(body):
            self.created.append(dict(body))
            if body['name'] == 'failure':
                raise ValueError('synthetic error with ' + body.get('password', ''))
            self.items.append({k: body[k] for k in ('name', 'host', 'user', 'port')})
            return {'ok': True, 'name': body['name']}
        handlers = {'resource': 'servers', 'list': lambda: {'items': self.items},
                    'create': create, 'users': lambda name: {'users': [{'name': 'app', 'uid': 1001, 'sensitive': False}]}}
        self.server = bc.create_server('ssh', port=0, home=str(self.home), handlers=handlers, policy=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.client = TestClient(self.server.server_address[1])
        self.controller = ai.ReviewController(home=self.home, vault=FakeVault())
        self.server.app.ai_controller = self.controller

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)

    def login(self):
        self.assertEqual(self.client.post('/api/setup', {'password': 'Synthetic-test-only-123'}).status, 201)
        response = self.client.post('/api/login', {'password': 'Synthetic-test-only-123'})
        self.assertEqual(response.status, 200)
        self.client.csrf = response.data['csrf_token']

    def preview(self, names=('demo',), extra=''):
        content = '\n'.join('Host %s\n HostName %s.example.com\n User ops\n%s' % (n, n, extra) for n in names)
        return self.client.post('/api/imports/preview', {'format': 'openssh', 'files': [
            {'name': 'config', 'content': base64.b64encode(content.encode()).decode()}]})

    def test_new_routes_require_session_and_csrf(self):
        for method, url in [('GET', '/api/ai/config'), ('POST', '/api/ai/service/start'),
                            ('POST', '/api/imports/preview'), ('GET', '/api/servers/existing/users')]:
            self.assertEqual(self.client.request(method, url).status, 401)
        self.login()
        self.assertEqual(self.client.post('/api/imports/preview', {}, csrf=None).status, 403)
        self.assertEqual(self.client.put('/api/ai/config', {}, csrf=None).status, 403)
        self.assertEqual(self.client.get('/api/servers/existing/users').data['users'][0]['uid'], 1001)

    def test_import_is_preview_first_and_credentials_are_write_only(self):
        self.login()
        response = self.preview(extra=' ProxyCommand echo untrusted-import-command')
        self.assertEqual(response.status, 200, response.text)
        self.assertEqual(self.created, [])
        preview = response.data
        item = preview['items'][0]
        self.assertTrue(item['requires_credentials'])
        result = self.client.post('/api/imports/commit', {'preview_id': preview['preview_id'], 'items': [
            {'id': item['id'], 'name': 'renamed', 'host': 'attacker.example.com', 'login_password': 'synthetic-import-secret'}]})
        self.assertEqual(result.status, 200, result.text)
        self.assertEqual(result.data['imported'], 1)
        self.assertEqual(self.created[0]['host'], 'demo.example.com')
        self.assertEqual(self.created[0]['password'], 'synthetic-import-secret')
        self.assertNotIn('synthetic-import-secret', result.text)
        self.assertNotIn('untrusted-import-command', result.text)
        replay = self.client.post('/api/imports/commit', {'preview_id': preview['preview_id'], 'items': [
            {'id': item['id'], 'name': 'again', 'login_password': 'synthetic-import-secret'}]})
        self.assertEqual(replay.status, 409)
        self.assertEqual(len(self.created), 1)

    def test_import_duplicates_expiry_and_failed_rows_are_safe(self):
        self.login()
        preview = self.preview(('first', 'second')).data
        rows = preview['items']
        duplicate = self.client.post('/api/imports/commit', {'preview_id': preview['preview_id'], 'items': [
            {'id': rows[0]['id'], 'name': 'same', 'login_password': 'synthetic'},
            {'id': rows[1]['id'], 'name': 'same', 'login_password': 'synthetic'}]})
        self.assertEqual(duplicate.status, 400)
        self.assertEqual(self.created, [])
        result = self.client.post('/api/imports/commit', {'preview_id': preview['preview_id'], 'items': [
            {'id': rows[0]['id'], 'name': 'existing', 'login_password': 'synthetic'},
            {'id': rows[1]['id'], 'name': 'failure', 'login_password': 'synthetic-failure-secret'}]})
        self.assertEqual((result.data['imported'], result.data['failed']), (0, 2))
        self.assertNotIn('synthetic-failure-secret', result.text)
        self.assertEqual(len(self.created), 1)
        expired = self.preview().data
        with patch('bindkit_admin.time.time', return_value=time.time() + 601):
            result = self.client.post('/api/imports/commit', {'preview_id': expired['preview_id'], 'items': []})
        self.assertEqual(result.status, 409)

    def test_invalid_base64_never_reaches_parser_or_state(self):
        self.login()
        response = self.client.post('/api/imports/preview', {'files': [{'name': 'x.xsh', 'content': '!!!'}]})
        self.assertEqual(response.status, 400)
        self.assertEqual(self.created, [])

    def test_import_without_username_never_defaults_to_root(self):
        self.login()
        preview = self.client.post('/api/imports/preview', {'format': 'openssh', 'files': [
            {'name': 'config', 'content': base64.b64encode(b'Host missing-user\n HostName server.example.com\n').decode()}]}).data
        row = {'id': preview['items'][0]['id'], 'login_password': 'synthetic'}
        result = self.client.post('/api/imports/commit', {'preview_id': preview['preview_id'], 'items': [row]})
        self.assertEqual((result.data['imported'], result.data['failed']), (0, 1))
        self.assertEqual(self.created, [])
        row['user'] = 'operator'
        result = self.client.post('/api/imports/commit', {'preview_id': preview['preview_id'], 'items': [row]})
        self.assertEqual(result.data['imported'], 1)
        self.assertEqual(self.created[0]['user'], 'operator')

    def test_ai_public_config_never_returns_key_or_reference(self):
        self.login()
        saved = self.client.put('/api/ai/config', {'api_key': 'synthetic-model-secret', 'model': 'test-model',
                   'scopes': {'ssh': ['existing'], 'db': []}, 'mode': 'auto'})
        self.assertEqual(saved.status, 200, saved.text)
        self.assertTrue(saved.data['has_api_key'])
        public = self.client.get('/api/ai/config')
        self.assertNotIn('synthetic-model-secret', public.text)
        self.assertNotIn('key_ref', public.text)
        failed = self.client.put('/api/ai/config', {'bad_field': 'synthetic-model-secret'})
        self.assertEqual(failed.status, 400)
        self.assertNotIn('synthetic-model-secret', failed.text)
        self.assertEqual(self.client.get('/api/ai/service/status').status, 200)
        self.assertEqual(self.client.post('/api/ai/test').data['connected'], False)

    def test_lan_ai_connection_can_be_saved_through_http_api(self):
        self.login()
        response = self.client.put('/api/ai/config', {'base_url': 'http://192.168.50.23:18000/v1',
            'model': 'synthetic', 'api_key': 'synthetic-secret', 'mode': 'off'})
        self.assertEqual(response.status, 200, response.text)
        self.assertTrue(response.data['has_api_key'])
        self.assertNotIn('synthetic-secret', response.text)

    def test_endpoint_error_is_specific_and_does_not_blame_keychain(self):
        self.login()
        response = self.client.put('/api/ai/config', {'base_url': 'http://example.invalid/v1', 'api_key': 'synthetic-secret'})
        self.assertEqual(response.status, 400)
        self.assertEqual(response.error_code, 'AI_ENDPOINT_HTTPS_REQUIRED')
        self.assertNotIn('钥匙串', response.error['message'])
        self.assertNotIn('synthetic-secret', response.text)

    def test_audit_http_pages_filter_and_snapshot_rotation(self):
        self.login()
        path = self.home / '.bindconsole/audit.log'
        records = [{'tool': 'ssh', 'actor': 'ai' if n % 2 else 'web', 'decision': 'allow', 'n': n} for n in range(1307)]
        path.write_text(''.join(json.dumps(r) + '\n' for r in records))
        first = self.client.get('/api/audit?tool=ssh&page_size=200&page=1').data
        self.assertEqual(first['total'], 1307)
        self.assertEqual(first['entries'][0]['n'], 1306)
        with path.open('a') as stream: stream.write(json.dumps({'n': 1307, 'tool': 'ssh'}) + '\n')
        page = self.client.get('/api/audit?tool=ssh&page_size=200&page=7&snapshot=' + first['snapshot']).data
        self.assertEqual((page['total'], len(page['entries'])), (1307, 107))
        filtered = self.client.get('/api/audit?tool=ssh&actor=ai&page_size=25').data
        self.assertEqual(filtered['total'], 653)
        path.write_text('{"tool":"ssh","n":9999}\n')
        self.assertEqual(self.client.get('/api/audit?tool=ssh&snapshot=' + first['snapshot']).status, 409)
        self.assertEqual(self.client.get('/api/audit?page=0').status, 400)


if __name__ == '__main__': unittest.main()
