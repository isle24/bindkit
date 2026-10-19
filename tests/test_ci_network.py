import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class LocalNetworkTests(unittest.TestCase):
    def test_console_test_client_ignores_ambient_proxy(self):
        spec = importlib.util.spec_from_file_location('console_integration',
            ROOT / 'bindconsole/tests/policy/test_console_integration.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch('urllib.request.getproxies', return_value={'http': 'http://127.0.0.1:1'}), \
                    patch('urllib.request.proxy_bypass', return_value=False):
                client = mod.Client('http://127.0.0.1:%d' % server.server_port)
                status, data, _ = client.request('GET', '/api/status', timeout=2)
            self.assertEqual(status, 200)
            self.assertTrue(data['ok'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
