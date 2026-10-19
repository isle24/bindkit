import importlib.util
import json
from pathlib import Path
import threading
import tempfile
import sys
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class LocalNetworkTests(unittest.TestCase):
    def kernel(self):
        sys.path.insert(0, str(ROOT / 'bindconsole'))
        import bindkit_console
        return bindkit_console

    def test_ip_console_binding_does_not_require_dns(self):
        bc = self.kernel()
        with tempfile.TemporaryDirectory() as home, \
                patch.object(bc.socket, 'getfqdn', side_effect=AssertionError('unexpected DNS')):
            server = bc.create_server('db', port=0, home=home, policy=False)
            try:
                self.assertEqual(server.server_name, '127.0.0.1')
                self.assertGreater(server.server_port, 0)
            finally:
                server.server_close()

    def test_local_interface_enumeration_does_not_require_dns(self):
        bc = self.kernel()
        with patch.object(bc.socket, 'getaddrinfo', side_effect=AssertionError('unexpected DNS')):
            self.assertIsInstance(bc._local_ipv4_addresses(), list)

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
        # Keep this transport fixture independent of the host's reverse-DNS setup.
        with patch('socket.getfqdn', return_value='127.0.0.1'):
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
