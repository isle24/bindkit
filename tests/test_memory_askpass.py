import os
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bindconsole'))
try:
    import bindkit_askpass as askpass
except ModuleNotFoundError:
    askpass = None


class MemoryAskpassTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='askpass-test-')
        self.addCleanup(temporary.cleanup)
        environ = patch.dict(os.environ, {'HOME': temporary.name})
        environ.start()
        self.addCleanup(environ.stop)
        self.assertIsNotNone(askpass, 'The memory-backed SSH_ASKPASS module is missing')

    def invoke(self, handle, prompt='Password:'):
        return subprocess.run(
            [handle.env()['SSH_ASKPASS'], prompt], env=handle.env(),
            input=b'unrelated command stdin', capture_output=True, timeout=5,
        )

    def test_actual_helper_preserves_utf8_special_characters_and_whitespace(self):
        secret = '  fake-口令-%-$-\'"-`-\\-$(exit 42)  '
        with askpass.MemoryAskpass(secret) as handle:
            for prompt in ('Password:', 'Passphrase:', '再次输入:'):
                result = self.invoke(handle, prompt)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, secret.encode('utf-8') + b'\n')
                self.assertEqual(result.stderr, b'')

    def test_secret_never_appears_in_files_env_or_helper_argv(self):
        secret = 'synthetic-UNIQUE-%-$-password-67391'
        with askpass.MemoryAskpass(secret) as handle:
            env = handle.env()
            self.assertEqual(env['SSH_ASKPASS_REQUIRE'], 'force')
            self.assertTrue(env['DISPLAY'])
            self.assertNotIn(secret, repr(env))
            self.assertEqual(stat.S_IMODE(os.stat(handle.dir).st_mode), 0o700)
            sockets, scripts = [], []
            for path in Path(handle.dir).iterdir():
                if path.is_socket():
                    sockets.append(path)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                else:
                    scripts.append(path)
                    contents = path.read_text()
                    self.assertNotIn(secret, contents)
                    self.assertNotIn(secret, repr(shlex.split(contents)))
                    self.assertTrue(os.access(path, os.X_OK))
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(len(sockets), 1)
            self.assertEqual(len(scripts), 1)
            self.assertFalse(hasattr(handle, 'secret_path'))

    def test_close_removes_socket_and_helper_and_stops_thread_promptly(self):
        handle = askpass.MemoryAskpass('synthetic-secret')
        directory = Path(handle.dir)
        thread = handle._thread
        self.assertTrue(thread.is_alive())
        started = time.monotonic()
        handle.close()
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(directory.exists())
        self.assertFalse(thread.is_alive())
        handle.close()
        with self.assertRaises(RuntimeError):
            handle.env()

    def test_context_cleanup_when_command_raises(self):
        with self.assertRaisesRegex(RuntimeError, 'synthetic failure'):
            with askpass.MemoryAskpass('synthetic-secret') as handle:
                directory = Path(handle.dir)
                raise RuntimeError('synthetic failure')
        self.assertFalse(directory.exists())
        self.assertFalse(handle._thread.is_alive())

    def test_invalid_secrets_are_rejected_before_any_resources_are_created(self):
        for secret in ('fake\nsecret', 'fake\rsecret', 'fake\0secret',
                       '字' * (askpass.MAX_SECRET_BYTES // 3 + 1)):
            with self.subTest(secret_length=len(secret)):
                with patch.object(askpass.tempfile, 'mkdtemp') as mkdir:
                    with self.assertRaises(ValueError) as error:
                        askpass.MemoryAskpass(secret)
                    mkdir.assert_not_called()
                self.assertNotIn(secret, str(error.exception))

    def test_maximum_size_secret_roundtrips(self):
        secret = 'x' * askpass.MAX_SECRET_BYTES
        with askpass.MemoryAskpass(secret) as handle:
            result = self.invoke(handle)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, secret.encode() + b'\n')

    def test_constructor_failure_removes_partial_resources(self):
        real_mkdtemp = tempfile.mkdtemp
        directories = []

        def tracked_mkdtemp(*args, **kwargs):
            directory = real_mkdtemp(*args, **kwargs)
            directories.append(Path(directory))
            return directory

        for target in ('socket.socket.bind', 'threading.Thread.start'):
            with self.subTest(stage=target):
                with patch.object(askpass.tempfile, 'mkdtemp', side_effect=tracked_mkdtemp):
                    with patch('bindkit_askpass.' + target, side_effect=OSError('synthetic failure')):
                        with self.assertRaisesRegex(OSError, 'synthetic failure'):
                            askpass.MemoryAskpass('synthetic-secret')
                self.assertFalse(directories[-1].exists())

    def test_disconnected_client_does_not_break_following_requests(self):
        with askpass.MemoryAskpass('synthetic-secret') as handle:
            socket_path = next(path for path in Path(handle.dir).iterdir() if path.is_socket())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
            result = self.invoke(handle)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'synthetic-secret\n')

    def test_slow_client_cannot_hold_broker_open_after_close(self):
        handle = askpass.MemoryAskpass('x' * askpass.MAX_SECRET_BYTES)
        self.addCleanup(handle.close)
        handle._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        socket_path = next(path for path in Path(handle.dir).iterdir() if path.is_socket())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(socket_path))
            self.assertEqual(client.recv(4), struct.pack('!I', askpass.MAX_SECRET_BYTES))
            started = time.monotonic()
            handle.close()
            self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(handle._thread.is_alive())
        self.assertFalse(Path(handle.dir).exists())

    def test_shell_wrapper_quotes_interpreter_and_socket_paths(self):
        with tempfile.TemporaryDirectory(prefix='ap path-') as temporary:
            interpreter = Path(temporary) / 'python $ \' quoted'
            interpreter.symlink_to(sys.executable)
            # Use a short /tmp path so this also works with macOS's small Unix
            # socket address limit even when the default TMPDIR is already long.
            with tempfile.TemporaryDirectory(prefix="ap ' $ ", dir='/tmp') as ipc_root:
                with patch.object(askpass.sys, 'executable', str(interpreter)):
                    with patch.object(askpass.tempfile, 'tempdir', ipc_root):
                        with askpass.MemoryAskpass('synthetic-secret') as handle:
                            result = self.invoke(handle)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stdout, b'synthetic-secret\n')

    def test_helper_rejects_incomplete_and_oversize_responses_without_output(self):
        responses = (b'\0\0', struct.pack('!I', askpass.MAX_SECRET_BYTES + 1),
                     struct.pack('!I', 100) + b'partial-secret')
        for response in responses:
            with self.subTest(response_length=len(response)):
                with tempfile.TemporaryDirectory(prefix='ap-bad-') as temporary:
                    socket_path = str(Path(temporary) / 's')
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                        server.bind(socket_path)
                        server.listen(1)
                        server.settimeout(5)

                        def respond():
                            client, _ = server.accept()
                            with client:
                                client.sendall(response)

                        thread = threading.Thread(target=respond)
                        thread.start()
                        try:
                            result = subprocess.run(
                                [sys.executable, '-I', '-c', askpass._HELPER_CODE, socket_path],
                                capture_output=True, timeout=5,
                            )
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(result.stdout, b'')
                            self.assertEqual(result.stderr, b'')
                        finally:
                            thread.join(timeout=5)
                        self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
