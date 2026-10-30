"""Memory-only SSH_ASKPASS transport for Unix OpenSSH clients.

Only the helper program and its private Unix socket are created on disk. The
login password or key passphrase is sent over the socket to the helper's stdout,
which OpenSSH consumes independently of the remote command's stdin.
"""

import os
import shlex
import shutil
import socket
import struct
import sys
import tempfile
import threading


MAX_SECRET_BYTES = 65536
_SOCKET_TIMEOUT = 0.2
_CLOSE_TIMEOUT = 2.0

# The length-prefixed protocol avoids returning a partial password if the broker
# closes during a response. This code and the socket path contain no credential.
_HELPER_CODE = '''import socket, struct, sys
def receive(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise OSError("Incomplete askpass response")
        result.extend(chunk)
    return result
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3.0)
        connection.connect(sys.argv[1])
        size = struct.unpack("!I", receive(connection, 4))[0]
        if size > %d:
            raise OSError("Invalid askpass response")
        secret = receive(connection, size)
    sys.stdout.buffer.write(secret)
    sys.stdout.buffer.write(b"\\n")
    sys.stdout.buffer.flush()
except (OSError, ValueError):
    sys.exit(1)
''' % MAX_SECRET_BYTES


class MemoryAskpass:
    """Own a short-lived broker; callers must close it or use a with block.

    Directory permissions protect the socket from other local users. Clearing
    our bytearray on close limits retention; Python cannot guarantee erasure of
    the original string supplied by the caller or copies held by OpenSSH.
    """

    def __init__(self, secret):
        if not isinstance(secret, str):
            raise TypeError('SSH password or passphrase must be text')
        if len(secret) > MAX_SECRET_BYTES or any(c in secret for c in '\x00\r\n'):
            raise ValueError('SSH password or passphrase contains invalid data or is too long')
        try:
            encoded = bytearray(secret, 'utf-8')
        except UnicodeEncodeError:
            raise ValueError('SSH password or passphrase must be valid UTF-8 text') from None
        if len(encoded) > MAX_SECRET_BYTES:
            encoded[:] = b'\x00' * len(encoded)
            raise ValueError('SSH password or passphrase is too long')

        self._secret = encoded
        self.dir = None
        self.askpass = None
        self._socket = None
        self._thread = None
        self._closed = False
        self._stop = threading.Event()
        self._close_lock = threading.Lock()
        try:
            self.dir = tempfile.mkdtemp(prefix='bk-ap-')
            os.chmod(self.dir, 0o700)
            socket_path = os.path.join(self.dir, 's')
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.settimeout(_SOCKET_TIMEOUT)
            self._socket.bind(socket_path)
            os.chmod(socket_path, 0o600)
            self._socket.listen(8)

            self.askpass = os.path.join(self.dir, 'askpass')
            # A shell wrapper permits Python executable paths containing spaces
            # without relying on PATH, PYTHONPATH, sitecustomize or user modules.
            script = '#!/bin/sh\nexec %s -I -c %s %s\n' % (
                shlex.quote(sys.executable), shlex.quote(_HELPER_CODE),
                shlex.quote(socket_path),
            )
            fd = os.open(self.askpass, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, 'w', encoding='utf-8') as helper:
                helper.write(script)
            self._thread = threading.Thread(
                target=self._serve, name='bindkit-askpass', daemon=True,
            )
            self._thread.start()
        except BaseException:
            self.close()
            raise

    def _serve(self):
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                if self._stop.is_set():
                    return
                try:
                    connection.settimeout(_SOCKET_TIMEOUT)
                    connection.sendall(struct.pack('!I', len(self._secret)))
                    connection.sendall(self._secret)
                except OSError:
                    # One abandoned helper must not break subsequent prompts.
                    continue

    def env(self):
        if self._closed:
            raise RuntimeError('SSH askpass broker has been closed')
        env = dict(os.environ)
        env['SSH_ASKPASS'] = self.askpass
        env['SSH_ASKPASS_REQUIRE'] = 'force'
        env['DISPLAY'] = env.get('DISPLAY') or ':0'
        return env

    def close(self):
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            if self._socket is not None:
                self._socket.close()
            if self._thread is not None and self._thread.ident is not None:
                self._thread.join(timeout=_CLOSE_TIMEOUT)
            self._secret[:] = b'\x00' * len(self._secret)
            self._secret.clear()
            if self.dir is not None:
                shutil.rmtree(self.dir, ignore_errors=True)
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError('SSH askpass broker did not stop')

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
