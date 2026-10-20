"""OS credential storage. There is deliberately no file-based fallback."""
import re
import uuid


class VaultError(RuntimeError):
    def __init__(self, message, code='VAULT_UNAVAILABLE'):
        super().__init__(message)
        self.code = code


class Vault:
    SERVICE = 'org.bindkit.credentials.v1'

    def __init__(self, backend=None):
        injected = backend is not None
        self._backend = backend
        self._reason = None
        if backend is None:
            try:
                import keyring
                self._backend = keyring.get_keyring()
            except Exception:
                self._reason = 'OS keyring unavailable; install the optional BindKit keyring runtime.'
        if self._backend is not None:
            kind = type(self._backend).__module__ + '.' + type(self._backend).__name__
            try:
                unsafe = any(x in kind.lower() for x in ('keyrings.alt', 'plaintext', 'fail.', 'null.', 'chainer'))
                os_backends = ('keyring.backends.macOS.', 'keyring.backends.SecretService.',
                               'keyring.backends.libsecret.', 'keyring.backends.kwallet.',
                               'keyring.backends.Windows.')
                if unsafe or self._backend.priority <= 0 or (not injected and not kind.startswith(os_backends)):
                    self._reason = 'A secure OS keyring backend is required.'
            except Exception:
                self._reason = 'OS keyring is locked or unavailable.'

    @staticmethod
    def new_ref(prefix='credential'):
        if not isinstance(prefix, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', prefix):
            raise ValueError('Invalid credential reference prefix')
        return 'bindkit:' + prefix + ':' + uuid.uuid4().hex

    def status(self):
        return {'available': self._backend is not None and self._reason is None,
                'backend': (type(self._backend).__module__ + '.' + type(self._backend).__name__) if self._backend else None,
                'reason': self._reason}

    def _call(self, operation, ref, *args):
        if not self.status()['available']:
            raise VaultError(self._reason or 'OS keyring unavailable')
        if not isinstance(ref, str) or not ref or len(ref) > 256:
            raise ValueError('Invalid credential reference')
        try:
            return getattr(self._backend, operation)(self.SERVICE, ref, *args)
        except Exception:
            # Backends may include secret values in exceptions. Never forward those.
            raise VaultError('OS keyring is locked or unavailable; unlock it and retry.',
                             'VAULT_LOCKED_OR_UNAVAILABLE') from None

    def get(self, ref):
        return self._call('get_password', ref)

    def set(self, ref, value):
        if not isinstance(value, str) or not value or '\x00' in value:
            raise ValueError('Credential must be a nonempty string without NUL')
        self._call('set_password', ref, value)

    def delete(self, ref):
        if self.get(ref) is not None:
            self._call('delete_password', ref)
