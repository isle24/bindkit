"""Verified connection edits; passwords never enter persistent connection state."""
import copy
import fcntl
import os
import re
import tempfile
import uuid
from contextlib import contextmanager


class ConnectionError(RuntimeError):
    def __init__(self, message, code='INVALID_REQUEST'):
        super().__init__(message)
        self.code = code


def public_credential_status(server, vault=None):
    return {'has_key': bool(server.get('key') and os.path.isfile(server['key'])),
            'sudo_auth': server.get('sudo_auth', 'none'),
            'has_sudo_credential': bool(server.get('sudo_credential_ref')),
            'keychain': vault.status() if vault else None}


@contextmanager
def _lock(ssh_module):
    directory = os.path.dirname(ssh_module.STATE_FILE)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(os.path.join(directory, '.connections.lock'), flags, 0o600)
    try:
        os.fchmod(fd, 0o600); fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


def _validate(row, body):
    if 'name' in body or 'alias' in body:
        raise ConnectionError('Connection aliases cannot be renamed by a credential edit.')
    candidate = copy.deepcopy(row)
    for field in ('host', 'user'):
        if field in body:
            value = body[field]
            pattern = r'[A-Za-z0-9][A-Za-z0-9_.:\[\]%-]{0,252}' if field == 'host' else r'[A-Za-z_][A-Za-z0-9_.-]{0,63}'
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise ConnectionError('Invalid ' + field)
            candidate[field] = value
    if 'port' in body:
        try:
            if isinstance(body['port'], bool): raise ValueError()
            port = int(body['port'])
            if str(port) != str(body['port']) or not 1 <= port <= 65535: raise ValueError()
        except (ValueError, TypeError):
            raise ConnectionError('Port must be an integer between 1 and 65535.') from None
        candidate['port'] = port
    for field in ('private_key', 'login_password', 'sudo_password'):
        if field in body and (not isinstance(body[field], str) or not body[field] or '\x00' in body[field]):
            raise ConnectionError(field + ' must be nonempty text without NUL.')
    if any(c in body.get('sudo_password', '') for c in ('\n', '\r')):
        raise ConnectionError('Sudo passwords containing line breaks are unsupported.')
    if 'clear_sudo_password' in body and not isinstance(body['clear_sudo_password'], bool):
        raise ConnectionError('clear_sudo_password must be a boolean.')
    if body.get('clear_sudo_password'):
        if 'sudo_password' in body or body.get('sudo_auth') == 'keyring':
            raise ConnectionError('Cannot clear and replace or enable a sudo credential together.')
        body = dict(body, sudo_auth=body.get('sudo_auth', 'none'))
    mode = body.get('sudo_auth', 'keyring' if 'sudo_password' in body else candidate.get('sudo_auth', 'none'))
    if mode not in ('keyring', 'nopasswd', 'none'):
        raise ConnectionError('sudo_auth must be keyring, nopasswd or none.')
    if 'sudo_password' in body and mode != 'keyring':
        raise ConnectionError('A sudo password requires keyring authentication.')
    if mode == 'keyring' and not (body.get('sudo_password') or candidate.get('sudo_credential_ref')):
        raise ConnectionError('Configure a sudo password before enabling keyring authentication.')
    candidate['sudo_auth'] = mode
    if mode != 'keyring': candidate['sudo_credential_ref'] = None
    return candidate


def update_connection(ssh_module, name, body, vault=None):
    """Verify first, stage new secrets, then commit config/state under an edit lock.

    Old local and remote keys are retained. The login password is used solely for
    installing a replacement public key through the existing SSH authentication helper.
    Caller must validate any combined policy request before invoking this operation.
    """
    if not isinstance(body, dict): raise ConnectionError('Request must be a JSON object.')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name):
        raise ConnectionError('Invalid connection alias.')
    with _lock(ssh_module):
        state = ssh_module.load_state()
        old = state.get('servers', {}).get(name)
        if old is None: raise ConnectionError('Connection does not exist.', 'NOT_FOUND')
        candidate = _validate(old, body)
        clearing = bool(body.get('clear_sudo_password') and old.get('sudo_credential_ref'))
        if 'sudo_password' in body or clearing:
            if vault is None:
                from bindkit_vault import Vault
                vault = Vault()
            if not vault.status()['available']:
                raise ConnectionError('OS keyring unavailable; unlock or install the optional runtime.', 'VAULT_UNAVAILABLE')
        owned_paths = []; new_ref = None; committed = False; config_written = False
        cleared = False; previous_secret = None
        try:
            if 'private_key' in body:
                os.makedirs(ssh_module.KEYS_DIR, mode=0o700, exist_ok=True)
                fd, key = tempfile.mkstemp(prefix=name + '-rotation-', dir=ssh_module.KEYS_DIR)
                owned_paths.append(key)
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(body['private_key'].rstrip('\n') + '\n')
                candidate['key'] = key; candidate['certificate'] = None
                candidate['source'] = 'adopted'
            elif 'login_password' in body:
                os.makedirs(ssh_module.KEYS_DIR, mode=0o700, exist_ok=True)
                key_name = name + '-rotation-' + uuid.uuid4().hex
                owned_paths.extend([os.path.join(ssh_module.KEYS_DIR, key_name), os.path.join(ssh_module.KEYS_DIR, key_name + '.pub')])
                key, _ = ssh_module.gen_keypair(key_name)
                candidate['key'] = key; candidate['certificate'] = None
                candidate['source'] = 'generated'; candidate['key_type'] = 'ed25519'
            if owned_paths:
                pubkey = ssh_module.read_pubkey_for(candidate['key'])
                if not pubkey:
                    raise ConnectionError('Replacement private key is invalid or encrypted; provide a usable key.', 'KEY_VALIDATION_FAILED')
                candidate['fingerprint'] = ssh_module.fingerprint_of(pubkey)
                if 'login_password' in body:
                    auth = ssh_module.make_auth('password', password=body['login_password'])
                    installed, _ = ssh_module.install_pubkey(candidate['host'], candidate['user'], candidate.get('port', 22),
                                                            auth, pubkey, restrict=candidate.get('restrict', False))
                    if not installed:
                        raise ConnectionError('Unable to install the replacement public key with the supplied login credential.', 'AUTHENTICATION_FAILED')
            # Sudo-only edits do not need remote access. Any connection/key change does.
            connection_fields = ('host', 'user', 'port', 'private_key', 'login_password')
            if any(key in body for key in connection_fields):
                valid, _ = ssh_module.test_connection(candidate['host'], candidate['user'], candidate.get('port', 22),
                                                     candidate['key'], candidate.get('certificate'))
                if not valid:
                    raise ConnectionError('Replacement connection verification failed; the previous connection was retained.', 'CONNECTION_VERIFICATION_FAILED')
                candidate['installed'] = True
            if 'sudo_password' in body:
                new_ref = vault.new_ref('sudo')
                vault.set(new_ref, body['sudo_password'])
                candidate['sudo_credential_ref'] = new_ref
            if clearing:
                previous_secret = vault.get(old['sudo_credential_ref'])
                vault.delete(old['sudo_credential_ref'])
                cleared = True
            candidate['id'] = old.get('id') or str(uuid.uuid4())
            candidate['revision'] = int(old.get('revision', 0)) + 1
            candidate['name'] = name
            updated = copy.deepcopy(state); updated['servers'][name] = candidate
            # Roll back the derived SSH config if state persistence fails.
            config_written = True
            ssh_module.write_ssh_config(updated['servers'])
            ssh_module.save_state(updated)
            committed = True
        except (Exception, SystemExit) as exc:
            rollback_failed = False
            if cleared and previous_secret is not None:
                try: vault.set(old['sudo_credential_ref'], previous_secret)
                except Exception: rollback_failed = True
            if config_written:
                try: ssh_module.write_ssh_config(state['servers'])
                except (Exception, SystemExit): rollback_failed = True
            if rollback_failed:
                raise ConnectionError('Connection update failed and configuration or credential restoration failed; inspect the managed connection and keyring before retrying.', 'ROLLBACK_FAILED') from None
            if isinstance(exc, ConnectionError): raise
            raise ConnectionError('Connection update failed; previous connection state was retained.', 'CONNECTION_UPDATE_FAILED') from None
        finally:
            if not committed:
                if new_ref:
                    try: vault.delete(new_ref)
                    except Exception: pass
                for path in owned_paths:
                    try: os.unlink(path)
                    except FileNotFoundError: pass
        return {'ok': True, 'name': name, 'id': candidate['id'], 'revision': candidate['revision'],
                'changed': [field for field in ('host','user','port','private_key','login_password','sudo_auth','sudo_password','clear_sudo_password') if field in body],
                'credential_status': public_credential_status(candidate, vault)}
