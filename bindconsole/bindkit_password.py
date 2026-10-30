"""Password SSH connections with keychain references and no key installation."""
import copy
from contextlib import contextmanager
from datetime import datetime
import re
import uuid

from bindkit_connections import ConnectionError


def is_password(server):
    mode = server.get('auth_type')
    if mode is not None:
        return mode == 'password'
    return not server.get('key') and bool(server.get('login_credential_ref') or server.get('encrypted_login_ref'))


def _login_secret(server, vault):
    from bindkit_pending import _vault
    ref = server.get('login_credential_ref')
    if not ref:
        raise ConnectionError('Provide a login password or unlock the saved imported credential.', 'NEEDS_CREDENTIAL')
    vault = _vault(vault)
    try:
        secret = vault.get(ref)
    except Exception:
        raise ConnectionError('Unlock the OS keyring and retry password authentication.', 'VAULT_UNAVAILABLE') from None
    if not isinstance(secret, str) or not secret or any(c in secret for c in ('\x00', '\n', '\r')):
        raise ConnectionError('The saved login credential is unavailable; provide a login password.', 'NEEDS_CREDENTIAL')
    return secret


@contextmanager
def transport(ssh_module, server, vault=None):
    """Keep the askpass broker alive for exactly the caller's SSH operation."""
    secret = _login_secret(server, vault)
    handle = None
    try:
        opts, handle = ssh_module.auth_ssh_opts(ssh_module.make_auth('password', password=secret))
        if handle is None:
            raise ConnectionError('Password authentication transport is unavailable.', 'PASSWORD_TRANSPORT_FAILED')
        # A master can authenticate as a different user/target, or with an old
        # credential. Every password operation must perform its own handshake.
        opts += ['-o', 'ControlPath=none', '-o', 'ControlMaster=no', '-o', 'ControlPersist=no']
        argv = ssh_module.ssh_base(server['host'], server['user'], server.get('port', 22)) + opts
        argv.append('%s@%s' % (server['user'], server['host']))
        env = handle.env()
    except (Exception, SystemExit):
        if handle is not None: handle.close()
        raise ConnectionError('Password authentication transport is unavailable.', 'PASSWORD_TRANSPORT_FAILED') from None
    try:
        yield argv, env
    finally:
        handle.close()


class _Environment:
    def __init__(self, value): self.value = value
    def env(self): return self.value


def run(ssh_module, server, command, stdin_data=None, timeout=120, vault=None):
    with transport(ssh_module, server, vault) as (argv, env):
        return ssh_module.run_ssh(argv + [command], secret_handle=_Environment(env),
                                  stdin_data=stdin_data, timeout=timeout)


def test(ssh_module, server, vault=None):
    """Read-only bounded password probe. Remote diagnostics never become errors."""
    try:
        rc, out, _ = run(ssh_module, server, "printf 'SSHBIND_OK\\n'", timeout=20, vault=vault)
        if rc == 0 and 'SSHBIND_OK' in out.splitlines():
            return True, ['Password authentication verified.']
        if rc == 124:
            return False, ['Password connection verification timed out.']
        return False, ['Password connection verification failed; check the address, account and login credential.']
    except ConnectionError as exc:
        messages = {
            'VAULT_UNAVAILABLE': 'Unlock the OS keyring and retry password authentication.',
            'NEEDS_CREDENTIAL': 'Provide a login password or unlock the saved imported credential.',
            'PASSWORD_TRANSPORT_FAILED': 'Password authentication transport is unavailable.',
        }
        return False, [messages.get(exc.code, 'Password connection verification could not be completed.')]
    except (Exception, SystemExit):
        return False, ['Password connection verification could not be completed.']


class _EphemeralVault:
    """Present an uncommitted candidate password to the ordinary test path."""
    def __init__(self, secret): self.secret = secret
    def status(self): return {'available': True}
    def get(self, ref): return self.secret


def _verify_candidate(ssh_module, candidate, secret):
    probe = dict(candidate, login_credential_ref='candidate-in-memory')
    valid, _ = test(ssh_module, probe, _EphemeralVault(secret))
    if not valid:
        raise ConnectionError('Password connection verification failed; previous connection state was retained.',
                              'CONNECTION_VERIFICATION_FAILED')


def _public(candidate):
    return {'ok': True, 'name': candidate['name'], 'id': candidate['id'], 'revision': candidate['revision'],
            'auth_type': candidate['auth_type'], 'installed': bool(candidate.get('installed')),
            'usable': bool(candidate.get('installed') and candidate.get('verification_status') == 'verified'
                           and candidate.get('login_credential_ref')),
            'verification_status': candidate.get('verification_status'),
            'has_login_credential': bool(candidate.get('login_credential_ref')),
            'has_encrypted_login': bool(candidate.get('encrypted_login_ref'))}


def create(ssh_module, body, vault=None):
    from bindkit_pending import (_validate_body, _vault, _lock, _save, _prepare_policy,
                                 _restore_policy, _cleanup_staged)
    name, candidate, secret, private_key, descriptor = _validate_body(body)
    if private_key or descriptor or candidate.get('auth_type') != 'password':
        raise ConnectionError('A password connection requires a login password without private key or encrypted descriptor.')
    if secret is None:
        raise ConnectionError('A login password is required.', 'NEEDS_CREDENTIAL')
    vault = _vault(vault)
    with _lock(ssh_module):
        state = ssh_module.load_state()
        if name in state['servers']:
            raise ConnectionError('Connection alias already exists.', 'CONFLICT')
        _verify_candidate(ssh_module, candidate, secret)
        candidate.update(id=str(uuid.uuid4()), revision=1, key='', auth_type='password', source='password',
                         installed=True, usable=True, verification_status='verified', fingerprint=None,
                         certificate=None, key_type=None, restrict=False,
                         created_at=datetime.now().isoformat(timespec='seconds'))
        refs = []; policy = None; committed = False
        try:
            ref = vault.new_ref('login'); refs.append(ref)
            vault.set(ref, secret); candidate['login_credential_ref'] = ref
            policy = _prepare_policy(ssh_module, name, body)
            updated = copy.deepcopy(state); updated['servers'][name] = candidate
            _save(ssh_module, state, updated); committed = True
            return _public(candidate)
        except (Exception, SystemExit) as exc:
            try:
                current = ssh_module.load_state()['servers'].get(name)
                if not current or current.get('id') != candidate['id']:
                    _restore_policy(policy)
            except (Exception, SystemExit):
                raise ConnectionError('Password connection registration and policy restoration failed.', 'ROLLBACK_FAILED') from None
            if isinstance(exc, ConnectionError): raise
            raise ConnectionError('Password connection could not be saved; check the OS keyring and local storage.',
                                  'CONNECTION_CREATE_FAILED') from None
        finally:
            if not committed: _cleanup_staged(ssh_module, vault, refs)


def update(ssh_module, name, body, vault=None):
    # The shared dispatcher locks, validates and handles explicit private-key edits.
    from bindkit_connections import update_connection
    return update_connection(ssh_module, name, body, vault)


def validate_update(old, body):
    from bindkit_connections import _validate
    # Native password creation/import accepts Windows domains and email logins.
    # Keep the same rule for edits without widening legacy key-mode validation.
    if 'user' in body:
        user = body['user']
        if not isinstance(user, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.@\\-]{0,127}', user):
            raise ConnectionError('Invalid user.')
    candidate = _validate(old, {key: value for key, value in body.items() if key != 'user'})
    if 'user' in body: candidate['user'] = body['user']
    return candidate


def _update_locked(ssh_module, name, body, state, old, vault=None):
    from bindkit_connections import public_credential_status
    from bindkit_pending import _vault, _save, _cleanup_staged, _prepare_policy, _restore_policy
    candidate = validate_update(old, body)
    secret = body.get('login_password')
    if secret is not None and any(c in secret for c in ('\n', '\r')):
        raise ConnectionError('Login passwords containing line breaks are unsupported.')
    pending = old.get('verification_status') == 'pending' or not old.get('installed', True)
    login_edit = any(field in body for field in ('host', 'user', 'port', 'login_password'))
    clearing = bool(body.get('clear_sudo_password') and old.get('sudo_credential_ref'))
    if secret is not None or 'sudo_password' in body or clearing:
        vault = _vault(vault)
    if login_edit and (not pending or secret is not None):
        _verify_candidate(ssh_module, candidate, secret if secret is not None else _login_secret(old, vault))
        candidate.update(installed=True, usable=True, verification_status='verified')
    candidate.update(key='', auth_type='password', certificate=None, fingerprint=None, key_type=None)
    refs = []; committed = False; cleared = False; previous_sudo = None; policy = None
    try:
        for prefix, field, value in (('login', 'login_credential_ref', secret),
                                     ('sudo', 'sudo_credential_ref', body.get('sudo_password'))):
            if value is not None:
                ref = vault.new_ref(prefix); refs.append(ref)
                vault.set(ref, value); candidate[field] = ref
        if clearing:
            previous_sudo = vault.get(old['sudo_credential_ref'])
            # Set before deletion: a backend may delete successfully, then report an error.
            cleared = True; vault.delete(old['sudo_credential_ref'])
        candidate.update(name=name, id=old.get('id') or str(uuid.uuid4()), revision=int(old.get('revision', 0)) + 1)
        policy = _prepare_policy(ssh_module, name, body)
        updated = copy.deepcopy(state); updated['servers'][name] = candidate
        _save(ssh_module, state, updated); committed = True
    except (Exception, SystemExit) as exc:
        try:
            if cleared and previous_sudo is not None: vault.set(old['sudo_credential_ref'], previous_sudo)
            if ssh_module.load_state()['servers'].get(name) == old: _restore_policy(policy)
        except (Exception, SystemExit):
            raise ConnectionError('Connection update and credential or policy restoration failed.', 'ROLLBACK_FAILED') from None
        if isinstance(exc, ConnectionError): raise
        raise ConnectionError('Password connection update failed; previous connection state was retained.',
                              'CONNECTION_UPDATE_FAILED') from None
    finally:
        if not committed: _cleanup_staged(ssh_module, vault, refs)
    if secret is not None and old.get('login_credential_ref'):
        # Cleanup only after a confirmed save, and retain references shared by another row.
        _cleanup_staged(ssh_module, vault, [old['login_credential_ref']])
    result = _public(candidate)
    result['changed'] = [field for field in ('host', 'user', 'port', 'login_password', 'sudo_auth',
                                           'sudo_password', 'clear_sudo_password') if field in body]
    result['credential_status'] = public_credential_status(candidate, vault)
    return result
