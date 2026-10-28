"""Explicit offline registration and transactional promotion of pending SSH aliases.

Login credentials and unrecovered Xshell descriptors are stored only in the OS
keychain. An offline registration never calls SSH or attempts authentication.
"""
import copy
from datetime import datetime
import json
import os
import re
import tempfile
import uuid

from bindkit_connections import ConnectionError, _lock, _validate


def _vault(vault=None):
    if vault is None:
        from bindkit_vault import Vault
        vault = Vault()
    try:
        if not vault.status()['available']:
            raise ValueError()
    except Exception:
        raise ConnectionError('OS keyring unavailable; unlock or install the optional runtime.', 'VAULT_UNAVAILABLE') from None
    return vault


def _password(body):
    auth = body.get('auth') if isinstance(body.get('auth'), dict) else {}
    return auth.get('password') if auth.get('password') is not None else body.get('password')


def _validate_body(body):
    if not isinstance(body, dict):
        raise ConnectionError('Request must be a JSON object.')
    name = body.get('name') or body.get('alias')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name) or '..' in name:
        raise ConnectionError('Invalid connection alias.')
    auth = body.get('auth') if isinstance(body.get('auth'), dict) else {}
    password = _password(body)
    private_key = auth.get('private_key') or body.get('private_key')
    for field, value in (('password', password), ('private_key', private_key)):
        if value is not None and (not isinstance(value, str) or not value or '\x00' in value or len(value) > 1024 * 1024):
            raise ConnectionError(field + ' must be nonempty text without NUL.')
    if password is not None and any(c in password for c in ('\n', '\r')):
        raise ConnectionError('Login passwords containing line breaks are unsupported.')
    baseline = {'name': name, 'key': '', 'installed': False, 'sudo_auth': 'none', 'sudo_credential_ref': None}
    candidate = _validate(baseline, {field: body.get(field, default) for field, default in (('host', ''), ('port', 22))})
    # Imported sessions also support explicit Windows domain / email identities.
    # Keep this compatibility rule local; Linux account edits remain stricter.
    user = body.get('user', 'root')
    if not isinstance(user, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.@\\-]{0,127}', user):
        raise ConnectionError('Invalid user.')
    candidate['user'] = user
    if 'sudo' in body:
        if body['sudo'] not in ('allow', 'ask', 'deny'):
            raise ConnectionError('sudo must be allow, ask or deny.')
        candidate['sudo'] = body['sudo']
    if 'note' in body:
        if body['note'] is not None and not isinstance(body['note'], str):
            raise ConnectionError('note must be text.')
        candidate['note'] = (body['note'] or '')[:200]
    descriptor = body.get('encrypted_login')
    if descriptor is not None:
        if not isinstance(descriptor, dict) or set(descriptor) != {'encrypted_password', 'version'}:
            raise ConnectionError('Encrypted login must contain encrypted_password and version.')
        if any(not isinstance(descriptor[field], str) or not descriptor[field] or '\x00' in descriptor[field] for field in descriptor):
            raise ConnectionError('Encrypted login descriptor must contain nonempty text.')
        if len(descriptor['encrypted_password']) > 1024 * 1024 or len(descriptor['version']) > 64:
            raise ConnectionError('Encrypted login descriptor is too large.')
    return name, candidate, password, private_key, descriptor


def _delete_refs(vault, refs):
    for ref in refs:
        try: vault.delete(ref)
        except Exception: pass


def _remove_owned(paths):
    for path in paths:
        try: os.unlink(path)
        except FileNotFoundError: pass


def _cleanup_staged(ssh_module, vault=None, refs=(), paths=()):
    # A storage backend can report failure after replacing a file. Never delete
    # credential/key material still referenced by persisted connection state.
    try:
        rows = list(ssh_module.load_state()['servers'].values())
        live_refs = {row.get(field) for row in rows for field in ('login_credential_ref', 'encrypted_login_ref')}
        live_paths = {row.get('key') for row in rows}
        live_paths.update(path + '.pub' for path in list(live_paths) if path)
        config = getattr(ssh_module, 'SSH_CONFIG', None)
        if config and os.path.isfile(config):
            with open(config, encoding='utf-8') as handle: text = handle.read()
            live_paths.update(path for path in paths if path in text)
    except (Exception, SystemExit):
        return  # Uncertain ownership: retain material for manual recovery.
    _delete_refs(vault, [ref for ref in refs if ref not in live_refs])
    _remove_owned([path for path in paths if path not in live_paths])


def _save(ssh_module, original, updated):
    try:
        ssh_module.write_ssh_config(updated['servers'])
        ssh_module.save_state(updated)
    except (Exception, SystemExit):
        restored = True
        try:
            latest = ssh_module.load_state()
            if latest == updated:
                try: ssh_module.save_state(original)
                except (Exception, SystemExit): pass
                latest = ssh_module.load_state()
            restored = latest == original
            ssh_module.write_ssh_config(latest['servers'])
        except (Exception, SystemExit):
            restored = False
        if not restored:
            raise ConnectionError('Connection state could not be saved and SSH configuration restoration failed.', 'ROLLBACK_FAILED') from None
        raise ConnectionError('Connection state could not be saved; previous connection was retained.', 'CONNECTION_SAVE_FAILED') from None


def _prepare_policy(ssh_module, name, body):
    fields = {field: body[field] for field in ('sudo', 'note', 'approval_ttl_s', 'allowed_users') if field in body}
    if not fields or not hasattr(ssh_module, '_console_policy_module'):
        return None
    mod = ssh_module._console_policy_module()
    previous = mod.read_policy('ssh')
    if previous.get('corrupt'):
        raise ConnectionError('SSH policy is corrupt; repair it before registering a connection.', 'STATE_CORRUPT')
    policy = copy.deepcopy(previous.get('data') or mod.default_policy('ssh'))
    clean = ssh_module._console_clean_ssh_policy({'servers': {name: fields}})['servers'][name]
    policy.setdefault('servers', {}).setdefault(name, {}).update(clean)
    expected = ssh_module._console_clean_ssh_policy(policy)
    mod.write_policy('ssh', expected)
    return mod, previous, expected


def _restore_policy(transaction):
    if transaction is None: return
    mod, previous, expected = transaction
    if mod.read_policy('ssh').get('data') != expected:
        return
    if previous.get('exists'):
        mod.write_policy('ssh', previous['data'])
    else:
        os.unlink(mod.tool_paths('ssh')['policy'])


def create_unverified(ssh_module, body, vault=None):
    """Register only after the caller has obtained explicit offline-add consent."""
    name, candidate, password, private_key, descriptor = _validate_body(body)
    with _lock(ssh_module):
        state = ssh_module.load_state()
        if name in state['servers']:
            raise ConnectionError('Connection alias already exists.', 'CONFLICT')
        if password is not None or descriptor is not None:
            vault = _vault(vault)
        candidate.update(id=str(uuid.uuid4()), revision=1, source='adopted' if private_key else 'pending',
                         verification_status='pending', installed=False, usable=False,
                         fingerprint=None, certificate=None, key_type=None, restrict=False,
                         created_at=datetime.now().isoformat(timespec='seconds'))
        refs = []; owned = []; policy = None; committed = False
        try:
            for prefix, value, field in (('login', password, 'login_credential_ref'),
                                         ('encrypted-login', json.dumps(descriptor) if descriptor is not None else None, 'encrypted_login_ref')):
                if value is not None:
                    ref = vault.new_ref(prefix); refs.append(ref)
                    vault.set(ref, value); candidate[field] = ref
            if private_key:
                os.makedirs(ssh_module.KEYS_DIR, mode=0o700, exist_ok=True)
                fd, path = tempfile.mkstemp(prefix=name + '-pending-', dir=ssh_module.KEYS_DIR)
                owned.append(path)
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(private_key.rstrip('\n') + '\n')
                candidate['key'] = path
            policy = _prepare_policy(ssh_module, name, body)
            updated = copy.deepcopy(state); updated['servers'][name] = candidate
            _save(ssh_module, state, updated)
            committed = True
        except (Exception, SystemExit) as exc:
            try:
                current = ssh_module.load_state()['servers'].get(name)
                if not current or current.get('id') != candidate['id']:
                    _restore_policy(policy)
            except Exception:
                raise ConnectionError('Offline registration failed and policy restoration failed.', 'ROLLBACK_FAILED') from None
            if isinstance(exc, ConnectionError): raise
            raise ConnectionError('Offline registration failed; check the OS keyring and local storage.', 'CONNECTION_CREATE_FAILED') from None
        finally:
            if not committed:
                _cleanup_staged(ssh_module, vault, refs, owned)
        return {'ok': True, 'name': name, 'id': candidate['id'], 'revision': 1, 'installed': False,
                'usable': False, 'verification_status': 'pending',
                'has_login_credential': bool(candidate.get('login_credential_ref')),
                'has_encrypted_login': bool(candidate.get('encrypted_login_ref'))}


def preserve_verified_password(ssh_module, body, create, vault=None):
    """Stage retention before SSH; the create callback owns its mutation lock."""
    if 'preserve_password' in body and not isinstance(body['preserve_password'], bool):
        raise ConnectionError('preserve_password must be a boolean.')
    if not body.get('preserve_password'):
        return create()
    password = _password(body)
    if not isinstance(password, str) or not password or '\x00' in password or any(c in password for c in ('\n', '\r')):
        raise ConnectionError('A login password is required for keychain retention.')
    vault = _vault(vault)
    ref = vault.new_ref('login'); committed = False; created = False; original = None; created_id = None
    name = body.get('name') or body.get('alias')
    try:
        vault.set(ref, password)
        result = create(); created = True
        created_id = result.get('id')
        with _lock(ssh_module):
            original = ssh_module.load_state(); updated = copy.deepcopy(original)
            candidate = updated['servers'].get(name)
            if not candidate or not candidate.get('installed', True):
                raise ConnectionError('Connection verification is required before retaining its login password.', 'CONNECTION_VERIFICATION_FAILED')
            if created_id and candidate.get('id') != created_id:
                raise ConnectionError('Connection identity changed before credential retention; retry with the current connection.', 'CONNECTION_CHANGED')
            created_id = candidate.get('id')
            candidate['login_credential_ref'] = ref
            candidate['verification_status'] = 'verified'
            _save(ssh_module, original, updated)
        committed = True
        result['has_login_credential'] = True
        return result
    except (Exception, SystemExit) as exc:
        if created:
            try:
                with _lock(ssh_module):
                    latest = ssh_module.load_state(); rollback = copy.deepcopy(latest)
                    old = original['servers'].get(name) if original else None
                    if old and old.get('id') == created_id and latest['servers'].get(name) == old:
                        rollback['servers'].pop(name, None)
                        _save(ssh_module, latest, rollback)
            except ConnectionError:
                raise ConnectionError('Credential retention failed and connection state restoration failed; inspect the connection before retrying.', 'ROLLBACK_FAILED') from None
        if isinstance(exc, ConnectionError): raise
        raise ConnectionError('Login credential could not be retained in the OS keyring; creation was not completed.', 'CREDENTIAL_RETENTION_FAILED') from None
    finally:
        if not committed: _cleanup_staged(ssh_module, vault, [ref])


def _failure(code, message, needs_credential=False):
    return {'ok': False, 'usable': False, 'installed': False, 'verification_status': 'pending',
            'code': code, 'message': message, 'needs_credential': needs_credential}


def unlock_credentials(ssh_module, name, credentials, vault=None):
    """Recover a saved descriptor locally; keep master/identity context ephemeral."""
    allowed = {'master_password', 'source_username', 'source_sid'}
    if not isinstance(credentials, dict) or set(credentials) - allowed:
        raise ConnectionError('credentials must contain only Xshell master or source identity fields.')
    if any(not isinstance(value, str) or '\x00' in value or len(value) > 4096 for value in credentials.values()):
        raise ConnectionError('Xshell unlock context must contain valid text.')
    with _lock(ssh_module):
        state = ssh_module.load_state(); old = state['servers'].get(name)
        if old is None: raise ConnectionError('Connection does not exist.', 'NOT_FOUND')
        if old.get('verification_status') != 'pending':
            raise ConnectionError('Only pending connections may unlock imported credentials.')
        ref = old.get('encrypted_login_ref')
        if not ref:
            return _failure('NO_ENCRYPTED_CREDENTIAL', 'No encrypted imported credential is saved for this connection.', True)
        try:
            vault = _vault(vault); encoded = vault.get(ref)
        except Exception:
            return _failure('VAULT_UNAVAILABLE', 'Unlock the OS keyring and retry credential recovery.')
        staged_ref = None; committed = False
        try:
            descriptor = json.loads(encoded)
            from bindkit_xshell_crypto import recover_password
            decoded = recover_password(descriptor['encrypted_password'], descriptor['version'], credentials=credentials)
            password = decoded.get('password')
            if decoded.get('status') != 'available' or not isinstance(password, str) or not password or '\x00' in password or any(c in password for c in ('\n', '\r')):
                return _failure('CREDENTIAL_UNLOCK_FAILED', 'Unable to unlock the saved credential; check the Xshell master password or source Windows identity.', True)
            staged_ref = vault.new_ref('login'); vault.set(staged_ref, password)
            updated = copy.deepcopy(state); candidate = updated['servers'][name]
            candidate['login_credential_ref'] = staged_ref
            candidate['revision'] = int(old.get('revision', 0)) + 1
            _save(ssh_module, state, updated); committed = True
            return {'ok': True, 'name': name, 'id': candidate['id'], 'revision': candidate['revision'],
                    'usable': False, 'verification_status': 'pending', 'has_login_credential': True,
                    'has_encrypted_login': True, 'message': 'Login credential unlocked and saved; test the connection to activate it.'}
        except (Exception, SystemExit) as exc:
            code = exc.code if isinstance(exc, ConnectionError) else 'CREDENTIAL_UNLOCK_FAILED'
            return _failure(code, 'Unable to unlock or save the credential; the saved connection and encrypted credential were retained.', True)
        finally:
            if staged_ref and not committed: _cleanup_staged(ssh_module, vault, [staged_ref])


def verify_pending(ssh_module, name, vault=None):
    """Install/verify access using saved material and activate only after success."""
    with _lock(ssh_module):
        state = ssh_module.load_state(); old = state['servers'].get(name)
        if old is None: raise ConnectionError('Connection does not exist.', 'NOT_FOUND')
        if old.get('verification_status') != 'pending':
            raise ConnectionError('Connection is not pending verification.')
        candidate = copy.deepcopy(old); owned = []; committed = False
        try:
            key = old.get('key') or ''
            if key and os.path.isfile(key):
                pubkey = ssh_module.read_pubkey_for(key)
                if not pubkey:
                    return _failure('NEEDS_CREDENTIAL', 'The saved private key is invalid or locked; provide a usable key or login password.', True)
            else:
                ref = old.get('login_credential_ref')
                if not ref:
                    return _failure('NEEDS_CREDENTIAL', 'Provide a login password or usable private key; encrypted imported credentials must be unlocked first.', True)
                try:
                    vault = _vault(vault); password = vault.get(ref)
                except Exception:
                    return _failure('VAULT_UNAVAILABLE', 'Unlock the OS keyring and retry verification.')
                if not isinstance(password, str) or not password:
                    return _failure('NEEDS_CREDENTIAL', 'The saved login credential is unavailable; provide a login password or usable private key.', True)
                os.makedirs(ssh_module.KEYS_DIR, mode=0o700, exist_ok=True)
                key_name = name + '-activation-' + uuid.uuid4().hex
                owned.extend([os.path.join(ssh_module.KEYS_DIR, key_name), os.path.join(ssh_module.KEYS_DIR, key_name + '.pub')])
                key, _ = ssh_module.gen_keypair(key_name)
                pubkey = ssh_module.read_pubkey_for(key)
                if not pubkey:
                    return _failure('KEY_VALIDATION_FAILED', 'The generated authentication key could not be read.')
                auth = ssh_module.make_auth('password', password=password)
                installed, _ = ssh_module.install_pubkey(old['host'], old['user'], old.get('port', 22), auth, pubkey, restrict=old.get('restrict', False))
                if not installed:
                    return _failure('AUTHENTICATION_FAILED', 'Unable to install the public key with the saved login credential; connection remains pending.')
                candidate.update(key=key, source='generated', certificate=None, key_type='ed25519')
            alive, _ = ssh_module.test_connection(candidate['host'], candidate['user'], candidate.get('port', 22), key, candidate.get('certificate'))
            if not alive:
                return _failure('CONNECTION_VERIFICATION_FAILED', 'Connection verification failed; saved connection and credentials were retained.')
            candidate.update(installed=True, usable=True, verification_status='verified',
                             fingerprint=ssh_module.fingerprint_of(pubkey), revision=int(old.get('revision', 0)) + 1)
            updated = copy.deepcopy(state); updated['servers'][name] = candidate
            _save(ssh_module, state, updated); committed = True
            return {'ok': True, 'usable': True, 'installed': True, 'verification_status': 'verified',
                    'name': name, 'id': candidate['id'], 'revision': candidate['revision'], 'message': 'Connection verified and activated.'}
        except (Exception, SystemExit) as exc:
            code = exc.code if isinstance(exc, ConnectionError) else 'CONNECTION_VERIFICATION_FAILED'
            message = ('Persistence failed and automatic restoration could not be confirmed; inspect the local connection before retrying.'
                       if code == 'ROLLBACK_FAILED' else 'Connection verification could not be completed; saved connection and credentials were retained.')
            return _failure(code, message)
        finally:
            if not committed: _cleanup_staged(ssh_module, paths=owned)
