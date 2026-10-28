"""Recover bounded Xshell saved passwords using an optional external cipher.

No file, registry, process, environment or network access. This module never
guesses source identity. All returned passwords are private caller data.

Format references (algorithms only; no upstream cipher code is copied):
https://github.com/HyperSine/how-does-Xmanager-encrypt-password/blob/master/doc/how-does-Xmanager-encrypt-password.md
https://github.com/JDArmy/SharpXDecrypt/blob/main/C%23/XClass.cs (MIT)
https://github.com/ssmmtt/Xpass/blob/master/Xclass.cs (7/8 identity format)

Session versions below 5.1 have no integrity digest. Versions 5.1+ append a
plaintext SHA256 digest outside the RC4 ciphertext. 7.0 retains the 6.x key;
7.1+ and 8.x reverse the source SID before appending the source username.
Unrecognized future major versions are deliberately unsupported.
"""
import base64
import binascii
import hashlib
import hmac
import re

MAX_PASSWORD_BYTES = 4096
MAX_ENCODED_PASSWORD = ((MAX_PASSWORD_BYTES + 32 + 2) // 3) * 4


def normalize_version(value):
    """Return a bounded numeric session version, or an empty unsupported value."""
    if not isinstance(value, str) or len(value) > 32:
        return ''
    value = value.strip()
    if not re.fullmatch(r'[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}', value):
        return ''
    parts = [int(part) for part in value.split('.')]
    if len(parts) == 1:
        parts.append(0)
    return '.'.join(str(part) for part in parts)


def recover_password(encrypted_password, version, credentials=None):
    """Return a private ``status`` result and ``password`` only after recovery.

    Statuses: missing (no password), needs_context (missing supplied source
    identity/master password), invalid (bad input/context/integrity/UTF-8),
    unsupported (version/backend), available (usable recovered password).
    Only supplied exact source identity and/or supplied master are attempted.
    """
    if encrypted_password == '':
        return {'status': 'missing'}
    normalized = normalize_version(version)
    if not normalized:
        return {'status': 'unsupported'}
    major, minor = (int(part) for part in normalized.split('.')[:2])
    if major < 1 or major > 8:
        return {'status': 'unsupported'}
    if credentials is None:
        credentials = {}
    if not isinstance(credentials, dict):
        return {'status': 'invalid'}
    for name, limit in (('master_password', MAX_PASSWORD_BYTES), ('source_username', 256), ('source_sid', 256)):
        value = credentials.get(name)
        if value is not None:
            if not isinstance(value, str) or len(value) > limit or '\0' in value:
                return {'status': 'invalid'}
            try:
                if len(value.encode('utf-8')) > limit:
                    return {'status': 'invalid'}
            except UnicodeError:
                return {'status': 'invalid'}
    if not isinstance(encrypted_password, str) or len(encrypted_password) > MAX_ENCODED_PASSWORD:
        return {'status': 'invalid'}
    try:
        data = base64.b64decode(encrypted_password, validate=True)
    except (ValueError, binascii.Error):
        return {'status': 'invalid'}
    modern = (major, minor) >= (5, 1)
    if not 1 <= len(data) <= MAX_PASSWORD_BYTES + (32 if modern else 0) or (modern and len(data) <= 32):
        return {'status': 'invalid'}

    keys = []
    if not modern:
        keys.append(hashlib.md5(b'!X@s#h$e%l^l&').digest())
    else:
        master = credentials.get('master_password')
        username, sid = credentials.get('source_username'), credentials.get('source_sid')
        if master:
            keys.append(hashlib.sha256(master.encode('utf-8')).digest())
        if sid:
            if (major, minor) <= (5, 2):
                material = sid
            elif username:
                material = sid[::-1] + username if (major, minor) >= (7, 1) else username + sid
            else:
                material = None
            if material is not None:
                keys.append(hashlib.sha256(material.encode('utf-8')).digest())
        if not keys:
            return {'status': 'needs_context'}
    try:
        from Crypto.Cipher import ARC4
    except ImportError:
        return {'status': 'unsupported', 'reason': 'backend_missing'}
    ciphertext, expected = (data[:-32], data[-32:]) if modern else (data, None)
    for key in keys:
        plaintext = ARC4.new(key).decrypt(ciphertext)
        if modern and not hmac.compare_digest(hashlib.sha256(plaintext).digest(), expected):
            continue
        try:
            password = plaintext.decode('utf-8', errors='strict')
        except UnicodeError:
            continue
        if not password or '\0' in password:
            continue
        return {'status': 'available', 'password': password}
    return {'status': 'invalid'}
