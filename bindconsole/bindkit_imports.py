"""Memory-only SSH session previews with a private optional credential sink.

Xshell .xsh (UTF-8/UTF-16), ordinary ZIP/.xts ZIPs containing .xsh,
FinalShell SSH JSON and OpenSSH config are accepted. Unknown protected .xts
containers are rejected. Imported commands are never run, Includes/IdentityFile
paths are never opened, and no credential is included in public preview data.
"""
import configparser
import fnmatch
import hashlib
import io
import json
import re
import shlex
import stat
import zipfile
import zlib

from bindkit_xshell_crypto import MAX_ENCODED_PASSWORD, normalize_version, recover_password

MAX_FILES = 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1024
MAX_EXPANDED_BYTES = 16 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_ITEMS = 1024
_PROTECTED = 'Unsupported protected/unknown container: export individual .xsh files or an ordinary unencrypted ZIP; re-enter passwords manually.'
_KEY_WARNING = 'Private-key reference is a filename hint only; select the key manually.'
_CREDENTIAL_WARNINGS = {
    'available': 'Saved password recovered locally for selected imports.',
    'needs_context': 'Saved Xshell password needs a master password or the exact source Windows username/SID.',
    'invalid': 'Stored password could not be verified; correct the batch unlock details or re-enter credentials.',
    'unsupported': 'This saved-password format is unsupported; re-enter credentials manually.',
}


def _decode(content):
    if content.startswith((b'\xff\xfe', b'\xfe\xff')):
        text = content.decode('utf-16')
    elif content[:64].count(b'\0') > 4:
        text = content.decode('utf-16-le')
    else:
        text = content.decode('utf-8-sig')
    if '\0' in text:
        raise ValueError('unsupported text encoding')
    return text


def _basename(value):
    return str(value).replace('\\', '/').rsplit('/', 1)[-1]


def _name(value):
    value = re.sub(r'[^A-Za-z0-9._-]+', '-', str(value or ''))[:80]
    while '..' in value:
        value = value.replace('..', '.')
    return value.lstrip('._-') or 'session'


def _key_hint(value):
    if not isinstance(value, str) or '\n' in value or 'PRIVATE KEY' in value or len(value) > 4096:
        return None
    hint = _basename(value.strip().strip('"\''))
    if not hint or hint in ('.', '..'):
        return None
    return re.sub(r'[^A-Za-z0-9._ -]', '_', hint)[:128]


def _candidate(name, host, port, user, source, key=None, password=False):
    if not isinstance(host, str):
        raise ValueError('missing host')
    host = host.strip()
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    if not host or len(host) > 253 or host.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.:-]+', host):
        raise ValueError('invalid or dynamic host')
    if isinstance(port, bool) or not re.fullmatch(r'[0-9]{1,5}', str(port)) or not 1 <= int(port) <= 65535:
        raise ValueError('invalid port')
    if user is None:
        user = ''
    if not isinstance(user, str) or len(user) > 128 or (user and not re.fullmatch(r'[A-Za-z0-9_.@\\-]+', user)) or user.startswith('-'):
        raise ValueError('invalid user')
    warnings = []
    safe_name = _name(name)
    if safe_name != name:
        warnings.append('Session name was normalized to a safe SSH alias.')
    hint = _key_hint(key)
    if hint:
        warnings.append(_KEY_WARNING)
    return {'name': safe_name, 'host': host, 'port': int(port), 'user': user,
            'source': source, 'auth_type': 'private_key' if hint else 'password' if password else 'unknown',
            'requires_credentials': True, 'key_hint': hint, 'warnings': warnings,
            'credential_status': 'unsupported' if password else 'missing', 'has_imported_password': False}


def _xshell(content, filename, credentials=None):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(_decode(content))
    sections = {name.upper(): dict(parser.items(name)) for name in parser.sections()}
    connection = sections.get('CONNECTION', {})
    auth = sections.get('CONNECTION:AUTHENTICATION', {})
    if str(connection.get('protocol', 'SSH')).upper() not in ('SSH', 'SSH2'):
        raise ValueError('non-SSH protocol excluded')
    key = auth.get('userkey') or auth.get('userkeyfile') or auth.get('identityfile')
    encrypted = auth.get('password', '')
    password = bool(encrypted or auth.get('passwordv2'))
    item = _candidate(filename.rsplit('.', 1)[0], connection.get('host'),
                      connection.get('port', 22), auth.get('username', ''), 'xshell', key, password)
    version = sections.get('SESSIONINFO', {}).get('version', '')
    recovered = recover_password(encrypted, version, credentials)
    # PasswordV2 is not assumed to use Password's encryption or byte format.
    if not encrypted and auth.get('passwordv2'):
        recovered = {'status': 'unsupported'}
        encrypted, version = auth['passwordv2'], ''
    status = recovered['status']
    item['credential_status'] = status
    item['has_imported_password'] = status == 'available'
    item['requires_credentials'] = status != 'available'
    if recovered.get('reason') == 'backend_missing':
        item['warnings'].append('Saved-password recovery requires the optional pycryptodome integration; install it or re-enter credentials.')
    elif status in _CREDENTIAL_WARNINGS:
        item['warnings'].append(_CREDENTIAL_WARNINGS[status])
    if status == 'available':
        item['_credential_descriptor'] = {'password': recovered['password']}
    elif encrypted and len(encrypted) <= MAX_ENCODED_PASSWORD:
        item['_credential_descriptor'] = {'encrypted_password': encrypted, 'version': normalize_version(version) or 'unknown'}
    return [item], []


def _finalshell(content, filename):
    value = json.loads(_decode(content))
    if not isinstance(value, dict):
        raise ValueError('expected a FinalShell connection object')
    kind = value.get('type')
    protocol = value.get('protocol')
    if ((kind is not None and str(kind).lower() not in ('100', 'ssh', 'ssh2'))
            or (protocol is not None and str(protocol).lower() not in ('ssh', 'ssh2'))):
        raise ValueError('non-SSH protocol excluded')
    key = value.get('private_key_path') or value.get('key_path') or value.get('identity_file')
    item = _candidate(value.get('name') or filename.rsplit('.', 1)[0], value.get('host'),
                      value.get('port', 22), value.get('user_name', value.get('username', value.get('user', ''))),
                      'finalshell', key, any('password' in str(k).lower() and isinstance(v, str) and bool(v)
                                             for k, v in value.items()))
    if item['credential_status'] == 'unsupported':
        item['warnings'].append(_CREDENTIAL_WARNINGS['unsupported'])
    return [item], []


def _matches(patterns, alias):
    positive = False
    for pattern in patterns:
        if pattern.startswith('!'):
            if fnmatch.fnmatchcase(alias, pattern[1:]):
                return False
        elif fnmatch.fnmatchcase(alias, pattern):
            positive = True
    return positive


def _openssh(content, filename):
    blocks = [(['*'], {})]
    current = blocks[0][1]
    aliases, warnings = [], []
    allowed = {'hostname', 'user', 'port', 'identityfile'}
    ignored = False
    for line in _decode(content).splitlines():
        # OpenSSH permits both 'key value' and 'key=value'. shlex handles quoted
        # arguments/comments without running expansion or shell commands.
        line = re.sub(r'^(\s*[^\s=]+)\s*=\s*', r'\1 ', line)
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            warnings.append('Malformed OpenSSH line was ignored.')
            continue
        if not parts:
            continue
        directive, values = parts[0].lower(), parts[1:]
        if directive == 'host':
            current = {}
            blocks.append((values, current))
            for name in values:
                if name and not any(c in name for c in '*?![') and name not in aliases:
                    aliases.append(name)
            if len(aliases) > MAX_ITEMS:
                raise ValueError('too many session candidates')
        elif directive == 'match':
            current = None
            ignored = True
        elif directive in ('include', 'proxycommand', 'localcommand', 'remotecommand', 'proxyjump'):
            ignored = True
        elif current is not None and directive in allowed and values:
            current.setdefault(directive, values[0])
    if ignored:
        warnings.append('Include/Match/proxy/command options were ignored; verify connectivity manually.')
    items = []
    for alias in aliases:
        options = {}
        for patterns, entries in blocks:
            if _matches(patterns, alias):
                for key, value in entries.items():
                    options.setdefault(key, value)
        try:
            item = _candidate(alias, options.get('hostname', alias), options.get('port', 22),
                              options.get('user', ''), 'openssh', options.get('identityfile'))
        except ValueError:
            warnings.append('OpenSSH session with invalid/dynamic endpoint was excluded.')
            continue
        if ignored:
            item['warnings'].append('Ignored SSH routing/command conditions require manual review.')
        items.append(item)
    if not items:
        warnings.append('No concrete SSH Host entries found; wildcard and dynamic entries are excluded.')
    return items, warnings


def _archive(content, expansion_budget, credentials=None):
    warnings, items = [], []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as container:
            members = container.infolist()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                return [], ['Archive has too many entries.']
            expanded = sum(member.file_size for member in members)
            if expanded > expansion_budget[0]:
                return [], ['Archive expanded size exceeds the total request limit.']
            expansion_budget[0] -= expanded
            # Validate the entire archive before reading any member; never extract.
            for member in members:
                name = member.filename.replace('\\', '/')
                mode = member.external_attr >> 16
                if (name.startswith('/') or re.match(r'^[A-Za-z]:', name)
                        or '..' in name.split('/') or '\0' in name
                        or stat.S_ISLNK(mode)
                        or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                    return [], ['Unsafe archive path or link rejected.']
                if member.flag_bits & 1:
                    return [], [_PROTECTED]
                if member.file_size > MAX_MEMBER_BYTES or member.file_size > max(1, member.compress_size) * MAX_COMPRESSION_RATIO:
                    return [], ['Archive member size/compression ratio exceeds the limit.']
            for member in members:
                if member.is_dir() or not member.filename.lower().endswith('.xsh'):
                    continue
                try:
                    with container.open(member) as stream:
                        payload = stream.read(MAX_MEMBER_BYTES + 1)
                    if len(payload) > MAX_MEMBER_BYTES:
                        return [], ['Archive member exceeds the size limit.']
                    parsed, notes = _xshell(payload, _basename(member.filename), credentials)
                    items.extend(parsed)
                    warnings.extend(notes)
                except (ValueError, UnicodeError, configparser.Error, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError):
                    warnings.append('An invalid/unsupported Xshell archive member was excluded.')
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        return [], [_PROTECTED]
    if not items and not warnings:
        warnings.append('No .xsh session files found in the ZIP archive.')
    return items, warnings


def parse_import_files(files, format='auto', reserved_names=(), credentials=None, credential_sink=None):
    """Preview supported files; return safe metadata only, without side effects.

    formats: auto/xshell/finalshell/openssh. Invalid input types or request limits
    raise ValueError. Individual malformed/unsupported files produce warnings and
    do not prevent other valid files from being previewed. IDs identify candidates
    within a repeatable preview; confirmation must validate the selected metadata.
    Optional credentials contain only master_password/source_username/source_sid.
    The optional sink receives (final_candidate_id, private_descriptor), containing
    a recovered password or bounded encrypted_password/version. Public metadata
    never contains either secret. has_imported_password means decoded and usable;
    requires_credentials becomes false only in that case, even without a sink.
    """
    if format not in ('auto', 'xshell', 'finalshell', 'openssh'):
        raise ValueError('unsupported import format')
    if credential_sink is not None and not callable(credential_sink):
        raise ValueError('credential sink must be callable')
    if not isinstance(files, (list, tuple)) or len(files) > MAX_FILES:
        raise ValueError('invalid import file count')
    total = 0
    for entry in files:
        if (not isinstance(entry, dict) or not isinstance(entry.get('name'), str)
                or not isinstance(entry.get('content'), bytes)):
            raise ValueError('each import file requires name and bytes content')
        if len(entry['name']) > 1024 or len(entry['content']) > MAX_FILE_BYTES:
            raise ValueError('import file exceeds the size limit')
        total += len(entry['content'])
    if total > MAX_TOTAL_BYTES:
        raise ValueError('total import size exceeds the limit')
    used = {str(name) for name in reserved_names}
    items, warnings = [], []
    expansion_budget = [MAX_EXPANDED_BYTES]
    for entry in files:
        filename, payload = _basename(entry['name']), entry['content']
        extension = filename.lower().rsplit('.', 1)[-1]
        try:
            if extension in ('zip', 'xts') or zipfile.is_zipfile(io.BytesIO(payload)):
                parsed, notes = _archive(payload, expansion_budget, credentials)
            else:
                chosen = format
                if chosen == 'auto':
                    chosen = 'xshell' if extension == 'xsh' else 'finalshell' if extension == 'json' else 'openssh'
                if chosen == 'xshell':
                    parsed, notes = _xshell(payload, filename, credentials)
                else:
                    parsed, notes = {'finalshell': _finalshell, 'openssh': _openssh}[chosen](payload, filename)
            warnings.extend(notes)
        except (ValueError, UnicodeError, configparser.Error, RecursionError):
            warnings.append('Invalid or non-SSH session file excluded; verify its format and endpoint.')
            continue
        if len(items) + len(parsed) > MAX_ITEMS:
            raise ValueError('too many session candidates')
        for item in parsed:
            descriptor = item.pop('_credential_descriptor', None)
            base, name, suffix = item['name'], item['name'], 2
            while name in used:
                name = '%s-%d' % (base, suffix)
                suffix += 1
            if name != base:
                item['warnings'].append('Duplicate/reserved alias renamed; review before import.')
            item['name'] = name
            used.add(name)
            # IDs depend only on connection metadata, never credentials, their
            # hashes, recovery status or context-dependent warning messages.
            identity = json.dumps({field: item[field] for field in
                                   ('name', 'host', 'port', 'user', 'source', 'auth_type', 'key_hint')},
                                  sort_keys=True, separators=(',', ':'), ensure_ascii=True)
            item['id'] = 'session_' + hashlib.sha256(identity.encode()).hexdigest()[:24]
            if descriptor is not None and credential_sink is not None:
                credential_sink(item['id'], descriptor)
            items.append(item)
    return {'items': items, 'warnings': warnings, 'count': len(items)}
