"""Trusted CLI adapters for immutable connection context and bounded AI review."""
import hashlib
import json
import re
import shlex
import os
from pathlib import Path


def _bounded_file(path, maximum=2 * 1024 * 1024):
    try:
        with path.open('rb') as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum: raise ValueError('Connection configuration exceeds bound')
        return data
    except FileNotFoundError:
        return b''


def ssh_transport_context(record):
    alias = record.get('via_ssh') if record.get('via') == 'ssh' else None
    if record.get('via') == 'docker' and ':' in str(record.get('docker_exec') or ''):
        alias = str(record['docker_exec']).split(':', 1)[0]
    if not alias: return None
    ssh_home = Path(os.path.expanduser('~')) / '.ssh'
    state_data = _bounded_file(ssh_home / 'sshbind' / 'servers.json')
    state = json.loads(state_data) if state_data else {}
    server = state.get('servers', {}).get(str(alias))
    config = _bounded_file(ssh_home / 'config')
    indirect = bool(re.search(rb'(?im)^\s*(?:Include|Match)\s', config))
    return {'alias': str(alias), 'managed_connection': connection_context(server) if server else None,
            'config_digest': hashlib.sha256(config).hexdigest(),
            'requires_human': indirect or not bool(server)}


def connection_context(record, tool='ssh'):
    fields = ('id', 'revision', 'host', 'port', 'user')
    result = {field: record.get(field) for field in fields}
    if tool == 'ssh':
        identity = {field: record.get(field) for field in
                    ('key', 'fingerprint', 'certificate', 'created_at', 'sudo_auth', 'sudo_credential_ref')}
    else:
        identity = {field: record.get(field) for field in
                    ('engine', 'database', 'file', 'via', 'via_ssh', 'docker_exec', 'config_file')}
        result.update({field: record.get(field) for field in ('engine', 'database', 'via')})
        transport = ssh_transport_context(record)
        identity['ssh_transport'] = transport
        result['transport_requires_human'] = bool(transport and transport['requires_human'])
    # Bind local key/transport references without exposing them in approvals or model payloads.
    result['identity_digest'] = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()
    return result


def protected_operation(command):
    # Security configuration and account/credential administration always need a human.
    pattern = (r'(?i)(?:\.bindconsole|\.ssh/(?:sshbind|authorized_keys)|\.dbbind|'
               r'\b(?:sudoers|authorized_keys|shadow|passwd|chpasswd|visudo|usermod|useradd|userdel|groupmod|gpasswd)\b|'
               r'\b(?:sshbind|dbbind)\s+(?:add|adopt|remove|import|config)|'
               r'\b(?:policy\.json|approvals?|credentials?|passwords?)\b)')
    command = command or ''
    if re.search(r'[\\`$*?\[\]{}]', command): return True
    try:
        words = shlex.split(command)
    except ValueError:
        return True
    if any(re.fullmatch(r'(?:ba|da|z|k|fi)?sh|python[0-9.]*|perl|ruby|node|env|eval|source|exec|command|xargs|find', os.path.basename(word)) for word in words):
        return True
    normalized = ' '.join(words)
    return bool(re.search(pattern, command) or re.search(pattern, normalized))


def review_gate(tool, gate, context, policy_module, recheck, reviewer=None):
    """AI cannot itself grant execution: only a fresh deterministic gate can."""
    if not gate or gate.get('decision') != 'ask' or gate.get('busy') or context.get('hard_allowed') is not True or context.get('protected') is not False:
        return gate
    try:
        request_id = gate.get('request_id')
        approval = policy_module.get_approval(tool, request_id)
        if not approval or approval.get('status') != 'pending': return gate
        revision = policy_module.policy_revision(tool)
        if context.get('policy_revision') != revision: return gate
        supplied = dict(context, fingerprint=approval['fingerprint'])
        if reviewer is None:
            from bindkit_ai import review_and_decide
            reviewer = review_and_decide
        reviewer(tool, request_id, supplied, policy_module, timeout=20)
        current = policy_module.get_approval(tool, request_id)
        if not current: return gate
        if current.get('status') in ('rejected', 'denied'):
            return {'decision': 'deny', 'code': 'AUTHZ_DENIED', 'message': '该请求已被拒绝，请由人工检查后再决定下一步。',
                    'request_id': request_id, 'hint': '审批拒绝不会自动重试或新建替代审批。'}
        if current.get('status') == 'approved':
            return recheck()
    except Exception:
        # Missing optional SDK, locked keychain, worker outage and malformed output
        # preserve the existing human approval request without exposing diagnostics.
        return gate
    return gate
