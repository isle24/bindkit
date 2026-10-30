"""Explicit identity plans and prompt-aware, noninteractive sudo execution."""
import hashlib
import json
import os
import re
import selectors
import shlex
import subprocess
import time
import uuid

_IDENTITY = re.compile(r'(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}|#[0-9]{1,10})\Z')
_PRIVILEGE = re.compile(r'(?<![\w-])(?:sudo|su|runuser|doas|pkexec)(?![\w-])')
_COMPLEX = re.compile(r'[\n\r;|&<>`$()]')
_WRAPPERS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'env', 'eval', 'exec', 'command', 'xargs', 'find', 'python', 'python3', 'perl', 'ruby', 'node', 'awk'}

def _privilege_text(command):
    if _PRIVILEGE.search(command): return True
    try:
        return any(os.path.basename(word) in ('sudo', 'su', 'runuser', 'doas', 'pkexec') for word in shlex.split(command))
    except ValueError:
        return True


def _simple_command(command):
    if _COMPLEX.search(command) or '\\' in command: return False
    try:
        words = shlex.split(command)
        return bool(words and os.path.basename(words[0]) not in _WRAPPERS)
    except ValueError:
        return False


_SENSITIVE = {'root', 'admin', 'administrator', 'sudo', 'wheel', 'daemon', 'nobody'}


def build_plan(command, login_user, as_user=None, allowed_users=(), uid_resolver=None):
    if not isinstance(command, str) or not command.strip() or '\x00' in command:
        raise ValueError('A nonempty command without NUL is required')
    original = command
    privileged = _privilege_text(command)
    target = as_user
    unsupported = False
    if as_user is not None:
        if not isinstance(as_user, str) or not _IDENTITY.fullmatch(as_user):
            raise ValueError('Target identity must be a literal account name or #UID')
    elif privileged:
        try:
            words = shlex.split(command)
            tool = os.path.basename(words[0]) if words else ''
            if tool == 'sudo' and not _COMPLEX.search(command):
                target = 'root'; pos = 1
                if pos < len(words) and words[pos] in ('-u', '--user'):
                    target = words[pos + 1]; pos += 2
                elif pos < len(words) and words[pos].startswith('--user='):
                    target = words[pos].split('=', 1)[1]; pos += 1
                if pos < len(words) and words[pos] == '--': pos += 1
                if pos == len(words) or words[pos].startswith('-'): raise ValueError()
                command = shlex.join(words[pos:])
            elif tool == 'su' and len(words) == 4 and words[2] == '-c' and not _COMPLEX.search(words[1]):
                target, command = words[1], words[3]
            elif tool == 'runuser' and len(words) >= 5 and words[1] == '-u' and words[3] == '--' and not _COMPLEX.search(command):
                target, command = words[2], shlex.join(words[4:])
            else:
                raise ValueError()
            if not _IDENTITY.fullmatch(target): raise ValueError()
        except (ValueError, IndexError):
            target = None; command = original; unsupported = True
    managed = target is not None and not unsupported
    uid = None
    if managed and uid_resolver is not None:
        try:
            resolved = uid_resolver(target)
            if isinstance(resolved, int) and not isinstance(resolved, bool) and resolved >= 0:
                uid = resolved
        except Exception:
            pass
    nested = managed and (_privilege_text(command) or not _simple_command(command))
    exempt = bool(managed and target in allowed_users and uid is not None and uid >= 1000
                  and target.lower() not in _SENSITIVE and not nested)
    context = {'version': 1, 'original_command': original, 'command': command,
               'login_user': login_user, 'target_user': target, 'target_uid': uid,
               'managed': managed, 'unsupported': unsupported, 'nested': bool(nested)}
    return dict(context, approval_exempt=exempt,
                requires_approval=bool((managed or privileged) and not exempt),
                fingerprint_context=context,
                fingerprint=hashlib.sha256(json.dumps(context, sort_keys=True, separators=(',', ':')).encode()).hexdigest())


def _result(code, stdout='', stderr='', started=False, authenticated=False, error=None):
    return {'exit_code': code, 'stdout': stdout, 'stderr': stderr, 'started': started,
            'authenticated': authenticated, 'error': error}


def _error(code, message):
    return {'code': code, 'message': message}


def execute_plan(ssh_module, server, plan, vault, stdin_data=None, timeout=120, transport=None):
    """Never send command input until sudo has started the nonce-bound wrapper.

    No PTY is allocated: requiretty, PAM multi-factor and interactive su are unsupported.
    started=None denotes an ambiguous transport failure and forbids automatic replay.
    """
    if plan.get('unsupported'):
        return _result(5, error=_error('UNSUPPORTED_PRIVILEGE', 'Use --as-user with a literal target and noninteractive command.'))
    nonce = uuid.uuid4().hex
    prompt = ('BINDKIT_PROMPT_' + nonce).encode()
    marker = ('BINDKIT_STARTED_' + nonce).encode()
    inner = "printf '%s\\n' " + shlex.quote(marker.decode()) + " >&2; exec sh -c " + shlex.quote(plan['command'])
    if plan.get('managed'):
        remote = 'sudo -S -p ' + shlex.quote(prompt.decode()) + ' -u ' + shlex.quote(plan['target_user']) + ' -- sh -c ' + shlex.quote(inner)
    else:
        remote = 'sh -c ' + shlex.quote(inner)
    if transport is None:
        argv = ssh_module.ssh_with_key(server['host'], server['user'], server.get('port', 22),
                                        server['key'], server.get('certificate')) + [remote]
        environment = None
    else:
        base_argv, environment = transport
        argv = list(base_argv) + [remote]
    if os.path.basename(argv[0]) == 'ssh': argv.insert(1, '-T')
    payload = stdin_data.encode('utf-8') if isinstance(stdin_data, str) else (stdin_data or b'')
    if not isinstance(payload, bytes): raise ValueError('stdin_data must be bytes or text')
    started = False; authenticated = False; prompted = False; password = None
    error = None; stdout = bytearray(); stderr = bytearray(); pending = bytearray()
    deadline = time.monotonic() + max(0.01, min(float(timeout), 86400))
    proc = None; selector = selectors.DefaultSelector()
    output_limit = 8 * 1024 * 1024
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, **({'env': environment} if transport is not None else {}))
        for stream, label in ((proc.stdout, 'out'), (proc.stderr, 'err')):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(proc.stdin.fileno(), False)

        def queue(data):
            pending.extend(data)
            if pending:
                try: selector.register(proc.stdin, selectors.EVENT_WRITE, 'in')
                except KeyError: pass
            elif started and not proc.stdin.closed:
                proc.stdin.close()

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = _error('EXECUTION_TIMEOUT', 'Execution timed out; do not automatically retry.')
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                if key.data == 'in':
                    try:
                        written = os.write(key.fd, pending[:65536]); del pending[:written]
                    except (BrokenPipeError, OSError):
                        pending.clear()
                    if not pending:
                        selector.unregister(key.fileobj)
                        if started: key.fileobj.close()
                    continue
                try: chunk = os.read(key.fd, 65536)
                except BlockingIOError: continue
                if not chunk:
                    selector.unregister(key.fileobj); continue
                dest = stdout if key.data == 'out' else stderr
                dest.extend(chunk)
                if len(stdout) + len(stderr) > output_limit:
                    error = _error('OUTPUT_LIMIT', 'Output exceeded the bounded capture limit; do not automatically retry.')
                    break
                if key.data != 'err' or started: continue
                if prompt in stderr:
                    stderr[:] = stderr.replace(prompt, b'', 1)
                    if prompted:
                        error = _error('AUTHENTICATION_FAILED', 'Sudo authentication failed or requires an unsupported additional factor.')
                        break
                    prompted = True
                    if server.get('sudo_auth', 'none') != 'keyring' or not server.get('sudo_credential_ref'):
                        error = _error('SUDO_CREDENTIAL_REQUIRED', 'Configure a sudo credential in the console or enable NOPASSWD on the server.')
                        break
                    try:
                        password = vault.get(server['sudo_credential_ref'])
                        if not isinstance(password, str) or not password or any(c in password for c in ('\n','\r','\x00')):
                            raise ValueError()
                    except Exception:
                        error = _error('SUDO_CREDENTIAL_UNAVAILABLE', 'Sudo credential unavailable; unlock or configure the OS keyring.')
                        break
                    queue(password.encode('utf-8') + b'\n')
                if marker + b'\n' in stderr:
                    stderr[:] = stderr.replace(marker + b'\n', b'', 1)
                    started = True; authenticated = True
                    queue(payload)
            if error: break
        if error and proc.poll() is None:
            proc.kill()
        try: proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            error = _error('EXECUTION_TIMEOUT', 'Execution timed out; do not automatically retry.')
        rc = proc.returncode
    except OSError:
        return _result(255, error=_error('TRANSPORT_UNAVAILABLE', 'Unable to start SSH transport.'))
    finally:
        selector.close()
        if proc is not None:
            if proc.poll() is None: proc.kill(); proc.wait()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream: stream.close()
    out = bytes(stdout).decode('utf-8', 'replace')
    err = bytes(stderr).replace(prompt, b'').replace(marker + b'\n', b'').decode('utf-8', 'replace')
    if password:
        out = out.replace(password, '[REDACTED]'); err = err.replace(password, '[REDACTED]')
    if not started:
        if not error and (rc == 255 or rc < 0):
            error = _error('EXECUTION_STATE_UNKNOWN', 'SSH transport was lost without a trusted execution marker; do not automatically retry.')
        elif not error and re.search(r'(requiretty|must have a tty|a terminal is required|no tty|verification code|one.time password)', err, re.I):
            error = _error('UNSUPPORTED_AUTHENTICATION', 'Interactive TTY or multi-factor sudo authentication is unsupported.')
        elif not error and prompted:
            error = _error('AUTHENTICATION_FAILED', 'Sudo authentication failed before command execution.')
        elif not error and rc not in (0, 255):
            error = _error('EXECUTION_NOT_STARTED', 'The managed wrapper did not start; inspect SSH or sudo configuration.')
        elif not error:
            error = _error('EXECUTION_STATE_UNKNOWN', 'No trusted execution marker received; do not automatically retry.')
        if error['code'] in ('EXECUTION_TIMEOUT', 'EXECUTION_STATE_UNKNOWN', 'OUTPUT_LIMIT'):
            started = None
    return _result(124 if error and error['code'] == 'EXECUTION_TIMEOUT' else (rc if rc else (1 if error else 0)),
                   out, err, started, authenticated, error)
