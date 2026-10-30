"""Authenticated administration extensions. Imports retain metadata only in RAM."""
import base64
import binascii
import copy
import re
import secrets
import threading
import time

_SSH_FAILURE_HINTS = {
    'AUTHENTICATION_FAILED': '密码认证未通过，请检查登录用户、密码和服务器认证设置',
    'REMOTE_KEY_INSTALL_FAILED': '服务器未能写入公钥，请检查家目录与 .ssh 目录权限',
    'KEY_LOGIN_VERIFICATION_FAILED': '密码认证和公钥写入已完成，但后续免密登录验证失败',
    'REMOTE_HOME_PERMISSIONS_UNSAFE': '服务器家目录允许组/其他用户写入，可能被 StrictModes 拦截，请由本人核对目录权限',
}


class AdminError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class AdminAPI:
    def __init__(self, app):
        self.app = app
        self.previews = {}
        self.lock = threading.Lock()

    def controller(self):
        if getattr(self.app, 'ai_controller', None) is None:
            from bindkit_ai import ReviewController
            self.app.ai_controller = ReviewController(home=self.app.home, console_home=self.app.runtime_dir)
        return self.app.ai_controller

    def ai(self, method, path, body):
        controller = self.controller()
        routes = {
            ('GET', ('config',)): controller.get_config,
            ('PUT', ('config',)): lambda: controller.save_config(body),
            ('GET', ('models',)): controller.list_models,
            ('POST', ('test',)): controller.test_connection,
            ('GET', ('service', 'status')): controller.service_status,
            ('POST', ('service', 'start')): controller.service_start,
            ('POST', ('service', 'stop')): controller.service_stop,
        }
        action = routes.get((method, tuple(path)))
        if action is None:
            if any(tuple(path) == route[1] for route in routes):
                raise AdminError('METHOD_NOT_ALLOWED', '不支持的请求方法', 405)
            raise AdminError('NOT_FOUND', '接口不存在', 404)
        try:
            result = action()
            if method == 'PUT' and result.get('mode') == 'off':
                controller.service_stop()
        except ValueError as exc:
            messages = {
                'ai_base_url_requires_https': ('AI_ENDPOINT_HTTPS_REQUIRED', '公网或未识别的模型地址必须使用 HTTPS；本机回环和私有局域网 IP 可使用 HTTP'),
                'ai_base_url_invalid': ('AI_ENDPOINT_INVALID', '模型 API 地址无效，请使用完整的 http:// 或 https:// 地址，且不要在地址中填写密钥'),
                'model_credential_unavailable': ('AI_KEYCHAIN_UNAVAILABLE', '无法保存模型 API Key，请解锁系统钥匙串并检查集成运行时'),
            }
            code, message = messages.get(str(exc), ('AI_CONFIG_INVALID', 'AI 配置无效，请检查字段格式与集成运行时'))
            raise AdminError(code, message) from None
        except Exception:
            raise AdminError('AI_UNAVAILABLE', 'AI 服务不可用，请检查集成运行时、系统钥匙串与模型配置', 503) from None
        if method != 'GET':
            self.app.audit('ai.' + '.'.join(path), 'allow')
        return result

    def _prune(self):
        now = time.time()
        self.previews = {token: p for token, p in self.previews.items()
                         if p['expires'] > now or p.get('busy')}

    def preview(self, body):
        if self.app.tool != 'ssh':
            raise AdminError('NOT_FOUND', '会话导入仅适用于 SSH 控制台', 404)
        if not isinstance(body, dict) or not isinstance(body.get('files'), list):
            raise AdminError('IMPORT_INVALID', '请选择需要导入的会话文件')
        files = body['files']
        if not 1 <= len(files) <= 1024:
            raise AdminError('IMPORT_INVALID', '一次最多选择 1024 个文件')
        credentials = body.get('credentials') or {}
        if not isinstance(credentials, dict) or set(credentials) - {'master_password', 'source_username', 'source_sid'} \
                or any(not isinstance(v, str) or len(v) > 8192 for v in credentials.values()):
            raise AdminError('IMPORT_INVALID', 'Xshell 解锁信息格式无效')
        decoded = []
        total = 0
        for entry in files:
            if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not isinstance(entry.get('content'), str):
                raise AdminError('IMPORT_INVALID', '文件格式无效')
            try:
                content = base64.b64decode(entry['content'], validate=True)
            except (ValueError, binascii.Error):
                raise AdminError('IMPORT_INVALID', '文件编码无效') from None
            total += len(content)
            if total > 16 * 1024 * 1024 or len(entry['name']) > 1024:
                raise AdminError('IMPORT_TOO_LARGE', '本次导入文件总计不能超过 16 MiB')
            decoded.append({'name': entry['name'], 'content': content})
        private = {}
        try:
            from bindkit_imports import parse_import_files
            existing = [row.get('name') for row in self.app.call_list_handler().get('servers', [])]
            result = parse_import_files(decoded, format=body.get('format', 'auto'), reserved_names=existing,
                                        credentials=credentials, credential_sink=lambda key, value: private.update({key: value}))
        except ValueError:
            raise AdminError('IMPORT_INVALID', '不支持的会话格式；可使用 .xsh、普通 ZIP、FinalShell JSON 或 OpenSSH config') from None
        finally:
            body.pop('credentials', None)
            body.pop('files', None)
        # Only bounded private descriptors remain in RAM; never serialize these to the client.
        token = secrets.token_urlsafe(24)
        expires = time.time() + 600
        with self.lock:
            self._prune()
            if len(self.previews) >= 16:
                raise AdminError('IMPORT_BUSY', '导入预览过多，请稍后重试', 429)
            self.previews[token] = {'items': {item['id']: copy.deepcopy(item) for item in result['items']},
                                    'credentials': private, 'expires': expires, 'used': set(), 'busy': set(), 'failed': set()}
        return dict(result, preview_id=token, expires_at=expires)

    def commit(self, body):
        if not isinstance(body, dict) or not isinstance(body.get('preview_id'), str):
            raise AdminError('IMPORT_INVALID', '缺少导入预览编号')
        rows = body.get('items')
        if not isinstance(rows, list) or len(rows) > 1024:
            raise AdminError('IMPORT_INVALID', '请选择需要导入的会话')
        with self.lock:
            self._prune()
            preview = self.previews.get(body['preview_id'])
            if preview is None:
                raise AdminError('IMPORT_EXPIRED', '预览已过期，请重新选择文件', 409)
            selected, names, ids = [], set(), set()
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get('id'), str):
                    raise AdminError('IMPORT_INVALID', '会话条目无效')
                if 'allow_unverified' in row and type(row['allow_unverified']) is not bool:
                    raise AdminError('IMPORT_INVALID', '待验证添加必须明确确认')
                item = preview['items'].get(row['id'])
                if item is None or row['id'] in preview['used']:
                    raise AdminError('IMPORT_EXPIRED', '条目已导入或预览无效，请重新预览', 409)
                name = row.get('name', item['name'])
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name) or name in ('.', '..') or name.startswith('-'):
                    raise AdminError('IMPORT_INVALID', '别名只允许字母、数字、点、短横线和下划线')
                if name in names or row['id'] in ids:
                    raise AdminError('IMPORT_DUPLICATE', '同一批次不能包含重复别名或条目')
                names.add(name); ids.add(row['id'])
                selected.append((copy.deepcopy(item), dict(row), name))
            # Reserve once before releasing the lock. No lock is held over SSH/network I/O.
            preview['used'].update(ids)
            preview['busy'].update(ids)
            preview['expires'] = time.time() + 600
        existing = {row.get('name') for row in self.app.call_list_handler().get('servers', [])}
        results = []
        for item, row, name in selected:
            result = {'id': item['id'], 'name': name, 'ok': False}
            deferred = row.get('allow_unverified') is True
            handler = self.app.handlers.get('create_unverified' if deferred else 'create')
            if name in existing:
                result['error'] = '该别名已存在，请修改导入别名后重试'
            elif deferred and item['id'] not in preview['failed']:
                result['error'] = '请先尝试导入，再确认是否先添加为待验证连接'
            elif not callable(handler):
                result['error'] = '当前工具不支持创建服务器'
            else:
                cached = preview['credentials'].get(item['id'], {})
                password = row.get('login_password') or cached.get('password')
                private_key = row.get('private_key') or cached.get('private_key')
                if row.get('private_key'):
                    password = None
                elif row.get('login_password'):
                    private_key = None
                username = row.get('user', item.get('user'))
                if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.@\\-]{0,127}', username):
                    result['error'] = '请明确填写 SSH 登录用户名，不会自动使用 root'
                elif any(value is not None and (not isinstance(value, str) or len(value) > 65536) for value in (password, private_key)):
                    result['error'] = '凭据格式无效'
                elif row.get('private_key') and row.get('login_password'):
                    result['error'] = '请仅选择密码或私钥中的一种'
                else:
                    payload = {key: item[key] for key in ('host', 'port', 'user')}
                    payload.update(name=name, user=username, sudo='ask')
                    if password:
                        payload.update(password=password, preserve_password=True)
                        cached = {'password': password}
                    if private_key:
                        payload['private_key'] = private_key
                        cached = {'private_key': private_key}
                    with self.lock:
                        preview['credentials'][item['id']] = cached
                    if deferred and cached.get('encrypted_password'):
                        payload['encrypted_login'] = dict(cached)
                    try:
                        if not deferred and not (password or private_key):
                            raise ValueError('credentials_required')
                        # Deliberately bypass generic exception reflection: SSH errors may echo credentials.
                        value = handler(payload)
                        if isinstance(value, dict) and value.get('ok') is False:
                            raise ValueError('create_failed')
                        result['ok'] = True
                        result.update(pending=deferred, verified=not deferred)
                        existing.add(name)
                        preview['credentials'].pop(item['id'], None)
                        preview['failed'].discard(item['id'])
                    except Exception as exc:
                        code = getattr(exc, 'code', None)
                        if not deferred and isinstance(code, str) and code in _SSH_FAILURE_HINTS:
                            result['code'] = code
                            result['error'] = _SSH_FAILURE_HINTS[code] + '（' + code + '）；可确认先添加为待验证连接'
                        else:
                            result['error'] = ('先添加失败，请检查本地存储与系统钥匙串' if deferred else
                                '连接或凭据验证未通过；可确认先添加为待验证连接')
                        result['can_add_unverified'] = not deferred
                        if not deferred:
                            preview['failed'].add(item['id'])
                    finally:
                        payload.clear()
            self.app.audit('servers.import', 'allow' if result['ok'] else 'deny', alias=name,
                           note=None if result['ok'] else 'IMPORT_FAILED')
            with self.lock:
                preview['busy'].discard(item['id'])
                if not result['ok']:
                    preview['used'].discard(item['id'])
            results.append(result)
        imported = sum(row['ok'] for row in results)
        return {'results': results, 'imported': imported, 'failed': len(results) - imported,
                'pending': sum(bool(row.get('pending')) for row in results)}


def dispatch(app, method, rest, body):
    if getattr(app, '_admin_api', None) is None:
        # ConsoleApp creates this before serving; fallback supports embedders.
        app._admin_api = AdminAPI(app)
    admin = app._admin_api
    if rest and rest[0] == 'ai':
        return admin.ai(method, rest[1:], body)
    if rest == ['imports', 'preview'] and method == 'POST':
        return admin.preview(body)
    if rest == ['imports', 'commit'] and method == 'POST':
        return admin.commit(body)
    raise AdminError('METHOD_NOT_ALLOWED', '不支持的导入请求', 405)
