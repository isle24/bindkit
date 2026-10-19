#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bindkit_console 内核后端测试（纯标准库，不依赖真实 sshbind/dbbind）。

运行：
    cd bindconsole/tests/backend && python3 -m unittest -v test_console
    # 或
    bash bindconsole/tests/backend/run_tests.sh

覆盖：
  * 首次 setup 密码 → 登录 → CSRF → 调 API 全链路
  * 未登录所有受保护 API → 401；status 最小暴露（Lead 约束）
  * 非 GET 缺/错 CSRF → 403；Cookie 篡改 → 401
  * 路径穿越（含编码变体/符号链接/目录列表/扩展名白名单）→ 400/404 且不泄露文件
  * 登录失败 5 次锁 60s（测试用 1s 验证恢复）
  * 非回环地址 / 端口占用 → 拒绝启动并给明确提示
  * 审批/审计（policy=False 内置文件读写降级 + fake policy 生产分支）
  * 两个控制台共用密码；daemon 启动与 SIGTERM 停止
"""

import http.client
import inspect
import io
import json
import os
import shutil
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))       # bindconsole/
for _path in (ROOT, HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import bindkit_console as bc           # noqa: E402
import fake_handlers                   # noqa: E402

PASSWORD = "Str0ng-test-password"
LAN_IPS = bc._local_ipv4_addresses()          # 本机局域网 IPv4（无则 LAN 用例 skip）


# ---------------------------------------------------------------------------
# HTTP 测试客户端
# ---------------------------------------------------------------------------

class Resp:
    def __init__(self, status, headers, body, set_cookies):
        self.status = status
        self._headers = list(headers)
        self.body = body
        self.set_cookies = list(set_cookies)

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    @property
    def json(self):
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except ValueError:
            return {}

    @property
    def data(self):
        return self.json.get("data")

    @property
    def error(self):
        return self.json.get("error") or {}

    @property
    def error_code(self):
        return self.error.get("code")

    def header(self, name):
        for key, value in self._headers:
            if key.lower() == name.lower():
                return value
        return None

    def header_all(self, name):
        return [value for key, value in self._headers if key.lower() == name.lower()]


class TestClient:
    """带 Cookie/CSRF 自动处理的 http.client 封装（每个请求独立连接）。"""

    def __init__(self, port, host="127.0.0.1"):
        self.port = port
        self.host = host
        self.cookies = {}
        self.csrf = None
        self.last_response = None

    # -- cookie / csrf --
    def set_cookie(self, name, value):
        self.cookies[name] = value

    def clear_cookies(self):
        self.cookies.clear()
        self.csrf = None

    def _update_cookies(self, set_cookies):
        for header in set_cookies:
            first = header.split(";", 1)[0].strip()
            if "=" not in first:
                continue
            name, value = first.split("=", 1)
            name = name.strip()
            if "max-age=0" in header.lower():
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value

    # -- 请求 --
    def request(self, method, path, json_body=None, raw_body=None, headers=None,
                csrf="auto"):
        body = None
        request_headers = {"Accept": "application/json"}
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif raw_body is not None:
            body = raw_body
        elif method in ("POST", "PUT", "DELETE", "PATCH"):
            body = b""
        if headers:
            request_headers.update(headers)
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            if csrf == "auto":
                if self.csrf:
                    request_headers.setdefault(bc.CSRF_HEADER, self.csrf)
            elif csrf is not None:
                request_headers[bc.CSRF_HEADER] = csrf
        if self.cookies:
            request_headers.setdefault(
                "Cookie", "; ".join("%s=%s" % (k, v) for k, v in self.cookies.items()))
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=request_headers)
            raw = conn.getresponse()
            status = raw.status
            response_headers = raw.getheaders()
            payload = raw.read()
            set_cookies = raw.msg.get_all("Set-Cookie") or []
        finally:
            conn.close()
        self._update_cookies(set_cookies)
        resp = Resp(status, response_headers, payload, set_cookies)
        self.last_response = resp
        return resp

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, json_body=None, **kwargs):
        return self.request("POST", path, json_body=json_body, **kwargs)

    def put(self, path, json_body=None, **kwargs):
        return self.request("PUT", path, json_body=json_body, **kwargs)

    def delete(self, path, json_body=None, **kwargs):
        return self.request("DELETE", path, json_body=json_body, **kwargs)


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def start_server(tool="ssh", home=None, web_root=None, handlers=None, policy=False,
                 **kwargs):
    server = bc.create_server(tool, port=0, handlers=handlers, home=home,
                              web_root=web_root, policy=policy, **kwargs)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    return server, thread


def stop_server(server, thread):
    try:
        server.shutdown()
    except Exception:                                   # noqa: BLE001
        pass
    thread.join(timeout=5)
    try:
        server.server_close()
    except Exception:                                   # noqa: BLE001
        pass


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def write_web_root(web_root):
    os.makedirs(web_root, exist_ok=True)
    index = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>bindconsole test</title>
<link rel="stylesheet" href="style.css">
<script>window.__BINDCONSOLE_TOOL__ = "__BINDCONSOLE_TOOL__";</script>
</head>
<body>
<div id="app">bindconsole test index</div>
<script src="app.js" defer></script>
<script src="ui.js" defer></script>
</body>
</html>
"""
    files = {
        "index.html": index,
        "app.js": "window.__BINDCONSOLE_TEST__ = true;\n",
        "ui.js": "/* ui */\n",
        "api.js": "/* api */\n",
        "pages.js": "/* pages */\n",
        "style.css": "body{color:#111}\n",
        "assets/logo.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>\n",
        "secret.py": "TOP_SECRET_PY_FILE = 'must-not-leak'\n",
        "readme.md": "must not be served\n",
    }
    for name, content in files.items():
        path = os.path.join(web_root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    try:
        os.symlink("/etc/passwd", os.path.join(web_root, "escape.html"))
    except OSError:
        pass
    os.makedirs(os.path.join(web_root, "assets-dir"), exist_ok=True)


class ApiAssertionsMixin:
    """API 响应断言（KernelTestCase 与自定义 server 的测试类共用）。"""

    def assert_error(self, resp, code, status=None):
        if status is not None:
            self.assertEqual(resp.status, status, resp.text)
        self.assertFalse(resp.json.get("ok"), resp.text)
        self.assertEqual(resp.error_code, code, resp.text)
        return resp.error

    def assert_ok(self, resp, status=200):
        self.assertEqual(resp.status, status, resp.text)
        self.assertTrue(resp.json.get("ok"), resp.text)
        return resp.data


class KernelTestCase(ApiAssertionsMixin, unittest.TestCase):
    TOOL = "ssh"
    AUTO_SETUP = True
    AUTO_LOGIN = False
    LOCKOUT_S = 60
    MAX_FAILURES = 5
    SESSION_TTL_S = None
    POLICY = False                     # False=测试降级；staticmethod(fake_handlers.make_fake_policy)=生产分支

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bindconsole-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.web_root = os.path.join(self.tmp, ".bindconsole", "web")
        write_web_root(self.web_root)
        self.handlers, self.state = fake_handlers.make_fake_handlers(self.TOOL)
        if callable(self.POLICY):
            self.fake_policy = self.POLICY()
            policy_arg = self.fake_policy
        else:
            self.fake_policy = None
            policy_arg = self.POLICY
        extra = {}
        if self.SESSION_TTL_S is not None:
            extra["session_ttl_s"] = self.SESSION_TTL_S
        self.server, self.thread = start_server(
            self.TOOL, home=self.tmp, web_root=self.web_root,
            handlers=self.handlers, policy=policy_arg,
            login_max_failures=self.MAX_FAILURES,
            login_lockout_s=self.LOCKOUT_S, **extra)
        self.addCleanup(stop_server, self.server, self.thread)
        self.port = self.server.server_address[1]
        self.client = TestClient(self.port)
        self.password = PASSWORD
        if self.AUTO_SETUP:
            self.setup_password()
        if self.AUTO_LOGIN:
            self.login()

    # -- 操作 --
    def setup_password(self, password=None):
        resp = self.client.post("/api/setup", {"password": password or self.password})
        self.assertEqual(resp.status, 201, resp.text)
        return resp

    def login(self, password=None):
        resp = self.client.post("/api/login", {"password": password or self.password})
        self.assertEqual(resp.status, 200, resp.text)
        self.client.csrf = resp.data["csrf_token"]
        return resp

    @property
    def secret_path(self):
        return os.path.join(self.tmp, ".bindconsole", "secret.json")


# ---------------------------------------------------------------------------
# 1. status 最小暴露 + setup / login
# ---------------------------------------------------------------------------

class SetupAndLoginTests(KernelTestCase):
    AUTO_SETUP = False
    AUTO_LOGIN = False

    def test_status_minimal_before_setup(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status, 200, resp.text)
        data = resp.data
        self.assertEqual(set(data.keys()),
                         {"setup_required", "setup_requires_token", "tool", "version"})
        self.assertTrue(data["setup_required"])
        self.assertFalse(data["setup_requires_token"])   # 回环模式无需 setup token
        self.assertEqual(data["tool"], "ssh")
        self.assertEqual(data["version"], bc.KERNEL_VERSION)
        # 未登录不得泄露路径/主机/策略/审计/别名
        self.assertNotIn(self.tmp, resp.text)
        for forbidden in ("servers", "policy", "audit", "aliases", "hosts"):
            self.assertNotIn(forbidden, resp.text)

    def test_setup_rejects_weak_password(self):
        resp = self.client.post("/api/setup", {"password": "short"})
        self.assert_error(resp, "WEAK_PASSWORD", 400)
        self.assertFalse(os.path.exists(self.secret_path))
        status = self.client.get("/api/status")
        self.assertTrue(status.data["setup_required"])

    def test_setup_rejects_missing_password(self):
        resp = self.client.post("/api/setup", {})
        self.assert_error(resp, "INVALID_BODY", 400)

    def test_setup_success_creates_secret_with_permissions(self):
        resp = self.client.post("/api/setup", {"password": PASSWORD})
        data = self.assert_ok(resp, 201)
        self.assertEqual(data["setup_required"], False)
        self.assertTrue(os.path.isfile(self.secret_path))
        self.assertEqual(os.stat(self.secret_path).st_mode & 0o777, 0o600)
        runtime_dir = os.path.join(self.tmp, ".bindconsole")
        self.assertEqual(os.stat(runtime_dir).st_mode & 0o777, 0o700)
        with open(self.secret_path, "r", encoding="utf-8") as fh:
            secret = json.load(fh)
        self.assertGreaterEqual(secret["password"]["iterations"], 200_000)
        self.assertEqual(secret["password"]["algo"], "pbkdf2_hmac_sha256")
        self.assertNotIn(PASSWORD, json.dumps(secret))       # 只存 hash

    def test_setup_second_time_conflict(self):
        self.client.post("/api/setup", {"password": PASSWORD})
        resp = self.client.post("/api/setup", {"password": "Another-password-1"})
        self.assert_error(resp, "ALREADY_SETUP", 409)

    def test_status_minimal_after_setup_before_login(self):
        self.client.post("/api/setup", {"password": PASSWORD})
        resp = self.client.get("/api/status")
        self.assertEqual(set(resp.data.keys()),
                         {"setup_required", "setup_requires_token", "tool", "version"})
        self.assertFalse(resp.data["setup_required"])
        self.assertFalse(resp.data["setup_requires_token"])
        self.assertNotIn("authenticated", resp.data)

    def test_login_before_setup_returns_setup_required(self):
        resp = self.client.post("/api/login", {"password": PASSWORD})
        self.assert_error(resp, "SETUP_REQUIRED", 400)

    def test_login_bad_password_401(self):
        self.client.post("/api/setup", {"password": PASSWORD})
        resp = self.client.post("/api/login", {"password": "wrong-password"})
        self.assert_error(resp, "INVALID_CREDENTIALS", 401)
        self.assertEqual(self.client.cookies, {})

    def test_login_success_cookie_attributes_and_csrf(self):
        self.client.post("/api/setup", {"password": PASSWORD})
        resp = self.client.post("/api/login", {"password": PASSWORD})
        data = self.assert_ok(resp, 200)
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["tool"], "ssh")
        self.assertEqual(data["expires_in"], bc.SESSION_TTL_S)
        self.assertTrue(data["csrf_token"])
        session_cookie = [c for c in resp.set_cookies if c.startswith(bc.SESSION_COOKIE + "=")]
        csrf_cookie = [c for c in resp.set_cookies if c.startswith(bc.CSRF_COOKIE + "=")]
        self.assertEqual(len(session_cookie), 1, resp.set_cookies)
        self.assertEqual(len(csrf_cookie), 1, resp.set_cookies)
        self.assertIn("HttpOnly", session_cookie[0])
        self.assertIn("SameSite=Strict", session_cookie[0])
        self.assertIn("Path=/", session_cookie[0])
        self.assertIn("Max-Age=%d" % bc.SESSION_TTL_S, session_cookie[0])
        self.assertNotIn("HttpOnly", csrf_cookie[0])          # JS 需读取
        self.assertIn("SameSite=Strict", csrf_cookie[0])
        self.assertEqual(self.client.cookies[bc.CSRF_COOKIE], data["csrf_token"])

    def test_status_authenticated_and_logout(self):
        self.client.post("/api/setup", {"password": PASSWORD})
        self.client.post("/api/login", {"password": PASSWORD})
        self.client.csrf = self.client.cookies[bc.CSRF_COOKIE]
        status = self.client.get("/api/status")
        data = self.assert_ok(status, 200)
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["resource"], "servers")
        self.assertEqual(data["port"], self.port)
        self.assertEqual(data["csrf_token"], self.client.csrf)
        self.assertIsInstance(data["pending_count"], int)
        logout = self.client.post("/api/logout")
        self.assert_ok(logout, 200)
        self.assertNotIn("authenticated", self.client.get("/api/status").data)
        self.assert_error(self.client.get("/api/servers"), "AUTH_REQUIRED", 401)


# ---------------------------------------------------------------------------
# 2. 未登录 → 401
# ---------------------------------------------------------------------------

class UnauthenticatedTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = False

    PROTECTED = [
        ("GET", "/api/servers"),
        ("GET", "/api/servers/demo-server"),
        ("POST", "/api/servers"),
        ("PUT", "/api/servers/demo-server"),
        ("DELETE", "/api/servers/demo-server"),
        ("POST", "/api/servers/demo-server/test"),
        ("GET", "/api/policy"),
        ("PUT", "/api/policy"),
        ("GET", "/api/approvals"),
        ("POST", "/api/approvals/apr_20261019_ab12cd/approve"),
        ("POST", "/api/approvals/apr_20261019_ab12cd/reject"),
        ("GET", "/api/audit"),
        ("POST", "/api/logout"),
        ("GET", "/api/databases"),
        ("GET", "/api/unknown-endpoint"),
    ]

    def test_all_protected_apis_401(self):
        for method, path in self.PROTECTED:
            with self.subTest(method=method, path=path):
                resp = self.client.request(
                    method, path,
                    json_body={"name": "demo-server"} if method in ("POST", "PUT") else None)
                self.assert_error(resp, "AUTH_REQUIRED", 401)
        # status 是公开 API，未登录也必须 200
        self.assertEqual(self.client.get("/api/status").status, 200)


# ---------------------------------------------------------------------------
# 3. CSRF / Cookie 篡改
# ---------------------------------------------------------------------------

class CsrfTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def test_get_needs_no_csrf(self):
        self.assert_ok(self.client.get("/api/servers"), 200)

    def test_post_without_csrf_403(self):
        resp = self.client.post("/api/servers", {"name": "demo-server"}, csrf=None)
        self.assert_error(resp, "CSRF_MISSING", 403)
        self.assertEqual(self.state.items, {})

    def test_wrong_csrf_token_403(self):
        resp = self.client.post("/api/servers", {"name": "demo-server"}, csrf="deadbeef" * 4)
        self.assert_error(resp, "CSRF_INVALID", 403)

    def test_csrf_cookie_mismatch_403(self):
        original = self.client.cookies[bc.CSRF_COOKIE]
        self.client.cookies[bc.CSRF_COOKIE] = "0" * 32
        try:
            resp = self.client.post("/api/servers", {"name": "demo-server"})
        finally:
            self.client.cookies[bc.CSRF_COOKIE] = original
        self.assert_error(resp, "CSRF_INVALID", 403)

    def test_put_and_delete_need_csrf(self):
        self.assert_error(self.client.put("/api/servers/x", {"note": "n"}, csrf=None),
                          "CSRF_MISSING", 403)
        self.assert_error(self.client.delete("/api/servers/x", csrf=None),
                          "CSRF_MISSING", 403)

    def test_logout_needs_csrf(self):
        self.assert_error(self.client.post("/api/logout", csrf=None),
                          "CSRF_MISSING", 403)

    def test_approve_needs_csrf(self):
        fake_handlers.write_approval(
            self.tmp, "ssh", fake_handlers.make_approval(approval_id="apr_nocsrf_1"))
        resp = self.client.post("/api/approvals/apr_nocsrf_1/approve", {}, csrf=None)
        self.assert_error(resp, "CSRF_MISSING", 403)
        saved = fake_handlers.read_approval(self.tmp, "ssh", "apr_nocsrf_1")
        self.assertEqual(saved["status"], "pending")


class CookieTamperTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def _tampered(self, token):
        return token[:-1] + ("0" if token[-1] != "0" else "1")

    def test_tampered_signature_401(self):
        token = self.client.cookies[bc.SESSION_COOKIE]
        self.client.set_cookie(bc.SESSION_COOKIE, self._tampered(token))
        self.assert_error(self.client.get("/api/servers"), "AUTH_REQUIRED", 401)

    def test_random_cookie_401(self):
        self.client.set_cookie(bc.SESSION_COOKIE, "v1.9999999999.deadbeef.deadbeef")
        self.assert_error(self.client.get("/api/audit"), "AUTH_REQUIRED", 401)

    def test_missing_cookie_401(self):
        self.client.clear_cookies()
        self.assert_error(self.client.get("/api/servers"), "AUTH_REQUIRED", 401)

    def test_truncated_session_cookie_401(self):
        token = self.client.cookies[bc.SESSION_COOKIE]
        self.client.set_cookie(bc.SESSION_COOKIE, token.split(".")[0] + ".x")
        self.assert_error(self.client.get("/api/servers"), "AUTH_REQUIRED", 401)

    def test_weird_cookie_401_not_500(self):
        for value in ("bindconsole_session=v1.9999999999.\u00f1.\u00fc",
                      "bindconsole_session===",
                      "bindconsole_session=v1.9999999999.deadbeef"):
            with self.subTest(value=value):
                resp = self.client.request("GET", "/api/servers",
                                           headers={"Cookie": value})
                self.assert_error(resp, "AUTH_REQUIRED", 401)


# ---------------------------------------------------------------------------
# 3.5 登出服务端吊销（CONTRACT §7.1：logout 后旧 Cookie 必须 401）
# ---------------------------------------------------------------------------

class LogoutRevocationTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def _replay(self, cookies):
        client = TestClient(self.port)
        client.cookies = dict(cookies)
        return client

    def test_logout_revokes_old_cookie_server_side(self):
        old_cookies = dict(self.client.cookies)
        old_csrf = self.client.csrf
        self.assert_ok(self.client.post("/api/logout"), 200)
        # 旧 Cookie 立即失效（不是只清客户端 Cookie）
        replay = self._replay(old_cookies)
        self.assert_error(replay.get("/api/servers"), "AUTH_REQUIRED", 401)
        # 旧 Cookie + 旧 CSRF 的写请求同样 401（认证先于 CSRF）
        replay.csrf = old_csrf
        self.assert_error(replay.post("/api/logout"), "AUTH_REQUIRED", 401)
        # 重新登录后新会话可用，旧 Cookie 依旧失效
        self.client.clear_cookies()
        self.login()
        self.assert_ok(self.client.get("/api/servers"), 200)
        self.assert_error(self._replay(old_cookies).get("/api/audit"),
                          "AUTH_REQUIRED", 401)

    def test_logout_token_revoked_after_relogin(self):
        old_token = self.client.cookies[bc.SESSION_COOKIE]
        self.client.post("/api/logout")
        self.client.clear_cookies()
        self.login()
        replay = TestClient(self.port)
        replay.set_cookie(bc.SESSION_COOKIE, old_token)
        self.assert_error(replay.get("/api/servers"), "AUTH_REQUIRED", 401)

    def test_failed_csrf_logout_does_not_revoke(self):
        old_cookies = dict(self.client.cookies)
        self.assert_error(self.client.post("/api/logout", csrf=None),
                          "CSRF_MISSING", 403)
        # 登出请求未成功 → 不应吊销会话
        self.assert_ok(self._replay(old_cookies).get("/api/servers"), 200)

    def test_session_epoch_persisted_increments_and_file_mode(self):
        with open(self.secret_path, "r", encoding="utf-8") as fh:
            before = json.load(fh)["session_epoch"]
        self.assert_ok(self.client.post("/api/logout"), 200)
        with open(self.secret_path, "r", encoding="utf-8") as fh:
            after = json.load(fh)["session_epoch"]
        self.assertEqual(after, before + 1)
        self.assertEqual(os.stat(self.secret_path).st_mode & 0o777, 0o600)

    def test_logout_response_marks_revoked(self):
        data = self.assert_ok(self.client.post("/api/logout"), 200)
        self.assertTrue(data["revoked"])
        self.assertFalse(data["authenticated"])

    def test_old_v1_token_rejected(self):
        # 升级前 v1 token 无 epoch，必须一律拒绝（否则可绕过吊销）
        replay = TestClient(self.port)
        replay.set_cookie(bc.SESSION_COOKIE, "v1.9999999999.0123456789abcdef")
        self.assert_error(replay.get("/api/servers"), "AUTH_REQUIRED", 401)


# ---------------------------------------------------------------------------
# 4. 登录限速
# ---------------------------------------------------------------------------

class LoginLockoutTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = False
    LOCKOUT_S = 1
    MAX_FAILURES = 5

    def test_lockout_after_five_failures_and_recovery(self):
        for attempt in range(1, 5):
            resp = self.client.post("/api/login", {"password": "bad-%d" % attempt})
            self.assert_error(resp, "INVALID_CREDENTIALS", 401)
        fifth = self.client.post("/api/login", {"password": "bad-5"})
        self.assert_error(fifth, "LOGIN_LOCKED", 429)
        self.assertIn("Retry-After", {k for k, _ in fifth._headers})
        locked = self.client.post("/api/login", {"password": PASSWORD})
        self.assert_error(locked, "LOGIN_LOCKED", 429)
        self.assertGreaterEqual(int(locked.header("Retry-After")), 1)
        time.sleep(1.3)
        recovered = self.client.post("/api/login", {"password": PASSWORD})
        self.assert_ok(recovered, 200)


# ---------------------------------------------------------------------------
# 5. 静态资源 / 路径穿越 / 安全头
# ---------------------------------------------------------------------------

class StaticTests(KernelTestCase):
    AUTO_SETUP = False
    AUTO_LOGIN = False
    WEB = True

    def test_index_served_and_tool_injected(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status, 200, resp.text)
        self.assertIn("text/html", resp.header("Content-Type"))
        self.assertIn('window.__BINDCONSOLE_TOOL__ = "ssh";', resp.text)
        self.assertNotIn('"__BINDCONSOLE_TOOL__"', resp.text)
        self.assertEqual(resp.header("Cache-Control"), "no-store")
        self.assertEqual(resp.header("X-Content-Type-Options"), "nosniff")
        # Server 头不回显 Python 版本
        self.assertEqual(resp.header("Server"), "bindconsole/" + bc.KERNEL_VERSION)
        self.assertNotIn("Python", resp.header("Server"))

    def test_static_assets_mime(self):
        js = self.client.get("/app.js")
        self.assertEqual(js.status, 200)
        self.assertIn("javascript", js.header("Content-Type"))
        css = self.client.get("/style.css")
        self.assertEqual(css.status, 200)
        self.assertIn("text/css", css.header("Content-Type"))
        svg = self.client.get("/assets/logo.svg")
        self.assertEqual(svg.status, 200)
        self.assertIn("image/svg+xml", svg.header("Content-Type"))

    def test_spa_fallback(self):
        resp = self.client.get("/servers/demo-server/detail")
        self.assertEqual(resp.status, 200, resp.text)
        self.assertIn("bindconsole test index", resp.text)
        self.assertIn('window.__BINDCONSOLE_TOOL__ = "ssh";', resp.text)

    def test_missing_asset_404(self):
        self.assert_error(self.client.get("/missing.js"), "NOT_FOUND", 404)

    def test_directory_requests_404_no_listing(self):
        resp = self.client.get("/assets-dir")
        self.assert_error(resp, "NOT_FOUND", 404)
        self.assertNotIn("index of", resp.text.lower())

    def test_disallowed_extension_404(self):
        for path in ("/secret.py", "/readme.md"):
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assert_error(resp, "NOT_FOUND", 404)
                self.assertNotIn("must-not-leak", resp.text)
                self.assertNotIn("must not be served", resp.text)

    def test_path_traversal_rejected(self):
        paths = [
            "/../../etc/passwd",
            "/%2e%2e%2f%2e%2e%2fetc/passwd",
            "/%2e%2e%2fetc%2fpasswd",
            "/..%2f..%2fetc%2fpasswd",
            "/....//....//etc/passwd",
            "/%2e%2e%5cetc%5cpasswd",
            "/%00index.html",
            "/.hidden",
        ]
        for path in paths:
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertIn(resp.status, (400, 404),
                              "path=%s status=%s body=%s" % (path, resp.status, resp.text[:200]))
                self.assertNotIn("root:", resp.text)
                self.assertNotIn("/bin/", resp.text)

    def test_symlink_escape_rejected(self):
        if not os.path.islink(os.path.join(self.web_root, "escape.html")):
            self.skipTest("当前文件系统不支持/未创建符号链接")
        resp = self.client.get("/escape.html")
        self.assertIn(resp.status, (400, 404), resp.text)
        self.assertNotIn("root:", resp.text)

    def test_security_headers_on_api_and_errors(self):
        for resp in (self.client.get("/api/status"),
                     self.client.get("/api/servers"),
                     self.client.get("/missing.js")):
            self.assertEqual(resp.header("Cache-Control"), "no-store")
            self.assertEqual(resp.header("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.header("X-Frame-Options"), "DENY")
            self.assertIsNotNone(resp.header("Content-Security-Policy"))

    def test_run_console_refuses_public_host(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            rc = bc.run_console("ssh", port=0, handlers=self.handlers,
                                host="8.8.8.8", home=self.tmp,
                                web_root=self.web_root)
        self.assertEqual(rc, 1)
        self.assertIn("拒绝", stderr.getvalue())

    def test_create_server_refuses_public_host(self):
        with self.assertRaises(bc.ConsoleStartupError) as ctx:
            bc.create_server("ssh", port=0, handlers=self.handlers,
                             host="8.8.8.8", home=self.tmp,
                             web_root=self.web_root, policy=False)
        self.assertIn("拒绝绑定非局域网地址", str(ctx.exception))


class MissingWebRootTests(ApiAssertionsMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bindconsole-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.handlers, _ = fake_handlers.make_fake_handlers("ssh")
        self.server, self.thread = start_server(
            "ssh", home=self.tmp, web_root=os.path.join(self.tmp, "no-such-web"),
            handlers=self.handlers, policy=False)
        self.addCleanup(stop_server, self.server, self.thread)
        self.client = TestClient(self.server.server_address[1])

    def test_missing_web_root_503_with_install_hint(self):
        resp = self.client.get("/")
        self.assert_error(resp, "WEB_UI_MISSING", 503)
        self.assertIn("install.sh", resp.error.get("hint", ""))
        self.assertEqual(self.client.get("/api/status").status, 200)


class DbInjectionTests(KernelTestCase):
    TOOL = "db"
    AUTO_SETUP = False
    AUTO_LOGIN = False

    def test_index_injects_db(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status, 200, resp.text)
        self.assertIn('window.__BINDCONSOLE_TOOL__ = "db";', resp.text)
        self.assertEqual(self.client.get("/api/status").data["tool"], "db")


# ---------------------------------------------------------------------------
# 6. 工具 handler 全链路（ssh / db）+ 异常映射
# ---------------------------------------------------------------------------

class ToolHandlersSshTests(KernelTestCase):
    TOOL = "ssh"
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def test_ssh_crud_flow(self):
        created = self.client.post("/api/servers", {
            "name": "demo-server", "user": "root", "host": "10.0.0.8", "port": 22,
            "password": "hunter2-ssh-secret", "sudo": "ask", "note": "主服务器",
        })
        data = self.assert_ok(created, 201)
        self.assertEqual(data["name"], "demo-server")
        self.assertTrue(data["has_password"])
        listed = self.assert_ok(self.client.get("/api/servers"), 200)
        self.assertEqual([s["name"] for s in listed["servers"]], ["demo-server"])
        single = self.assert_ok(self.client.get("/api/servers/demo-server"), 200)
        self.assertEqual(single["host"], "10.0.0.8")
        updated = self.assert_ok(self.client.put("/api/servers/demo-server",
                                                 {"sudo": "allow", "note": "已改"}))
        self.assertEqual(updated["sudo"], "allow")
        tested = self.assert_ok(self.client.post("/api/servers/demo-server/test"))
        self.assertTrue(tested["ok"])
        deleted = self.assert_ok(self.client.delete("/api/servers/demo-server"))
        self.assertTrue(deleted["deleted"])
        self.assertEqual(self.assert_ok(self.client.get("/api/servers"))["servers"], [])
        self.assertEqual(
            [call[0] for call in self.state.calls],
            ["create", "list", "get", "update", "test", "delete", "list"])

    def test_credentials_never_echoed(self):
        ssh_secret = "hunter2-UNIQUE-ssh-secret"
        key_secret = "-----BEGIN OPENSSH PRIVATE KEY-----UNIQUE-KEY"
        resp = self.client.post("/api/servers", {
            "name": "cred-srv", "user": "root", "host": "127.0.0.1",
            "password": ssh_secret, "private_key": key_secret,
        })
        self.assert_ok(resp, 201)
        self.assertNotIn(ssh_secret, resp.text)
        self.assertNotIn("UNIQUE-KEY", resp.text)
        self.assertNotIn("private_key", resp.text)
        self.assertNotIn(ssh_secret, self.client.get("/api/servers").text)
        self.assertNotIn(ssh_secret, self.client.get("/api/audit?tool=all").text)
        audit_log = os.path.join(self.tmp, ".bindconsole", "audit.log")
        with open(audit_log, "r", encoding="utf-8") as fh:
            self.assertNotIn(ssh_secret, fh.read())
        # 凭证确实到达了工具侧 handler（证明不是内核随手丢掉）
        self.assertEqual(self.state.credentials["cred-srv"]["password"], ssh_secret)
        self.assertEqual(self.state.credentials["cred-srv"]["private_key"], key_secret)

    def test_invalid_names_rejected(self):
        cases = ["../evil", "..", "a b", "a/b", "名前", "", "a" * 200]
        for name in cases:
            with self.subTest(name=name):
                resp = self.client.post("/api/servers", {"name": name})
                self.assert_error(resp, "INVALID_NAME", 400)
        self.assertEqual(self.state.items, {})

    def test_invalid_name_in_path_rejected(self):
        for path in ("/api/servers/..%2f..%2fetc", "/api/servers/..",
                     "/api/servers/%2e%2e"):
            with self.subTest(path=path):
                resp = self.client.delete(path)
                # 路径里出现 .. 段 → 更准确的 PATH_INVALID；均 400 拒绝
                self.assert_error(resp, "PATH_INVALID", 400)
        resp = self.client.delete("/api/servers/bad%20name")
        self.assert_error(resp, "INVALID_NAME", 400)

    def test_missing_name_rejected(self):
        resp = self.client.post("/api/servers", {"host": "127.0.0.1"})
        self.assert_error(resp, "MISSING_FIELD", 400)

    def test_unknown_resource_404(self):
        self.assert_error(self.client.get("/api/databases"), "NOT_FOUND", 404)
        self.assert_error(self.client.get("/api/unknown-endpoint"), "NOT_FOUND", 404)

    def test_method_not_allowed(self):
        resp = self.client.request("PUT", "/api/status", json_body={})
        self.assert_error(resp, "METHOD_NOT_ALLOWED", 405)
        self.assertEqual(resp.header("Allow"), "GET")
        resp = self.client.request("GET", "/api/servers/demo-server/test")
        self.assert_error(resp, "METHOD_NOT_ALLOWED", 405)

    def test_policy_get_put(self):
        policy = self.assert_ok(self.client.get("/api/policy"), 200)
        self.assertEqual(policy["version"], 1)
        updated = self.assert_ok(self.client.put("/api/policy", {"defaults": {"sudo": "deny"}}))
        self.assertEqual(updated["defaults"]["sudo"], "deny")
        self.assertEqual(self.fake_policy, None)
        self.assertIn(("policy_put", {"defaults": {"sudo": "deny"}}), self.state.calls)

    def test_handler_console_error_mapping(self):
        self.state.fail_next = "console_error"
        resp = self.client.post("/api/servers", {"name": "x"})
        self.assert_error(resp, "FAKE_CONFLICT", 409)
        self.assertEqual(resp.error.get("hint"), "fake hint")

    def test_handler_value_error_mapping(self):
        self.state.fail_next = "value_error"
        resp = self.client.post("/api/servers", {"name": "x"})
        self.assert_error(resp, "INVALID_REQUEST", 400)
        self.assertIn("人话错误", resp.error["message"])

    def test_handler_runtime_error_hides_traceback(self):
        warnings = []
        original_warn = bc._warn
        bc._warn = lambda message: warnings.append(message)
        try:
            self.state.fail_next = "runtime_error"
            resp = self.client.post("/api/servers", {"name": "x"})
        finally:
            bc._warn = original_warn
        self.assert_error(resp, "INTERNAL", 500)
        self.assertNotIn("hunter2-should-never-leak", resp.text)
        self.assertNotIn("Traceback", resp.text)
        self.assertTrue(any("Traceback" in message for message in warnings),
                        "服务端日志应记录 traceback")
        # 内核写审计 decision=error
        audit = self.assert_ok(self.client.get("/api/audit?tool=all"), 200)
        self.assertTrue(any(entry.get("decision") == "error"
                            for entry in audit["entries"]), audit["entries"])

    def test_delete_merges_query_into_body(self):
        self.client.post("/api/servers", {
            "name": "del-srv", "password": "p", "private_key": "k"})
        resp = self.client.delete("/api/servers/del-srv?delete_key=true")
        data = self.assert_ok(resp, 200)
        self.assertTrue(data["key_removed"])
        delete_call = [call for call in self.state.calls if call[0] == "delete"][-1]
        self.assertEqual(delete_call[2]["delete_key"], "true")
        self.assertNotIn("del-srv", self.state.credentials)


class ToolHandlersDbTests(KernelTestCase):
    TOOL = "db"
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def test_db_crud_flow(self):
        created = self.client.post("/api/databases", {
            "alias": "demo-mysql", "engine": "mysql", "host": "127.0.0.1",
            "port": 3306, "user": "root", "password": "db-secret",
            "database": "appdb", "max_level": "read",
        })
        data = self.assert_ok(created, 201)
        self.assertEqual(data["alias"], "demo-mysql")
        self.assertTrue(data["has_password"])
        listed = self.assert_ok(self.client.get("/api/databases"), 200)
        self.assertEqual([d["alias"] for d in listed["databases"]], ["demo-mysql"])
        updated = self.assert_ok(self.client.put("/api/databases/demo-mysql",
                                                 {"max_level": "ddl"}))
        self.assertEqual(updated["max_level"], "ddl")
        tested = self.assert_ok(self.client.post("/api/databases/demo-mysql/test"))
        self.assertTrue(tested["ok"])
        deleted = self.assert_ok(self.client.delete("/api/databases/demo-mysql"))
        self.assertTrue(deleted["deleted"])
        self.assertEqual(self.assert_ok(self.client.get("/api/databases"))["databases"], [])

    def test_db_allowed_schemas_roundtrip(self):
        created = self.client.post("/api/databases", {
            "alias": "pg-schema", "engine": "postgres", "host": "127.0.0.1",
            "user": "postgres", "database": "analytics",
            "allowed_schemas": ["public", "app"]})
        self.assert_ok(created, 201)
        listed = self.assert_ok(self.client.get("/api/databases"), 200)["databases"]
        item = [d for d in listed if d["alias"] == "pg-schema"][0]
        self.assertEqual(item["allowed_schemas"], ["public", "app"])
        updated = self.assert_ok(self.client.put("/api/databases/pg-schema",
                                                 {"allowed_schemas": None}))
        self.assertIsNone(updated["allowed_schemas"])

    def test_db_missing_alias_rejected(self):
        resp = self.client.post("/api/databases", {"name": "wrong-key"})
        self.assert_error(resp, "MISSING_FIELD", 400)

    def test_db_invalid_alias_rejected(self):
        for alias in ("../evil", "a b", ".."):
            with self.subTest(alias=alias):
                resp = self.client.post("/api/databases", {"alias": alias})
                self.assert_error(resp, "INVALID_NAME", 400)


# ---------------------------------------------------------------------------
# 7. 审批 / 审计（policy=False 测试降级路径）
# ---------------------------------------------------------------------------

class ApprovalFallbackTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def setUp(self):
        super().setUp()
        self.ap = fake_handlers.make_approval(approval_id="apr_20261019_ab12cd")
        fake_handlers.write_approval(self.tmp, "ssh", self.ap)

    def test_pending_list_and_status_filter(self):
        data = self.assert_ok(self.client.get("/api/approvals"), 200)
        self.assertEqual([a["id"] for a in data["approvals"]], [self.ap["id"]])
        self.assertEqual(data["approvals"][0]["status"], "pending")
        all_data = self.assert_ok(self.client.get("/api/approvals?status=all"), 200)
        self.assertEqual(len(all_data["approvals"]), 1)
        self.assert_error(self.client.get("/api/approvals?status=bogus"),
                          "INVALID_PARAM", 400)

    def test_approve_flow_persists_and_audits(self):
        resp = self.client.post("/api/approvals/apr_20261019_ab12cd/approve",
                                {"consumes": 3, "ttl_s": 300, "note": "演示批准"})
        data = self.assert_ok(resp, 200)
        approval = data["approval"]
        self.assertEqual(approval["status"], "approved")
        self.assertEqual(approval["consumes_left"], 3)
        self.assertEqual(approval["decided_by"], "web")
        self.assertIsNotNone(approval["decided_at"])
        self.assertEqual(approval["note"], "演示批准")
        saved = fake_handlers.read_approval(self.tmp, "ssh", self.ap["id"])
        self.assertEqual(saved["status"], "approved")
        self.assertEqual(saved["consumes_left"], 3)
        self.assertEqual(os.stat(os.path.join(
            fake_handlers.approvals_dir(self.tmp, "ssh"), self.ap["id"] + ".json")
        ).st_mode & 0o777, 0o600)
        audit = self.assert_ok(self.client.get("/api/audit?tool=all"), 200)["entries"]
        approve_entries = [e for e in audit
                           if e.get("decision") == "approve" and e.get("request_id") == self.ap["id"]]
        self.assertTrue(approve_entries, audit)
        self.assertEqual(approve_entries[0]["actor"], "web")
        with open(os.path.join(self.tmp, ".bindconsole", "audit.log"),
                  "r", encoding="utf-8") as fh:
            self.assertIn("approve", fh.read())

    def test_reject_flow(self):
        resp = self.client.post("/api/approvals/apr_20261019_ab12cd/reject",
                                {"note": "不允许重启 nginx"})
        data = self.assert_ok(resp, 200)
        self.assertEqual(data["approval"]["status"], "denied")
        self.assertEqual(data["approval"]["note"], "不允许重启 nginx")
        saved = fake_handlers.read_approval(self.tmp, "ssh", self.ap["id"])
        self.assertEqual(saved["status"], "denied")
        audit = self.assert_ok(self.client.get("/api/audit?tool=all"), 200)["entries"]
        self.assertTrue(any(e.get("decision") == "reject" for e in audit))

    def test_approve_unknown_404(self):
        resp = self.client.post("/api/approvals/apr_doesnotexist/approve", {})
        self.assert_error(resp, "APPROVAL_NOT_FOUND", 404)

    def test_approve_twice_conflict(self):
        self.client.post("/api/approvals/apr_20261019_ab12cd/approve", {})
        resp = self.client.post("/api/approvals/apr_20261019_ab12cd/approve", {})
        self.assert_error(resp, "APPROVAL_ALREADY_DECIDED", 409)

    def test_approve_invalid_params(self):
        for body in ({"consumes": 0}, {"consumes": 11}, {"consumes": "3"},
                     {"ttl_s": 10}, {"ttl_s": 86401}, {"ttl_s": "300"}):
            with self.subTest(body=body):
                resp = self.client.post("/api/approvals/apr_20261019_ab12cd/approve", body)
                self.assert_error(resp, "INVALID_PARAM", 400)
        saved = fake_handlers.read_approval(self.tmp, "ssh", self.ap["id"])
        self.assertEqual(saved["status"], "pending")

    def test_expired_approval(self):
        expired = fake_handlers.make_approval(approval_id="apr_expired", expires_offset=-30)
        fake_handlers.write_approval(self.tmp, "ssh", expired)
        pending = self.assert_ok(self.client.get("/api/approvals"), 200)["approvals"]
        self.assertEqual([a["id"] for a in pending], [self.ap["id"]])
        all_items = self.assert_ok(self.client.get("/api/approvals?status=all"), 200)["approvals"]
        expired_item = [a for a in all_items if a["id"] == "apr_expired"][0]
        self.assertEqual(expired_item["status"], "expired")
        resp = self.client.post("/api/approvals/apr_expired/approve", {})
        self.assert_error(resp, "APPROVAL_EXPIRED", 409)

    def test_invalid_approval_id_path_rejected(self):
        resp = self.client.post("/api/approvals/..%2f..%2fetc/approve", {})
        self.assert_error(resp, "PATH_INVALID", 400)

    def test_audit_limit_and_order_and_tool_filter(self):
        for index in range(5):
            fake_handlers.write_approval(
                self.tmp, "ssh",
                fake_handlers.make_approval(approval_id="apr_audit_%d" % index))
            self.client.post("/api/approvals/apr_audit_%d/reject" % index, {"note": "n%d" % index})
        entries = self.assert_ok(self.client.get("/api/audit?limit=3"), 200)["entries"]
        self.assertEqual(len(entries), 3)
        timestamps = [e.get("ts") for e in entries]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))
        all_entries = self.assert_ok(self.client.get("/api/audit?tool=all&limit=100"), 200)["entries"]
        self.assertTrue(all(e.get("tool") in ("ssh", "db") for e in all_entries))
        self.assert_error(self.client.get("/api/audit?tool=bogus"), "INVALID_PARAM", 400)
        self.assert_error(self.client.get("/api/audit?limit=abc"), "INVALID_PARAM", 400)

    def test_audit_never_contains_password(self):
        secret = "audit-UNIQUE-secret-9f8e"
        self.client.post("/api/servers", {"name": "audit-srv", "password": secret})
        entries = self.assert_ok(self.client.get("/api/audit?tool=all&limit=200"),
                                 200)["entries"]
        self.assertNotIn(secret, json.dumps(entries, ensure_ascii=False))


# ---------------------------------------------------------------------------
# 8. 生产分支：内核必须调用 bindkit_policy（fake policy 注入）
# ---------------------------------------------------------------------------

class ProductionPolicyTests(KernelTestCase):
    POLICY = staticmethod(fake_handlers.make_fake_policy)
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def test_status_pending_count_from_policy(self):
        self.fake_policy.add_pending()
        status = self.assert_ok(self.client.get("/api/status"), 200)
        self.assertEqual(status["pending_count"], 1)

    def test_approvals_list_uses_policy_module(self):
        self.fake_policy.add_pending()
        data = self.assert_ok(self.client.get("/api/approvals"), 200)
        self.assertEqual(data["approvals"][0]["id"], "apr_test_0001")
        self.assertIn(("list_approvals", "ssh", "pending"), self.fake_policy.calls)

    def test_approve_uses_policy_module(self):
        self.fake_policy.add_pending()
        resp = self.client.post("/api/approvals/apr_test_0001/approve",
                                {"consumes": 2, "ttl_s": 300})
        data = self.assert_ok(resp, 200)
        self.assertEqual(data["approval"]["status"], "approved")
        self.assertEqual(data["approval"]["consumes_left"], 2)
        approve_calls = [c for c in self.fake_policy.calls if c[0] == "approve"]
        self.assertEqual(approve_calls[0][3:5], (2, 300))
        self.assertTrue(any(r["action"] == "sudo" and r["decision"] == "approve"
                            for r in self.fake_policy.audit_records))

    def test_handler_audit_goes_through_policy(self):
        self.client.post("/api/servers", {"name": "audit-through-policy"})
        records = [r for r in self.fake_policy.audit_records
                   if r["action"] == "servers.create"]
        self.assertTrue(records)
        self.assertEqual(records[0]["decision"], "allow")
        self.assertEqual(records[0]["alias"], "audit-through-policy")

    def test_audit_endpoint_uses_read_audit(self):
        self.fake_policy.audit("ssh", "web", None, "login", "allow")
        data = self.assert_ok(self.client.get("/api/audit?tool=all"), 200)
        self.assertTrue(any(e.get("action") == "login" for e in data["entries"]))
        self.assertIn(("read_audit", None, bc.AUDIT_DEFAULT_LIMIT), self.fake_policy.calls)


# ---------------------------------------------------------------------------
# 9. 启动失败路径
# ---------------------------------------------------------------------------

class StartupErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bindconsole-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.handlers, _ = fake_handlers.make_fake_handlers("ssh")

    def test_run_console_signature_frozen_order(self):
        params = list(inspect.signature(bc.run_console).parameters)
        self.assertEqual(params[:5],
                         ["tool", "port", "handlers", "daemon", "open_browser"])
        self.assertEqual(bc.default_port("ssh"), 8790)
        self.assertEqual(bc.default_port("db"), 8791)
        self.assertTrue(bc.is_loopback("127.0.0.1"))
        self.assertFalse(bc.is_loopback("0.0.0.0"))
        self.assertFalse(bc.is_loopback("localhost"))

    def test_allowed_bind_targets(self):
        self.assertEqual(bc._classify_bind_host("127.0.0.1").kind, "loopback")
        self.assertEqual(bc._classify_bind_host("0.0.0.0").kind, "wildcard")
        self.assertEqual(bc._classify_bind_host("::1").kind, "loopback")
        lan_ips = bc._local_ipv4_addresses()
        if lan_ips:
            target = bc._classify_bind_host(lan_ips[0])
            self.assertEqual(target.kind, "lan")
            self.assertEqual(target.host, lan_ips[0])

    def test_refused_bind_targets(self):
        for host in ("8.8.8.8", "203.0.113.5", "localhost", "example.com", "::"):
            with self.subTest(host=host):
                with self.assertRaises(bc.ConsoleStartupError) as ctx:
                    bc.create_server("ssh", port=0, handlers=self.handlers,
                                     host=host, home=self.tmp, policy=False)
                message = str(ctx.exception) + " " + (ctx.exception.hint or "")
                self.assertTrue("局域网" in message or "hostname" in message
                                or "不受支持" in message, message)

    def test_run_console_refuses_public_host_returns_1(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = bc.run_console("ssh", port=0, handlers=self.handlers,
                                host="8.8.8.8", home=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("拒绝绑定非局域网地址", stderr.getvalue())

    def test_invalid_port_refused(self):
        with self.assertRaises(bc.ConsoleStartupError):
            bc.create_server("ssh", port=70000, handlers=self.handlers,
                             home=self.tmp, policy=False)

    def test_port_in_use_error_has_hint(self):
        first, thread = start_server("ssh", home=self.tmp, handlers=self.handlers,
                                     policy=False)
        self.addCleanup(stop_server, first, thread)
        port = first.server_address[1]
        with self.assertRaises(bc.ConsoleStartupError) as ctx:
            bc.create_server("ssh", port=port, handlers=self.handlers,
                             home=self.tmp, policy=False)
        message = str(ctx.exception)
        hint = ctx.exception.hint or ""
        self.assertIn("占用", message)
        self.assertIn("--port", hint)

    def test_run_console_port_in_use_returns_1(self):
        first, thread = start_server("ssh", home=self.tmp, handlers=self.handlers,
                                     policy=False)
        self.addCleanup(stop_server, first, thread)
        port = first.server_address[1]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = bc.run_console("ssh", port=port, handlers=self.handlers,
                                home=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("占用", stderr.getvalue())
        self.assertIn("--port", stderr.getvalue())

    def test_missing_policy_module_refused_in_production(self):
        from unittest import mock
        with mock.patch.object(bc, "_load_policy_module",
                               return_value=(None, "ImportError: 模拟缺失")):
            with self.assertRaises(bc.ConsoleStartupError) as ctx:
                bc.create_server("ssh", port=0, handlers=self.handlers,
                                 home=self.tmp)
        self.assertIn("bindkit_policy", str(ctx.exception))
        self.assertIn("install.sh", ctx.exception.hint or "")

    def test_incomplete_policy_module_refused(self):
        class IncompletePolicy:
            def audit(self, *args, **kwargs):
                return None
        with self.assertRaises(bc.ConsoleStartupError) as ctx:
            bc.create_server("ssh", port=0, handlers=self.handlers,
                             home=self.tmp, policy=IncompletePolicy())
        self.assertIn("接口不完整", str(ctx.exception))

    def test_invalid_tool_raises(self):
        with self.assertRaises(ValueError):
            bc.create_server("nope", port=0, handlers=self.handlers,
                             home=self.tmp, policy=False)


# ---------------------------------------------------------------------------
# 10. 两个控制台共存 / 共用密码
# ---------------------------------------------------------------------------

class SharedConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bindconsole-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.web_root = os.path.join(self.tmp, ".bindconsole", "web")
        write_web_root(self.web_root)
        self.servers = []
        for tool in ("ssh", "db"):
            handlers, _state = fake_handlers.make_fake_handlers(tool)
            server, thread = start_server(tool, home=self.tmp,
                                          web_root=self.web_root,
                                          handlers=handlers, policy=False)
            self.servers.append((server, thread))
            self.addCleanup(stop_server, server, thread)
        self.ssh = TestClient(self.servers[0][0].server_address[1])
        self.db = TestClient(self.servers[1][0].server_address[1])

    def test_two_consoles_share_password_and_session(self):
        self.assertEqual(self.ssh.get("/api/status").data["tool"], "ssh")
        self.assertEqual(self.db.get("/api/status").data["tool"], "db")
        self.assertEqual(self.ssh.post("/api/setup", {"password": PASSWORD}).status, 201)
        # 另一个控制台立即可用同一密码登录（共享 secret.json）
        login = self.db.post("/api/login", {"password": PASSWORD})
        self.assertEqual(login.status, 200, login.text)
        self.db.csrf = login.data["csrf_token"]
        self.assertEqual(self.db.get("/api/databases").status, 200)
        # 会话签名密钥相同：ssh 上建立的会话在 db 控制台同样有效
        cross = TestClient(self.servers[1][0].server_address[1])
        cross.cookies = dict(self.db.cookies)
        status = cross.get("/api/status")
        self.assertTrue(status.data.get("authenticated"), status.text)
        # 未登录的第三个客户端仍然 401
        anon = TestClient(self.servers[0][0].server_address[1])
        self.assertEqual(anon.get("/api/servers").status, 401)

    def test_logout_on_one_console_revokes_shared_sessions(self):
        # 两个控制台共用 secret.json → 共享 session_epoch
        self.assertEqual(self.ssh.post("/api/setup", {"password": PASSWORD}).status, 201)
        ssh_login = self.ssh.post("/api/login", {"password": PASSWORD})
        self.assertEqual(ssh_login.status, 200, ssh_login.text)
        self.ssh.csrf = ssh_login.data["csrf_token"]
        db_login = self.db.post("/api/login", {"password": PASSWORD})
        self.assertEqual(db_login.status, 200, db_login.text)
        self.db.csrf = db_login.data["csrf_token"]
        db_old_cookies = dict(self.db.cookies)
        self.assertEqual(self.db.get("/api/databases").status, 200)

        # 在 ssh 控制台登出 → db 控制台上的会话（同一 secret/epoch）也应立即失效
        self.assertEqual(self.ssh.post("/api/logout").status, 200)
        self.assertEqual(self.db.get("/api/databases").status, 401)
        replay = TestClient(self.servers[1][0].server_address[1])
        replay.cookies = dict(db_old_cookies)
        self.assertEqual(replay.get("/api/databases").status, 401)
        # 重新登录后恢复（新 epoch）
        relogin = self.db.post("/api/login", {"password": PASSWORD})
        self.assertEqual(relogin.status, 200, relogin.text)
        self.db.csrf = relogin.data["csrf_token"]
        self.assertEqual(self.db.get("/api/databases").status, 200)


# ---------------------------------------------------------------------------
# 11. daemon 启动 / SIGTERM 停止（POSIX）
# ---------------------------------------------------------------------------

@unittest.skipUnless(hasattr(os, "fork"), "daemon 需要 POSIX fork")
class DaemonTests(unittest.TestCase):
    def test_daemon_start_and_sigterm_stop(self):
        tmp = tempfile.mkdtemp(prefix="bindconsole-daemon-")
        self.addCleanup(shutil.rmtree, tmp, True)
        web_root = os.path.join(tmp, ".bindconsole", "web")
        write_web_root(web_root)
        handlers, _state = fake_handlers.make_fake_handlers("ssh")
        port = free_port()
        pid = None
        stdout, stderr = io.StringIO(), io.StringIO()
        stdout.write("")  # keep flake quiet
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = bc.run_console("ssh", port=port, handlers=handlers,
                                    daemon=True, home=tmp, web_root=web_root)
            self.assertEqual(rc, 0, stderr.getvalue())
            self.assertIn("http://127.0.0.1:%d/" % port, stdout.getvalue())
            pid_file = os.path.join(tmp, ".bindconsole", "run", "ssh.pid")
            deadline = time.time() + 5
            while time.time() < deadline and not os.path.isfile(pid_file):
                time.sleep(0.05)
            self.assertTrue(os.path.isfile(pid_file), "pid 文件未生成")
            with open(pid_file, "r", encoding="ascii") as fh:
                pid = int(fh.read().strip())
            run_dir = os.path.dirname(pid_file)
            self.assertEqual(os.stat(run_dir).st_mode & 0o777, 0o700)
            client = TestClient(port)
            status = None
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    status = client.get("/api/status")
                    if status.status == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            self.assertIsNotNone(status, "daemon 服务未在 5s 内就绪")
            self.assertEqual(status.status, 200, status.text)
            self.assertIn("bindconsole · sshbind Web 控制台", stdout.getvalue())
        finally:
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
                reaped = False
                deadline = time.time() + 5
                while time.time() < deadline:
                    try:
                        waited, _status = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        reaped = True
                        break
                    if waited == pid:
                        reaped = True
                        break
                    time.sleep(0.05)
                self.assertTrue(reaped, "daemon 进程未在 SIGTERM 后退出")


# ---------------------------------------------------------------------------
# 11.5 服务日志脱敏（M3：URL path / query / Referer / UA 不得明文落盘）
# ---------------------------------------------------------------------------

class LogRedactionTests(KernelTestCase):
    AUTO_SETUP = False
    AUTO_LOGIN = False

    def test_api_path_password_not_in_service_log(self):
        secret = "URLPASSWORD-SuperSecret-42"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            resp = self.client.get(
                "/api/servers/%s?password=%s" % (secret, secret),
                headers={"Referer": "http://127.0.0.1/?password=" + secret,
                         "User-Agent": secret + "-UA"})
        self.assert_error(resp, "AUTH_REQUIRED", 401)
        logs = stderr.getvalue()
        self.assertIn("/api/servers/***", logs)          # 有访问日志且已脱敏
        self.assertNotIn(secret, logs)                    # 口令/query/Referer/UA 均未落盘
        self.assertNotIn("Referer", logs)
        self.assertNotIn("User-Agent", logs)

    def test_static_query_not_in_service_log(self):
        secret = "STATIC-URL-SECRET-77"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            resp = self.client.get("/missing.js?password=" + secret,
                                   headers={"User-Agent": secret})
        self.assert_error(resp, "NOT_FOUND", 404)
        logs = stderr.getvalue()
        self.assertIn("/missing.js", logs)                # 静态路径可记录
        self.assertNotIn(secret, logs)                    # query 与 UA 不落盘

    def test_redaction_helpers(self):
        self.assertEqual(bc._redact_request_target("/api/servers/secret"),
                         "/api/servers/***")
        self.assertEqual(bc._redact_request_target("/api/approvals/apr_x/approve?x=1"),
                         "/api/approvals/***")
        self.assertEqual(bc._redact_request_target("/api/status?token=abc"),
                         "/api/status")
        self.assertEqual(bc._redact_request_target("/app.js?v=1"), "/app.js")
        self.assertEqual(bc._redact_request_target(""), "/")
        text = bc._sanitize_log_text("GET /api/approvals/apr_x?token=abc 401")
        self.assertIn("/api/approvals/***", text)
        self.assertNotIn("abc", text)


@unittest.skipUnless(hasattr(os, "fork"), "daemon 日志测试需要 POSIX fork")
class DaemonLogRedactionTests(unittest.TestCase):
    """端到端：daemon 模式的真实日志文件 ~/.bindconsole/run/<tool>.log 不含明文口令。"""

    def test_daemon_log_file_redacts_api_path(self):
        tmp = tempfile.mkdtemp(prefix="bindconsole-logtest-")
        self.addCleanup(shutil.rmtree, tmp, True)
        web_root = os.path.join(tmp, ".bindconsole", "web")
        write_web_root(web_root)
        handlers, _state = fake_handlers.make_fake_handlers("ssh")
        port = free_port()
        secret = "DAEMON-LOG-PASSWORD-123"
        pid = None
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = bc.run_console("ssh", port=port, handlers=handlers,
                                    daemon=True, home=tmp, web_root=web_root)
            self.assertEqual(rc, 0)
            pid_file = os.path.join(tmp, ".bindconsole", "run", "ssh.pid")
            deadline = time.time() + 5
            while time.time() < deadline and not os.path.isfile(pid_file):
                time.sleep(0.05)
            self.assertTrue(os.path.isfile(pid_file))
            with open(pid_file, "r", encoding="ascii") as fh:
                pid = int(fh.read().strip())
            client = TestClient(port)
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    if client.get("/api/status").status == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            resp = client.get(
                "/api/servers/%s?password=%s" % (secret, secret),
                headers={"Referer": "http://127.0.0.1/?password=" + secret,
                         "User-Agent": secret + "-UA"})
            self.assertEqual(resp.status, 401, resp.text)
            log_path = os.path.join(tmp, ".bindconsole", "run", "ssh.log")
            deadline = time.time() + 5
            logs = ""
            while time.time() < deadline:
                if os.path.isfile(log_path):
                    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                        logs = fh.read()
                    if "/api/servers/***" in logs:
                        break
                time.sleep(0.05)
            self.assertIn("/api/servers/***", logs, logs)
            self.assertNotIn(secret, logs, logs)
            self.assertNotIn("Referer", logs)
            self.assertNotIn("User-Agent", logs)
        finally:
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
                deadline = time.time() + 5
                while time.time() < deadline:
                    try:
                        waited, _status = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if waited == pid:
                        break
                    time.sleep(0.05)


# ---------------------------------------------------------------------------
# 11.6 局域网模式（CONTRACT §2：0.0.0.0 / LAN IP / ::1 + setup token + 警告）
# ---------------------------------------------------------------------------

@unittest.skipUnless(LAN_IPS, "未检测到本机局域网 IPv4，跳过 LAN 模式测试")
class LanModeTests(ApiAssertionsMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bindconsole-lan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.web_root = os.path.join(self.tmp, ".bindconsole", "web")
        write_web_root(self.web_root)
        self.handlers, _state = fake_handlers.make_fake_handlers("ssh")
        self.lan_ip = LAN_IPS[0]
        self.server, self.thread = start_server(
            "ssh", home=self.tmp, web_root=self.web_root,
            handlers=self.handlers, policy=False, host="0.0.0.0")
        self.addCleanup(stop_server, self.server, self.thread)
        self.port = self.server.server_address[1]
        self.local_client = TestClient(self.port)                    # 127.0.0.1
        self.lan_client = TestClient(self.port, host=self.lan_ip)    # 局域网 IP

    def test_status_via_lan_ip_and_setup_token_flags(self):
        resp = self.lan_client.get("/api/status")
        self.assertEqual(resp.status, 200, resp.text)
        data = resp.data
        self.assertEqual(set(data.keys()),
                         {"setup_required", "setup_requires_token", "tool", "version"})
        self.assertTrue(data["setup_required"])
        self.assertTrue(data["setup_requires_token"])
        self.assertTrue(self.server.app.setup_token)
        # token 本身绝不出现在 API 响应里
        self.assertNotIn(self.server.app.setup_token, resp.text)
        self.assertEqual(self.local_client.get("/api/status").status, 200)

    def test_setup_requires_token_403_then_success(self):
        self.assert_error(self.lan_client.post("/api/setup", {"password": PASSWORD}),
                          "SETUP_TOKEN_REQUIRED", 403)
        self.assert_error(self.lan_client.post(
            "/api/setup", {"password": PASSWORD, "setup_token": "wrong-token"}),
            "SETUP_TOKEN_INVALID", 403)
        # 失败后仍未 setup，token 仍有效
        self.assertTrue(self.lan_client.get("/api/status").data["setup_required"])
        token = self.server.app.setup_token
        created = self.lan_client.post(
            "/api/setup", {"password": PASSWORD, "setup_token": token})
        self.assertEqual(created.status, 201, created.text)
        # token 一次性消费
        self.assertFalse(self.server.app.setup_requires_token())
        self.assertIsNone(self.server.app.setup_token)
        status = self.lan_client.get("/api/status").data
        self.assertFalse(status["setup_required"])
        self.assertFalse(status["setup_requires_token"])
        # 登录 + 资源 API 在局域网地址上可用
        login = self.lan_client.post("/api/login", {"password": PASSWORD})
        self.assertEqual(login.status, 200, login.text)
        self.lan_client.csrf = login.data["csrf_token"]
        self.assertEqual(self.lan_client.get("/api/servers").status, 200)
        # 二次 setup → 409
        self.assert_error(self.lan_client.post(
            "/api/setup", {"password": PASSWORD, "setup_token": "any"}),
            "ALREADY_SETUP", 409)

    def test_bind_specific_lan_ip(self):
        server, thread = start_server(
            "ssh", home=self.tmp, web_root=self.web_root,
            handlers=self.handlers, policy=False, host=self.lan_ip)
        self.addCleanup(stop_server, server, thread)
        port = server.server_address[1]
        self.assertEqual(server.server_address[0], self.lan_ip)
        self.assertIn("http://%s:%d/" % (self.lan_ip, port), server.urls)
        client = TestClient(port, host=self.lan_ip)
        resp = client.get("/api/status")
        self.assertEqual(resp.status, 200, resp.text)
        self.assertTrue(resp.data["setup_requires_token"])

    def test_banner_lan_warning_urls_and_token(self):
        out = io.StringIO()
        with redirect_stdout(out):
            bc._print_banner(self.server)
        text = out.getvalue()
        self.assertIn("局域网", text)
        self.assertIn("HTTP 明文", text)
        self.assertIn("用完 Ctrl-C 关闭", text)
        self.assertIn("http://%s:%d/" % (self.lan_ip, self.port), text)
        self.assertIn("setup_token: %s" % self.server.app.setup_token, text)

    def test_loopback_banner_unchanged_no_token(self):
        tmp = tempfile.mkdtemp(prefix="bindconsole-loopback-")
        self.addCleanup(shutil.rmtree, tmp, True)
        web_root = os.path.join(tmp, ".bindconsole", "web")
        write_web_root(web_root)
        handlers, _ = fake_handlers.make_fake_handlers("ssh")
        server, thread = start_server("ssh", home=tmp, web_root=web_root,
                                      handlers=handlers, policy=False)
        self.addCleanup(stop_server, server, thread)
        self.assertIsNone(server.app.setup_token)
        self.assertFalse(server.app.setup_requires_token())
        out = io.StringIO()
        with redirect_stdout(out):
            bc._print_banner(server)
        text = out.getvalue()
        self.assertNotIn("局域网", text)
        self.assertNotIn("setup_token", text)
        self.assertIn("http://127.0.0.1:%d/" % server.server_address[1], text)

    def test_ipv6_loopback_optional(self):
        try:
            server, thread = start_server(
                "ssh", home=self.tmp, web_root=self.web_root,
                handlers=self.handlers, policy=False, host="::1")
        except bc.ConsoleStartupError as exc:
            self.skipTest("本机 IPv6 回环不可用：%s" % exc.message)
        self.addCleanup(stop_server, server, thread)
        port = server.server_address[1]
        self.assertIn("[::1]", server.url)
        client = TestClient(port, host="::1")
        resp = client.get("/api/status")
        self.assertEqual(resp.status, 200, resp.text)
        self.assertFalse(resp.data["setup_requires_token"])   # 回环，无需 token


# ---------------------------------------------------------------------------
# 12. 会话过期 / 请求体边界 / handler 返回兼容 / 真实 policy 集成
# ---------------------------------------------------------------------------

class SessionExpiryTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = True
    SESSION_TTL_S = 1

    def test_session_expires(self):
        self.assertEqual(self.client.get("/api/servers").status, 200)
        time.sleep(1.4)
        self.assert_error(self.client.get("/api/servers"), "AUTH_REQUIRED", 401)


class RequestLimitsTests(KernelTestCase):
    AUTO_SETUP = False
    AUTO_LOGIN = False

    def test_invalid_json_400(self):
        resp = self.client.post("/api/setup", raw_body=b"not-json",
                                headers={"Content-Type": "application/json"})
        self.assert_error(resp, "INVALID_JSON", 400)

    def test_json_array_body_400(self):
        resp = self.client.post("/api/setup", raw_body=b'["a"]')
        self.assert_error(resp, "INVALID_BODY", 400)

    def test_oversized_body_413(self):
        # 内核在读取前按 Content-Length 直接拒绝并关闭连接，因此用裸 socket 只发头
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            request = ("POST /api/setup HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                       "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                       % (bc.MAX_BODY_BYTES + 100)).encode("ascii")
            sock.sendall(request)
            chunks = []
            sock.settimeout(5)
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            sock.close()
        raw = b"".join(chunks).decode("utf-8", "replace")
        self.assertIn("413", raw.splitlines()[0], raw[:200])
        self.assertIn("PAYLOAD_TOO_LARGE", raw)


class HandlerCompatibilityTests(unittest.TestCase):
    """兼容 core-dev 早期约定：list 返回裸 list、delete(name) 单参、显式 ok/data 包络。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bindconsole-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.web_root = os.path.join(self.tmp, ".bindconsole", "web")
        write_web_root(self.web_root)
        self.calls = []
        handlers = {
            "resource": "servers",
            "list": lambda: [{"name": "alpha"}, {"name": "beta"}],
            "get": lambda name: {"name": name},
            "create": lambda body: {"ok": True, "data": {"name": body["name"]}},
            "update": lambda name, body: {"ok": True, "data": {"name": name,
                                                              "note": body.get("note")}},
            "delete": lambda name: {"deleted": name},          # 单参旧签名
            "test": lambda name: {"ok": True, "message": "ok"},
        }
        self.server, self.thread = start_server(
            "ssh", home=self.tmp, web_root=self.web_root, handlers=handlers,
            policy=False)
        self.addCleanup(stop_server, self.server, self.thread)
        self.client = TestClient(self.server.server_address[1])
        self.client.post("/api/setup", {"password": PASSWORD})
        login = self.client.post("/api/login", {"password": PASSWORD})
        self.client.csrf = login.data["csrf_token"]

    def test_list_bare_list_and_explicit_envelope(self):
        data = self.client.get("/api/servers").json["data"]
        self.assertEqual(data["servers"], [{"name": "alpha"}, {"name": "beta"}])
        created = self.client.post("/api/servers", {"name": "gamma"})
        self.assertEqual(created.status, 201)
        self.assertEqual(created.json["data"], {"name": "gamma"})
        updated = self.client.put("/api/servers/alpha", {"note": "n"})
        self.assertEqual(updated.json["data"]["note"], "n")

    def test_delete_single_arg_handler_supported(self):
        resp = self.client.delete("/api/servers/alpha")
        self.assertEqual(resp.status, 200, resp.text)
        self.assertEqual(resp.json["data"], {"deleted": "alpha"})

    def test_test_handler_ok_field_kept_in_data(self):
        resp = self.client.post("/api/servers/alpha/test")
        self.assertEqual(resp.json["data"], {"ok": True, "message": "ok"})

    def test_missing_policy_handlers_404(self):
        self.assert_error(self.client.get("/api/policy"),
                          "HANDLER_NOT_CONFIGURED", 404)

    def assert_error(self, resp, code, status=None):
        if status is not None:
            self.assertEqual(resp.status, status, resp.text)
        self.assertEqual(resp.error_code, code, resp.text)


class HandlerEnvelopeErrorTests(KernelTestCase):
    AUTO_SETUP = True
    AUTO_LOGIN = True

    def test_handler_ok_false_error_envelope(self):
        self.state.fail_next = "ok_false"
        resp = self.client.post("/api/servers", {"name": "x"})
        self.assert_error(resp, "FAKE_DENIED", 422)
        self.assertEqual(resp.error.get("hint"), "fake ok:false")


@unittest.skipUnless(hasattr(os, "fork"), "集成 smoke 需要 POSIX")
class IntegrationRealPolicyTests(unittest.TestCase):
    """子进程隔离 HOME，验证内核生产路径真的调用真实 bindkit_policy。"""

    def test_kernel_calls_real_policy_module(self):
        import subprocess
        tmp = tempfile.mkdtemp(prefix="bindconsole-integration-")
        self.addCleanup(shutil.rmtree, tmp, True)
        env = dict(os.environ)
        env["HOME"] = tmp
        env.pop("BINDCONSOLE_HOME", None)
        script = os.path.join(HERE, "integration_real_policy.py")
        proc = subprocess.run([sys.executable, script], capture_output=True,
                              text=True, env=env, timeout=180, cwd=tmp)
        self.assertEqual(proc.returncode, 0,
                         "stdout=%s\nstderr=%s" % (proc.stdout, proc.stderr))
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        result = json.loads(lines[-1])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["policy_module"], "bindkit_policy")
        self.assertEqual(result["approval_status"], "approved")
        self.assertEqual(result["consumes_left"], 2)
        self.assertGreaterEqual(result["audit_records"], 3)
        self.assertGreaterEqual(result["audit_api_entries"], 1)
        # 真实文件落在隔离 HOME 内
        self.assertTrue(os.path.isfile(os.path.join(
            tmp, ".bindconsole", "audit.log")))
        self.assertTrue(os.path.isfile(os.path.join(
            tmp, ".ssh", "sshbind", "approvals", "apr_integration_1.json")))


# ---------------------------------------------------------------------------
# 12. 可直接执行的入口
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
