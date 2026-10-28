#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bindkit_console — bindconsole 共享 Web 控制台内核（仅标准库，零第三方依赖，Python 3.9+）

被 `sshbind --startserver` / `dbbind --startserver` 导入使用（契约 v1 §7.1）：

    from bindkit_console import run_console
    sys.exit(run_console("ssh", port=8790, handlers=handlers,
                         daemon=args.daemon, open_browser=args.open))

对外入口（冻结，CONTRACT §7.1.1）::

    run_console(tool, port, handlers, daemon=False, open_browser=False) -> int

本内核只负责：HTTP/1.1（ThreadingHTTPServer）、认证、会话 Cookie、CSRF、JSON 收发、
静态资源、审批/审计桥接与启动/后台化。**不直接操作工具状态**：servers/databases/policy
全部通过工具侧传入的 handlers 回调（见下），因此测试可注入 fake handlers。

handlers 约定（CONTRACT §7.1.1）::

    handlers = {
        "resource": "servers",                    # 或 "databases"，决定 URL 名词
        "list":    lambda: {"items": [...]},      # GET    /api/<resource>
        "get":     lambda name: {...},            # GET    /api/<resource>/<name>（可选）
        "create":  lambda body: {...},            # POST   /api/<resource>
        "update":  lambda name, body: {...},      # PUT    /api/<resource>/<name>
        "delete":  lambda name, body: {...},      # DELETE /api/<resource>/<name>
        "test":    lambda name: {...},            # POST   /api/<resource>/<name>/test
        "policy_get": lambda: {...},              # GET    /api/policy
        "policy_put": lambda body: {...},         # PUT    /api/policy
    }

handler 成功返回 dict / list（或显式 ``{"ok": true, "data": ...}``）；内核包装成
``{"ok": true, "data": ...}``。不带 "data" 键的 ``{"ok": true, ...}`` 视为载荷本身。
handler 失败抛 :class:`ConsoleError`（携带 code/message/hint/status）；抛 ``ValueError``
视为 400；其他异常 → 500 INTERNAL + 审计，**traceback 绝不返回浏览器**。
DELETE 的 body 会合并 query 参数（例如 ``?delete_key=true`` → ``body["delete_key"]="true"``）。

通用 API（内核实现）:

    GET  /api/status                    最小暴露的状态（未登录只含 setup_required/tool/version）
    POST /api/setup                     首次设置管理密码
    POST /api/login                     登录（失败 5 次锁 60s）
    POST /api/logout                    登出
    GET  /api/approvals?status=pending|all
    POST /api/approvals/<id>/approve    body {consumes?:1..10, ttl_s?:60..86400, note?}
    POST /api/approvals/<id>/reject     body {note?}
    GET  /api/audit?limit=100&tool=ssh|db|all

安全底线（CONTRACT §9）：
  * 默认只绑 127.0.0.1；`--host` 显式允许 0.0.0.0 / ::1 / 本机局域网 IPv4
    （CONTRACT §2：其他地址一律拒绝启动）。局域网模式启动时打印全部 LAN URL 与
    "HTTP 明文、临时使用"警告，且首次设置密码必须携带终端打印的一次性 setup token
    （防同网段抢注）；回环模式无 token 要求；
  * 密码 PBKDF2-HMAC-SHA256 ≥200k 次 + 随机 salt，secret.json 0600，目录 0700；
  * 会话 Cookie HttpOnly; SameSite=Strict; Path=/，HMAC-SHA256 签名，默认 12h；
    **登出必须服务端吊销**（CONTRACT §7.1）：secret.json 维护 session_epoch，token 内嵌 epoch，
    logout 时 epoch+1 → 该 secret 下的**所有旧会话立即失效**。两个控制台共用同一 secret，
    因此**任一控制台登出会让两边所有已登录会话一起失效**（本地单管理员模型，属预期行为）；
    升级后旧版本 v1 token 一律拒绝（需重新登录）。
  * 非 GET 需 ``X-Bindconsole-CSRF`` 与 Cookie nonce 双提交校验（nonce 同时绑定在签名会话里）；
  * 所有响应 Cache-Control: no-store / X-Content-Type-Options: nosniff；
  * 服务日志对 /api/** 的 path 与全部 query 脱敏（只记 method/脱敏路径/状态码/耗时/客户端），
    绝不原样记录 Referer/User-Agent/Cookie —— 防止口令误放 URL 后明文落盘；
  * 静态资源只从 ~/.bindconsole/web/ 白名单扩展名提供，路径规范化 + realpath 防穿越，不给目录列表；
  * name/alias 仅 [A-Za-z0-9_.-] 且禁止 —— 名单/策略/审计读写全部走 bindkit_policy（单一真源）。

审批/审计：生产路径**必须**有 ``bindkit_policy``（缺失时启动失败并提示 install.sh）；
``policy=False`` 是**仅供测试/前端 mock** 的内置文件读写降级，不得在生产使用。
"""

import argparse
import base64
import datetime
import errno
import hashlib
import ipaddress
import hmac
import inspect
import json
import mimetypes
import os
import re
import secrets
import signal
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer

try:                                    # 仅 POSIX 用于枚举网卡 IPv4（LAN 模式）
    import fcntl
except ImportError:                     # pragma: no cover - Windows
    fcntl = None

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

KERNEL_VERSION = "1.2.0"
VERSION = KERNEL_VERSION                      # 兼容别名

ALLOWED_TOOLS = ("ssh", "db")
DEFAULT_PORTS = {"ssh": 8790, "db": 8791}
LOOPBACK_HOSTS = ("127.0.0.1", "::1")
WILDCARD_HOSTS = ("0.0.0.0",)
LAN_ALLOWED_HINT = ("允许：127.0.0.1（默认）、0.0.0.0（所有网卡）、::1、"
                    "本机局域网 IPv4（如 192.168.1.10）")
# 局域网模式只接受 RFC1918 / 链路本地 / CGNAT 地址；公网地址即使本机持有也拒绝
LAN_NETWORKS = tuple(ipaddress.IPv4Network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10",
))
_SIOCGIFADDR = {"linux": 0x8915, "darwin": 0xC0206921}
TOOL_PROGRAMS = {"ssh": "sshbind", "db": "dbbind"}
DEFAULT_RESOURCES = {"ssh": "servers", "db": "databases"}

SESSION_COOKIE = "bindconsole_session"
CSRF_COOKIE = "bindconsole_csrf"
CSRF_HEADER = "X-Bindconsole-CSRF"

SESSION_TTL_S = 12 * 3600                     # 会话默认 12h
PBKDF2_ITERATIONS = 310_000                   # 契约要求 ≥200k
PBKDF2_MIN_ITERATIONS = 200_000
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 1024
MAX_BODY_BYTES = 1 << 20                      # 1 MiB
MAX_IMPORT_BODY_BYTES = 24 << 20              # Authenticated preview only; 16 MiB base64 input
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_S = 60
AUDIT_TARGET_TRUNCATE = 500
NAME_MAX_LEN = 128
APPROVAL_CONSUMES_MIN, APPROVAL_CONSUMES_MAX = 1, 10
APPROVAL_TTL_MIN, APPROVAL_TTL_MAX = 60, 86_400
DEFAULT_APPROVAL_TTL = 600
AUDIT_DEFAULT_LIMIT, AUDIT_MAX_LIMIT = 100, 1000

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
RESOURCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
APPROVAL_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_HEX_NONCE_RE = re.compile(r"^[0-9a-f]{16,64}$")
_EXP_RE = re.compile(r"^[0-9]{1,12}$")

# 静态白名单（Lead 冻结约束：其余扩展名一律 404）
STATIC_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}
STATIC_MAX_SEGMENTS = 12

# 所有响应强制加的安全头
_SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
)

# 生产路径 bindkit_policy 必须提供的接口（单一真源，内核不重复实现）
POLICY_REQUIRED_FUNCS = ("list_approvals", "get_approval", "approve", "reject",
                         "audit", "read_audit")


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------

class ConsoleStartupError(Exception):
    """启动失败（非回环 host / 端口占用 / 缺少策略模块……），工具侧应打印并退出。"""

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.message = message
        self.hint = hint


class ConsoleError(Exception):
    """handler / 内核业务错误，映射到 HTTP 状态码 + 统一错误体。"""

    def __init__(self, code, message, hint=None, status=400, headers=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.status = int(status)
        self.headers = headers or {}


# ---------------------------------------------------------------------------
# 绑定目标（CONTRACT §2：127.0.0.1 / 0.0.0.0 / ::1 / 本机局域网 IPv4）
# ---------------------------------------------------------------------------

class BindTarget:
    """一次 bind 的目标：host 字面量、模式（loopback/lan/wildcard）与地址族。"""

    __slots__ = ("host", "kind", "family")

    def __init__(self, host, kind, family):
        self.host = host
        self.kind = kind
        self.family = family

    @property
    def is_loopback(self):
        return self.kind == "loopback"

    @property
    def is_lan_mode(self):
        """0.0.0.0 或本机局域网 IP：需要打印 LAN URL + 启动警告 + setup token。"""
        return self.kind in ("lan", "wildcard")


def _is_lan_ipv4(ip):
    return any(ip in network for network in LAN_NETWORKS)


def _local_ipv4_addresses():
    """枚举本机局域网 IPv4（RFC1918/链路本地），用 if_nameindex + ioctl，带降级探测。"""
    found = []
    if fcntl is not None and sys.platform in _SIOCGIFADDR:
        try:
            interfaces = socket.if_nameindex()
        except OSError:
            interfaces = []
        for _index, name in interfaces:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                ifreq = struct.pack("256s", name.encode("utf-8", "replace")[:15])
                result = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR[sys.platform], ifreq)
                found.append(socket.inet_ntoa(result[20:24]))
            except OSError:
                pass
            finally:
                sock.close()
    try:                                # 默认路由所在网卡地址（无实际流量）
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))
            found.append(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass
    addresses = []
    for address in found:
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            continue
        if not _is_lan_ipv4(ip):
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def _can_bind_address(host, family=socket.AF_INET):
    """用临时 bind 验证该地址确为本机网卡地址（bind 失败即 EADDRNOTAVAIL）。"""
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _classify_bind_host(host):
    """校验 --host 并返回 BindTarget；不在白名单 → ConsoleStartupError（CONTRACT §2）。"""
    if not isinstance(host, str) or not host.strip():
        raise ConsoleStartupError(
            "--host 不能为空",
            hint="默认 127.0.0.1；局域网可用 --host 0.0.0.0 或本机局域网 IP")
    host = host.strip()
    if host == "127.0.0.1":
        return BindTarget(host, "loopback", socket.AF_INET)
    if host == "::1":
        if not socket.has_ipv6:
            raise ConsoleStartupError("当前 Python 不支持 IPv6，无法绑定 ::1")
        return BindTarget(host, "loopback", socket.AF_INET6)
    if host == "0.0.0.0":
        return BindTarget(host, "wildcard", socket.AF_INET)
    if host in ("::", "[::]", "[::1]", "localhost"):
        raise ConsoleStartupError(
            "--host %r 不受支持" % host, hint=LAN_ALLOWED_HINT)
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        raise ConsoleStartupError(
            "--host 只接受 IP 字面量，不支持 hostname：%r" % host,
            hint=LAN_ALLOWED_HINT)
    if ip.is_loopback:
        raise ConsoleStartupError(
            "不支持回环地址 %s（本机回环请使用 127.0.0.1）" % host,
            hint=LAN_ALLOWED_HINT)
    if not _is_lan_ipv4(ip):
        raise ConsoleStartupError(
            "拒绝绑定非局域网地址：%s" % host,
            hint="局域网模式只允许 RFC1918/链路本地 IPv4"
                 "（10/8、172.16/12、192.168/16、169.254/16、100.64/10）；"
                 "公网地址一律拒绝")
    if not _can_bind_address(host, socket.AF_INET):
        raise ConsoleStartupError(
            "地址 %s 不是本机网卡地址，无法绑定" % host,
            hint="用 ipconfig / ifconfig 查看本机局域网 IP；"
                 "或用 --host 0.0.0.0 绑定所有网卡")
    return BindTarget(host, "lan", socket.AF_INET)


def _format_host_url(host, port):
    if ":" in host:
        return "http://[%s]:%d/" % (host, int(port))
    return "http://%s:%d/" % (host, int(port))


def _access_urls_for(target, port):
    """给用户访问的 URL 列表（局域网模式列出全部可用 LAN URL）。"""
    if target.kind == "wildcard":
        return [_format_host_url(address, port) for address in _local_ipv4_addresses()]
    return [_format_host_url(target.host, port)]


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def default_port(tool):
    """工具默认端口（契约 §2：ssh=8790, db=8791）。"""
    return DEFAULT_PORTS.get(tool)


def is_loopback(host):
    """回环地址判定（127.0.0.1 / ::1）。非回环的合法 bind 目标见 _classify_bind_host。"""
    return host in LOOPBACK_HOSTS


def _iso_now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _to_epoch(value):
    """把 ISO 时间字符串转 epoch 秒；无法解析返回 None。"""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    return None


def _b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def _b64d(text):
    return base64.b64decode(text.encode("ascii"), validate=True)


def _truncate(text, limit):
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


# 服务日志脱敏（CONTRACT §9.2 凭证零泄露的延伸）：
#   * /api/<resource>/<...> 只保留 /api/<resource>/***，query 一律丢弃；
#   * 任何日志文本里的 ?query 片段统一替换为 ?***（防 Referer/UA 等误入日志）；
#   * 单行截断，避免超长 URL 刷爆日志。
_API_LOG_RE = re.compile(r"/api(?:/[^\s\"'<>]*)")
_QUERY_LOG_RE = re.compile(r"\?[^\s\"'<>]*")


def _redact_request_target(target):
    """访问日志用的 URL 脱敏：/api/** 保留资源名、其余段与 query 全部隐藏。"""
    if not isinstance(target, str):
        return "***"
    base = target.split("?", 1)[0].split("#", 1)[0]
    # 去掉控制字符（防日志注入），保留可见 ASCII/URL 字符
    base = "".join(ch for ch in base if 0x20 < ord(ch) < 0x7F) or "/"
    if base.startswith("/api"):
        segments = [seg for seg in base.split("/") if seg]
        if len(segments) <= 2:
            return "/" + "/".join(segments)
        return "/" + "/".join(segments[:2]) + "/***"
    return base


def _sanitize_log_text(text, limit=800):
    """清洗最终写入服务日志的文本（绝不落盘请求路径中的凭证/query）。"""
    if not isinstance(text, str):
        text = str(text)
    text = _API_LOG_RE.sub(lambda match: _redact_request_target(match.group(0)), text)
    text = _QUERY_LOG_RE.sub("?***", text)
    return _truncate(text, limit)


def _warn(message):
    """服务端日志警告（绝不包含凭证；写失败也不影响主流程）。"""
    try:
        sys.stderr.write("bindconsole: %s\n" % _sanitize_log_text(message))
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass


def _ensure_dir(path, mode=0o700):
    os.makedirs(path, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class _FileLock:
    """极简跨进程互斥（O_CREAT|O_EXCL 锁文件 + 陈旧锁清理）。

    仅用于 secret.json 的 session_epoch 自增（两个控制台可能同时 logout）。
    持锁时间极短；进程崩溃留下的锁超过 10s 视为陈旧并自动清理。
    """

    def __init__(self, path, timeout=5.0, stale_after=10.0):
        self.path = path
        self.timeout = timeout
        self.stale_after = stale_after
        self._fd = None

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                return self
            except FileExistsError:
                try:
                    stale = time.time() - os.stat(self.path).st_mtime
                except FileNotFoundError:
                    continue
                if stale > self.stale_after:
                    try:
                        os.unlink(self.path)
                    except OSError:
                        pass
                    continue
                if time.time() > deadline:
                    raise ConsoleError("SESSION_LOCK_TIMEOUT", "会话状态更新繁忙",
                                       hint="请稍后重试", status=503)
                time.sleep(0.02)

    def __exit__(self, exc_type, exc, tb):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
        try:
            os.unlink(self.path)
        except OSError:
            pass
        return False


def _atomic_write_bytes(path, data, mode=0o600):
    """临时文件 + fsync + os.replace 原子写，权限 0600。"""
    directory = os.path.dirname(path) or "."
    _ensure_dir(directory, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-bindconsole-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_json(path, obj, mode=0o600):
    payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    _atomic_write_bytes(path, payload, mode=mode)


def _create_exclusive_json(path, obj, mode=0o600):
    """原子“仅当不存在时创建”（secret.json 首次设置用），已存在抛 FileExistsError。"""
    directory = os.path.dirname(path) or "."
    _ensure_dir(directory, 0o700)
    payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    fd, tmp = tempfile.mkstemp(prefix=".tmp-bindconsole-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        try:
            os.link(tmp, path)          # 原子 create-if-absent（POSIX）
        except FileExistsError:
            raise
        except OSError:
            # 文件系统不支持硬链接时退化为 O_EXCL
            try:
                out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            except FileExistsError:
                raise
            with os.fdopen(out, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _read_text_file_tail(path, max_lines, max_bytes=4 * 1024 * 1024):
    """从文件尾部倒读最近 max_lines 行（审计文件持续增长，不整读）。"""
    try:
        fh = open(path, "rb")
    except OSError:
        return []
    with fh:
        try:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            data = b""
            block = 65536
            while pos > 0 and data.count(b"\n") <= max_lines and len(data) < max_bytes:
                step = min(block, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
                block = min(block * 2, 1024 * 1024)
        except OSError:
            return []
    lines = data.split(b"\n")
    if pos > 0 and lines:
        lines = lines[1:]                # 丢掉被截断的首行
    return [ln for ln in lines if ln.strip()][-max_lines:]


def _append_jsonl_fallback(path, record):
    """测试模式审计追加（生产审计必须走 bindkit_policy.audit）。"""
    directory = os.path.dirname(path) or "."
    _ensure_dir(directory, 0o700)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _validate_name(value, field="name"):
    """name/alias/id 白名单校验（契约 §9.3）：仅 [A-Za-z0-9_.-]，禁 ..。"""
    if not isinstance(value, str) or not value:
        raise ConsoleError("INVALID_NAME", "%s 不能为空" % field,
                           hint="%s 仅允许字母、数字、下划线、点、短横线" % field)
    if len(value) > NAME_MAX_LEN:
        raise ConsoleError("INVALID_NAME", "%s 过长（上限 %d 字符）" % (field, NAME_MAX_LEN))
    if ".." in value or not NAME_RE.match(value):
        raise ConsoleError("INVALID_NAME",
                           "%s 仅允许 [A-Za-z0-9_.-]，且不得包含 .." % field,
                           hint="例如：demo-server / production-server / backup-server")
    return value


def _validate_approval_id(value):
    if not isinstance(value, str) or not value or ".." in value \
            or not APPROVAL_ID_RE.match(value) or len(value) > NAME_MAX_LEN:
        raise ConsoleError("INVALID_APPROVAL_ID", "审批单 id 非法",
                           hint="审批单 id 形如 apr_20261019_ab12cd")
    return value


def _int_param(body, key, default, minimum, maximum, label=None):
    """从 body 取整型参数并做范围校验（bool 不算整数）。"""
    value = body.get(key, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConsoleError("INVALID_PARAM", "%s 必须是整数" % (label or key))
    if not (minimum <= value <= maximum):
        raise ConsoleError("INVALID_PARAM",
                           "%s 超出范围（%d..%d）" % (label or key, minimum, maximum))
    return value


def _parse_iso_or_none(value):
    return _to_epoch(value)


def _call_handler_flexible(fn, args):
    """按 handler 实际签名调用（兼容契约版 delete(name, body) 与旧版 delete(name)）。

    只在**签名绑不上**时裁掉多余尾部实参；handler 内部真正抛的 TypeError 不会被吞。
    """
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(*args)
    try:
        sig.bind(*args)
    except TypeError:
        for count in range(len(args) - 1, -1, -1):
            try:
                sig.bind(*args[:count])
            except TypeError:
                continue
            return fn(*args[:count])
        raise
    return fn(*args)


def _normalize_handler_result(result):
    """handler 返回规整。

    支持三种约定：
      * 裸 dict / list                     → 作为 data（内核自动包装 {"ok":true,"data":...}）
      * {"ok": true, "data": ...}          → 取 data（显式包络）
      * {"ok": false, "error": {...}}      → 抛 ConsoleError（业务错误）
    注意：不带 "data" 键的 {"ok": true, ...} 视为**载荷本身**（例如 test 接口返回
    {"ok": true, "message": "连接成功"}，前端拿到 data.ok 语义），避免吞掉 handler 字段。
    """
    if isinstance(result, dict) and result.get("ok") is False and isinstance(result.get("error"), dict):
        err = result["error"]
        raise ConsoleError(
            str(err.get("code") or "HANDLER_ERROR"),
            str(err.get("message") or "操作失败"),
            err.get("hint") if isinstance(err.get("hint"), str) else None,
            status=int(err.get("status") or 400),
        )
    if isinstance(result, dict) and result.get("ok") is True and "data" in result:
        return result["data"]
    if result is None:
        return {}
    return result


def _normalize_list_result(result, resource):
    """list handler → data：{"items":[...]} / [...] / {...} 统一成 {<resource>:[...]}。"""
    if isinstance(result, dict) and "items" in result:
        data = {k: v for k, v in result.items() if k != "items"}
        data[resource] = result["items"]
        return data
    if isinstance(result, list):
        return {resource: result}
    if isinstance(result, dict):
        return result
    return {resource: result}


def _inject_tool_into_html(html, tool):
    """CONTRACT §7.1.2：只替换 `"__BINDCONSOLE_TOOL__"` 这一处为 "ssh"/"db"。"""
    quoted = '"__BINDCONSOLE_TOOL__"'
    if quoted in html:
        return html.replace(quoted, json.dumps(tool), 1)
    # 兜底：前端未写占位时，在 <head> 后注入同义 script（不破坏契约语义）
    script = '<script>window.__BINDCONSOLE_TOOL__ = %s;</script>' % json.dumps(tool)
    match = re.search(r"<head[^>]*>", html, re.IGNORECASE)
    if match:
        return html[:match.end()] + "\n" + script + html[match.end():]
    return script + "\n" + html


def _cookie_header(name, value, max_age, http_only):
    parts = ["%s=%s" % (name, value), "Path=/", "Max-Age=%d" % int(max_age),
             "SameSite=Strict"]
    if http_only:
        parts.append("HttpOnly")
    return "; ".join(parts)


def _flat_query(query):
    """parse_qs 结果 → 扁平 dict（同名取第一个值）。"""
    return {key: values[0] for key, values in query.items() if values}


def _constant_time_eq(left, right):
    """常量时间比较；非 ASCII/非字符串一律视为不相等（Cookie 可能被篡改为任意字节）。"""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except (UnicodeError, TypeError):
        return False


def _is_within(root, target):
    """target 是否位于 root 目录内（均应为 realpath）。"""
    try:
        root = os.path.realpath(root)
        target = os.path.realpath(target)
        return os.path.commonpath([root, target]) == root
    except (ValueError, OSError):
        return False


# ---------------------------------------------------------------------------
# 密码 / secret.json
# ---------------------------------------------------------------------------

class SecretStore:
    """~/.bindconsole/secret.json：管理密码 hash + 会话签名密钥（两个控制台共用）。"""

    def __init__(self, path):
        self.path = path
        self._cache = None            # (mtime_ns, size, data)
        self._lock = threading.Lock()

    def exists(self):
        try:
            return os.path.isfile(self.path)
        except OSError:
            return False

    def load(self):
        with self._lock:
            try:
                st = os.stat(self.path)
            except OSError:
                self._cache = None
                return None
            if self._cache and self._cache[0] == st.st_mtime_ns and self._cache[1] == st.st_size:
                return self._cache[2]
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as exc:
                raise ConsoleError(
                    "SECRET_CORRUPT", "管理密码文件损坏，无法读取",
                    hint="备份后删除 ~/.bindconsole/secret.json 可重新设置密码（所有会话会失效）；错误：%s"
                         % _truncate(str(exc), 200), status=500)
            if not isinstance(data, dict) or not isinstance(data.get("password"), dict):
                raise ConsoleError("SECRET_CORRUPT", "管理密码文件格式不正确",
                                   hint="删除 ~/.bindconsole/secret.json 后重新设置密码",
                                   status=500)
            self._cache = (st.st_mtime_ns, st.st_size, data)
            return data

    def setup(self, password):
        if not isinstance(password, str):
            raise ConsoleError("INVALID_BODY", "password 必须是字符串")
        if len(password) < MIN_PASSWORD_LEN:
            raise ConsoleError("WEAK_PASSWORD",
                               "管理密码至少 %d 个字符" % MIN_PASSWORD_LEN)
        if len(password) > MAX_PASSWORD_LEN:
            raise ConsoleError("WEAK_PASSWORD", "管理密码过长（上限 %d 字符）" % MAX_PASSWORD_LEN)
        if self.exists():
            raise ConsoleError("ALREADY_SETUP", "管理密码已设置，请直接登录",
                               hint="两个控制台共用同一份密码；忘记密码需手动删除 ~/.bindconsole/secret.json",
                               status=409)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                     PBKDF2_ITERATIONS)
        now = _iso_now()
        data = {
            "version": 1,
            "created_at": now,
            "updated_at": now,
            "password": {
                "algo": "pbkdf2_hmac_sha256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": _b64e(salt),
                "hash": _b64e(digest),
            },
            "session_secret": _b64e(secrets.token_bytes(32)),
            # 会话吊销计数器：token 内嵌 epoch，logout 时 +1 让所有旧会话立即失效
            "session_epoch": 0,
        }
        try:
            _create_exclusive_json(self.path, data, mode=0o600)
        except FileExistsError:
            raise ConsoleError("ALREADY_SETUP", "管理密码已设置，请直接登录", status=409)
        with self._lock:
            self._cache = None
        return True

    def verify(self, password):
        data = self.load()
        if data is None:
            raise ConsoleError("SETUP_REQUIRED", "尚未设置管理密码",
                               hint="请先在控制台设置管理密码", status=400)
        if not isinstance(password, str):
            return False
        try:
            pwd = data["password"]
            iterations = int(pwd.get("iterations"))
            salt = _b64d(pwd.get("salt") or "")
            expected = _b64d(pwd.get("hash") or "")
        except (KeyError, TypeError, ValueError):
            raise ConsoleError("SECRET_CORRUPT", "管理密码文件损坏，无法校验",
                               hint="删除 ~/.bindconsole/secret.json 后重新设置密码",
                               status=500)
        if iterations < 1 or not salt or not expected:
            raise ConsoleError("SECRET_CORRUPT", "管理密码文件损坏，无法校验",
                               hint="删除 ~/.bindconsole/secret.json 后重新设置密码",
                               status=500)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)

    def session_secret(self):
        data = self.load()
        if data is None:
            raise ConsoleError("SETUP_REQUIRED", "尚未设置管理密码", status=400)
        try:
            raw = _b64d(data.get("session_secret") or "")
        except (TypeError, ValueError):
            raw = b""
        if len(raw) < 16:
            raise ConsoleError("SECRET_CORRUPT", "会话密钥损坏",
                               hint="删除 ~/.bindconsole/secret.json 后重新设置密码",
                               status=500)
        return raw

    def session_epoch(self):
        """当前会话 epoch（旧 secret.json 没有该字段时视为 0，升级后旧 v1 token 已被拒绝）。"""
        data = self.load()
        if data is None:
            raise ConsoleError("SETUP_REQUIRED", "尚未设置管理密码", status=400)
        try:
            return max(0, int(data.get("session_epoch") or 0))
        except (TypeError, ValueError):
            return 0

    def bump_session_epoch(self):
        """服务端吊销：epoch + 1（原子写 + 跨进程锁），返回新 epoch。

        CONTRACT §7.1：logout 后同一 Cookie 访问任何受保护 API 必须 401。
        两个控制台共用同一份 secret.json，因此该操作会**同时吊销两个控制台的所有会话**
        （本地单管理员模型；独立会话吊销需要 jti 黑名单，v1 不引入）。
        """
        lock_path = self.path + ".lock"
        with _FileLock(lock_path):
            self._cache = None                 # 绕过缓存，读取磁盘最新状态
            data = self.load()
            if data is None:
                raise ConsoleError("SETUP_REQUIRED", "尚未设置管理密码", status=400)
            try:
                current = max(0, int(data.get("session_epoch") or 0))
            except (TypeError, ValueError):
                current = 0
            new_epoch = current + 1
            data["session_epoch"] = new_epoch
            data["updated_at"] = _iso_now()
            _atomic_write_json(self.path, data, mode=0o600)
            self._cache = None                 # 其他进程/线程按 mtime 重新加载
        return new_epoch


# ---------------------------------------------------------------------------
# 会话（HMAC 签名 Cookie）
# ---------------------------------------------------------------------------

class Session:
    __slots__ = ("expires_at", "nonce")

    def __init__(self, expires_at, nonce):
        self.expires_at = expires_at
        self.nonce = nonce


class SessionManager:
    """v2.<exp>.<epoch>.<nonce>.<hmac>；nonce 同时用于 CSRF 双提交绑定。

    epoch 来自 ``secret.json``：logout 时 epoch+1（服务端吊销），verify 时要求
    token 内嵌 epoch == 当前 epoch，因此旧 Cookie 立即失效（CONTRACT §7.1）。
    v1 token 一律拒绝（升级前会话需重新登录；这也避免旧版本无 epoch 的 token 绕过吊销）。
    """

    TOKEN_VERSION = "v2"

    def __init__(self, secret_store, ttl_s=SESSION_TTL_S):
        self._secret = secret_store
        self.ttl_s = int(ttl_s)

    def _signing_key(self):
        return hmac.new(self._secret.session_secret(),
                        b"bindconsole-session-v1", hashlib.sha256).digest()

    def _sign(self, exp_text, epoch_text, nonce):
        message = ("%s.%s.%s.%s" % (self.TOKEN_VERSION, exp_text, epoch_text, nonce)).encode("ascii")
        return hmac.new(self._signing_key(), message, hashlib.sha256).hexdigest()

    def issue(self):
        epoch = self._secret.session_epoch()
        expires_at = int(time.time()) + self.ttl_s
        nonce = secrets.token_hex(16)
        exp_text = str(expires_at)
        epoch_text = str(epoch)
        token = "%s.%s.%s.%s.%s" % (self.TOKEN_VERSION, exp_text, epoch_text, nonce,
                                    self._sign(exp_text, epoch_text, nonce))
        return token, expires_at, nonce

    def verify(self, token):
        if not isinstance(token, str) or len(token) > 4096:
            return None
        parts = token.split(".")
        if len(parts) != 5:
            return None
        version, exp_text, epoch_text, nonce, signature = parts
        if version != self.TOKEN_VERSION:
            return None
        if not _EXP_RE.match(exp_text) or not _EXP_RE.match(epoch_text) \
                or not _HEX_NONCE_RE.match(nonce):
            return None
        try:
            expires_at = int(exp_text)
            token_epoch = int(epoch_text)
        except ValueError:
            return None
        if expires_at <= int(time.time()):
            return None
        try:
            expected = self._sign(exp_text, epoch_text, nonce)
        except ConsoleError:
            return None
        if not _constant_time_eq(expected, signature):
            return None
        try:
            if token_epoch != self._secret.session_epoch():
                return None                # 已登出 / 已被更新 epoch 吊销
        except ConsoleError:
            return None
        return Session(expires_at, nonce)

    def revoke_all(self):
        """服务端吊销所有会话（epoch+1），返回新 epoch。"""
        return self._secret.bump_session_epoch()


# ---------------------------------------------------------------------------
# 登录限速（内存）
# ---------------------------------------------------------------------------

class LoginLimiter:
    """连续失败 max_failures 次 → 锁 lockout_s 秒（进程内，够用且无持久化负担）。"""

    def __init__(self, max_failures=LOGIN_MAX_FAILURES, lockout_s=LOGIN_LOCKOUT_S):
        self.max_failures = max(1, int(max_failures))
        self.lockout_s = max(1, int(lockout_s))
        self._state = {}
        self._lock = threading.Lock()

    def remaining(self, key):
        now = time.time()
        with self._lock:
            state = self._state.get(key)
            if not state:
                return 0
            locked_until = state.get("locked_until") or 0
            if locked_until > now:
                return int(locked_until - now) + 1
            if locked_until:
                state["locked_until"] = 0
                state["count"] = 0
            return 0

    def record_failure(self, key):
        now = time.time()
        with self._lock:
            state = self._state.setdefault(key, {"count": 0, "locked_until": 0})
            if state["locked_until"] > now:
                return int(state["locked_until"] - now) + 1
            state["count"] += 1
            if state["count"] >= self.max_failures:
                state["count"] = 0
                state["locked_until"] = now + self.lockout_s
                return self.lockout_s
            return 0

    def record_success(self, key):
        with self._lock:
            self._state.pop(key, None)


# ---------------------------------------------------------------------------
# 审批 / 审计：生产走 bindkit_policy；policy=False 时使用仅供测试的文件降级
# ---------------------------------------------------------------------------

def _load_policy_module(runtime_dir):
    """import bindkit_policy（优先 ~/.bindconsole/lib，其次内核所在目录）。

    返回 (module, error_message)。
    """
    candidates = []
    for directory in (os.path.join(runtime_dir, "lib"),
                      os.path.dirname(os.path.abspath(__file__))):
        if directory and os.path.isdir(directory) and directory not in candidates:
            candidates.append(directory)
            if directory not in sys.path:
                sys.path.insert(0, directory)
    try:
        import bindkit_policy  # noqa: F401  （延迟导入，安装后即可用）
    except Exception as exc:  # noqa: BLE001
        return None, "%s: %s" % (type(exc).__name__, exc)
    return bindkit_policy, None


class ApprovalStore:
    """审批单读写桥。

    生产：必须调用 bindkit_policy 的 list_approvals/get_approval/approve/reject。
    测试：``policy=False`` 时用契约 §5.2 文件格式直接读写（**仅测试路径**）。
    """

    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()

    # ---- 目录 / 文件（仅测试降级用） ----

    def _dir(self):
        return os.path.join(self.app.tool_home, "approvals")

    def _path(self, approval_id):
        return os.path.join(self._dir(), "%s.json" % approval_id)

    def _load_file(self, approval_id):
        path = self._path(approval_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise ConsoleError("APPROVAL_CORRUPT", "审批单文件损坏",
                               hint=_truncate(str(exc), 200), status=500)
        return data if isinstance(data, dict) else None

    def _effective_status(self, ap):
        status = ap.get("status")
        expires = _parse_iso_or_none(ap.get("expires_at"))
        if status == "pending" and expires is not None and expires <= time.time():
            return "expired"
        return status

    def _fallback_items(self):
        directory = self._dir()
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            return []
        items = []
        for name in names:
            if not name.endswith(".json"):
                continue
            approval_id = name[:-5]
            if ".." in approval_id or not APPROVAL_ID_RE.match(approval_id):
                continue
            try:
                ap = self._load_file(approval_id)
            except ConsoleError:
                continue
            if not ap:
                continue
            ap = dict(ap)
            ap.setdefault("tool", self.app.tool)
            ap["_effective_status"] = self._effective_status(ap)
            items.append(ap)
        items.sort(key=lambda x: (_to_epoch(x.get("created_at")) or 0,
                                  str(x.get("id") or "")), reverse=True)
        return items

    def _fallback_list(self, status_filter):
        items = self._fallback_items()
        if status_filter == "pending":
            items = [ap for ap in items if ap.get("_effective_status") == "pending"]
        out = []
        for ap in items:
            item = dict(ap)
            if item.get("_effective_status") == "expired" and item.get("status") == "pending":
                item["status"] = "expired"
            item.pop("_effective_status", None)
            out.append(item)
        return out

    def _fallback_decide(self, approval_id, approve, body):
        consumes = _int_param(body, "consumes", 1, APPROVAL_CONSUMES_MIN,
                              APPROVAL_CONSUMES_MAX)
        ttl_s = _int_param(body, "ttl_s", None, APPROVAL_TTL_MIN, APPROVAL_TTL_MAX)
        note = body.get("note")
        if note is not None and not isinstance(note, str):
            raise ConsoleError("INVALID_PARAM", "note 必须是字符串")
        with self._lock:
            ap = self._load_file(approval_id)
            if not ap:
                raise ConsoleError("APPROVAL_NOT_FOUND", "审批单不存在：%s" % approval_id,
                                   status=404)
            if ap.get("status") != "pending":
                raise ConsoleError(
                    "APPROVAL_ALREADY_DECIDED",
                    "审批单状态不是 pending（当前 %s），不能再次处理" % ap.get("status"),
                    status=409)
            if self._effective_status(ap) == "expired":
                raise ConsoleError("APPROVAL_EXPIRED", "审批单已过期", status=409)
            now = time.time()
            if approve:
                ttl = ttl_s if ttl_s is not None else int(ap.get("ttl_s") or DEFAULT_APPROVAL_TTL)
                ap["status"] = "approved"
                ap["consumes_left"] = consumes
                ap["expires_at"] = datetime.datetime.fromtimestamp(
                    now + ttl).astimezone().isoformat(timespec="seconds")
                ap["ttl_s"] = ttl
            else:
                ap["status"] = "denied"
                ap["consumes_left"] = 0
            ap["decided_at"] = _iso_now()
            ap["decided_by"] = "web"
            if note is not None:
                ap["note"] = _truncate(note, AUDIT_TARGET_TRUNCATE)
            _atomic_write_json(self._path(approval_id), ap, mode=0o600)
        self.app.audit("approval", "approve" if approve else "reject",
                       alias=ap.get("alias"), request_id=ap.get("id"),
                       target=ap.get("target"),
                       note=("consumes=%s" % consumes) if approve else note)
        return ap

    # ---- 统一接口 ----

    def list(self, status_filter="pending"):
        app = self.app
        if app.policy_module is not None:
            try:
                if status_filter == "pending":
                    items = app.policy_module.list_approvals(app.tool, status="pending")
                else:
                    items = app.policy_module.list_approvals(app.tool)
            except Exception as exc:  # noqa: BLE001
                _warn("审批列表读取失败: %s" % exc)
                raise ConsoleError("APPROVAL_STORE_ERROR", "审批列表读取失败",
                                   hint="详见服务端日志", status=500)
            return [dict(x) for x in items if isinstance(x, dict)]
        return self._fallback_list(status_filter)

    def pending_count(self):
        try:
            return len(self.list("pending"))
        except Exception:  # noqa: BLE001
            return 0

    def decide(self, approval_id, approve, body):
        _validate_approval_id(approval_id)
        app = self.app
        if app.policy_module is not None:
            consumes = _int_param(body, "consumes", 1, APPROVAL_CONSUMES_MIN,
                                  APPROVAL_CONSUMES_MAX)
            ttl_s = _int_param(body, "ttl_s", None, APPROVAL_TTL_MIN, APPROVAL_TTL_MAX)
            note = body.get("note")
            if note is not None and not isinstance(note, str):
                raise ConsoleError("INVALID_PARAM", "note 必须是字符串")
            note = _truncate(note, AUDIT_TARGET_TRUNCATE) if note is not None else None
            try:
                if approve:
                    result = app.policy_module.approve(
                        app.tool, approval_id, consumes=consumes,
                        ttl_s=ttl_s if ttl_s is not None else DEFAULT_APPROVAL_TTL,
                        note=note, decided_by="web")
                else:
                    result = app.policy_module.reject(
                        app.tool, approval_id, note=note, decided_by="web")
            except ValueError as exc:
                raise self._map_policy_value_error(exc)
            except Exception as exc:  # noqa: BLE001
                _warn("审批操作失败: %s" % exc)
                raise ConsoleError("APPROVAL_STORE_ERROR", "审批操作失败",
                                   hint="详见服务端日志", status=500)
            if not isinstance(result, dict):
                raise ConsoleError("APPROVAL_STORE_ERROR", "审批模块返回格式异常",
                                   status=500)
            return result
        return self._fallback_decide(approval_id, approve, body)

    @staticmethod
    def _map_policy_value_error(exc):
        message = _truncate(str(exc), 300) or "审批操作失败"
        if "不存在" in message:
            return ConsoleError("APPROVAL_NOT_FOUND", message, status=404)
        if "状态不是" in message:
            return ConsoleError("APPROVAL_ALREADY_DECIDED", message, status=409)
        return ConsoleError("APPROVAL_INVALID", message, status=400)


def _fallback_read_audit(runtime_dir, tool_filter, limit):
    lines = _read_text_file_tail(os.path.join(runtime_dir, "audit.log"),
                                 max_lines=max(limit * 4, limit + 10))
    entries = []
    for raw in lines:
        try:
            record = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if tool_filter and record.get("tool") != tool_filter:
            continue
        entries.append(record)
    entries.reverse()
    return entries[:limit]


def _fallback_append_audit(runtime_dir, tool, action, decision, alias=None,
                           request_id=None, target=None, source="127.0.0.1", note=None):
    record = {
        "ts": _iso_now(),
        "tool": tool,
        "actor": "web",
        "alias": alias,
        "action": action,
        "decision": decision,
        "request_id": request_id,
        "target": _truncate(target, AUDIT_TARGET_TRUNCATE),
        "source": source,
        "note": _truncate(note, AUDIT_TARGET_TRUNCATE) if note is not None else None,
    }
    _append_jsonl_fallback(os.path.join(runtime_dir, "audit.log"), record)
    return record


# ---------------------------------------------------------------------------
# Web 控制台应用（与 HTTP 层解耦，便于测试）
# ---------------------------------------------------------------------------

class ConsoleApp:
    """一个控制台实例的全部状态与业务逻辑。"""

    def __init__(self, tool, port, handlers=None, host="127.0.0.1", home=None,
                 web_root=None, policy=None, login_max_failures=LOGIN_MAX_FAILURES,
                 login_lockout_s=LOGIN_LOCKOUT_S, session_ttl_s=SESSION_TTL_S,
                 bind_target=None):
        if tool not in ALLOWED_TOOLS:
            raise ValueError("tool 必须是 'ssh' 或 'db'，收到：%r" % (tool,))
        self.tool = tool
        self.program = TOOL_PROGRAMS[tool]
        self.display_name = self.program
        self.bind_target = bind_target or _classify_bind_host(host)
        self.host = self.bind_target.host
        self.lan_mode = self.bind_target.is_lan_mode
        self.port = int(port or 0)
        self.handlers = dict(handlers) if isinstance(handlers, dict) else {}

        self.home = os.path.abspath(os.path.expanduser(home)) if home else os.path.expanduser("~")
        self.runtime_dir = (os.path.abspath(os.path.expanduser(os.environ["BINDCONSOLE_HOME"]))
                            if home is None and os.environ.get("BINDCONSOLE_HOME")
                            else os.path.join(self.home, ".bindconsole"))
        if tool == "ssh":
            self.tool_home = os.path.join(self.home, ".ssh", "sshbind")
        else:
            self.tool_home = os.path.join(self.home, ".dbbind")
        self.web_root = os.path.abspath(web_root) if web_root else os.path.join(self.runtime_dir, "web")

        resource = self.handlers.get("resource") or DEFAULT_RESOURCES[tool]
        if not isinstance(resource, str) or not RESOURCE_RE.match(resource):
            raise ConsoleStartupError(
                "handlers['resource'] 非法：%r" % (resource,),
                hint="resource 只能是小写字母/数字/短横线，例如 servers 或 databases")
        self.resource = resource

        self.secret = SecretStore(os.path.join(self.runtime_dir, "secret.json"))
        # 防抢注（CONTRACT §2）：非回环首次启动生成一次性 setup token，只打印在终端
        self.setup_token = None
        if self.lan_mode and not self.secret.exists():
            self.setup_token = secrets.token_urlsafe(12)
        self.sessions = SessionManager(self.secret, ttl_s=session_ttl_s)
        self.limiter = LoginLimiter(login_max_failures, login_lockout_s)

        # ---- 审批/审计后端：生产必须 bindkit_policy；policy=False 仅测试 ----
        self.test_only_policy_io = policy is False
        self.policy_module = None
        self.policy_load_error = None
        if policy is False:
            # ⚠️ 仅限测试 / 前端 mock：使用内置文件读写，禁止在生产调用
            self.policy_module = None
        elif policy is None:
            module, error = _load_policy_module(self.runtime_dir)
            if module is None:
                raise ConsoleStartupError(
                    "缺少共享策略/审计模块 bindkit_policy.py，控制台无法启动",
                    hint="请先运行 install.sh 安装 bindconsole"
                         "（安装 ~/.bindconsole/lib/bindkit_policy.py）：bash bindconsole/install.sh")
            missing = [name for name in POLICY_REQUIRED_FUNCS if not callable(getattr(module, name, None))]
            if missing:
                raise ConsoleStartupError(
                    "bindkit_policy.py 接口不完整，缺少：%s" % ", ".join(missing),
                    hint="请更新 bindconsole 后重新运行 install.sh（内核需要单一真源的审批/审计实现）")
            self.policy_module = module
        else:
            # 允许测试注入伪策略模块验证生产分支；同样校验接口
            missing = [name for name in POLICY_REQUIRED_FUNCS if not callable(getattr(policy, name, None))]
            if missing:
                raise ConsoleStartupError(
                    "注入的 policy 模块接口不完整，缺少：%s" % ", ".join(missing))
            self.policy_module = policy
        self.approvals = ApprovalStore(self)
        self._admin_api = None
        try:
            from bindkit_admin import AdminAPI
            self._admin_api = AdminAPI(self)
        except ImportError:
            pass  # Older core-only fixtures/installations retain their original routes.
        self.started_at = time.time()

    # ---- 审计 ----

    def audit(self, action, decision, alias=None, request_id=None, target=None,
              note=None, source="127.0.0.1"):
        """写审计（失败不影响主流程）。生产走 bindkit_policy.audit，测试走内置 JSONL。"""
        try:
            if self.policy_module is not None:
                self.policy_module.audit(
                    self.tool, "web", alias, action, decision,
                    request_id=request_id, target=target, source=source, note=note)
            else:
                _fallback_append_audit(self.runtime_dir, self.tool, action, decision,
                                       alias=alias, request_id=request_id,
                                       target=target, source=source, note=note)
        except Exception as exc:  # noqa: BLE001
            _warn("审计写入失败（已忽略）: %s" % exc)

    def read_audit(self, limit, tool_filter):
        if self.policy_module is not None:
            try:
                entries = self.policy_module.read_audit(
                    tool=None if tool_filter == "all" else tool_filter, limit=limit)
            except Exception as exc:  # noqa: BLE001
                _warn("审计读取失败: %s" % exc)
                raise ConsoleError("AUDIT_READ_ERROR", "审计读取失败",
                                   hint="详见服务端日志", status=500)
            items = [dict(x) for x in entries if isinstance(x, dict)]
        else:
            items = _fallback_read_audit(self.runtime_dir,
                                         None if tool_filter == "all" else tool_filter,
                                         limit)
        if tool_filter != "all":
            items = [x for x in items if x.get("tool") == tool_filter]
        items.sort(key=lambda x: (_to_epoch(x.get("ts")) or 0), reverse=True)
        return items[:limit]

    # ---- 状态 / 认证 ----

    def access_urls(self):
        """访问 URL 列表（0.0.0.0 时列出全部局域网地址）。"""
        return _access_urls_for(self.bind_target, self.port)

    def setup_requires_token(self):
        """非回环启动且尚未设置密码时，POST /api/setup 需要终端打印的一次性 token。"""
        return bool(self.setup_token) and not self.secret.exists()

    def status_data(self, session, source="127.0.0.1"):
        """未登录最小暴露：setup_required / setup_requires_token / tool / version。"""
        data = {
            "setup_required": not self.secret.exists(),
            "setup_requires_token": self.setup_requires_token(),
            "tool": self.tool,
            "version": KERNEL_VERSION,
        }
        if session is not None:
            remaining = self.limiter.remaining(source)
            data.update({
                "authenticated": True,
                "resource": self.resource,
                "port": self.port,
                "csrf_token": session.nonce,
                "pending_count": self.approvals.pending_count(),
                "locked_out": remaining > 0,
                "lockout_remaining_s": remaining,
            })
        return data

    def setup(self, body, source="127.0.0.1"):
        password = body.get("password")
        if not isinstance(password, str):
            raise ConsoleError("INVALID_BODY", "缺少 password 字段",
                               hint="请求体形如 {\"password\": \"至少8位\", \"setup_token\": \"...\"}")
        if self.setup_requires_token():
            provided = body.get("setup_token")
            if not isinstance(provided, str) or not provided:
                self.audit("setup", "deny", source=source, note="setup_token missing")
                raise ConsoleError(
                    "SETUP_TOKEN_REQUIRED",
                    "局域网模式首次设置管理密码必须提供 setup_token",
                    hint="setup_token 仅在启动终端打印，请查看终端输出；回环模式不需要",
                    status=403)
            if not _constant_time_eq(provided, self.setup_token or ""):
                self.audit("setup", "deny", source=source, note="setup_token invalid")
                raise ConsoleError(
                    "SETUP_TOKEN_INVALID", "setup_token 错误",
                    hint="请核对启动终端打印的一次性 token（区分大小写，每次启动重新生成）",
                    status=403)
        try:
            self.secret.setup(password)
        except ConsoleError:
            self.audit("setup", "deny", source=source)
            raise
        self.setup_token = None          # 一次性 token：设置成功后立即作废
        self.audit("setup", "allow", source=source)
        return {"setup_required": False}

    def login(self, body, source="127.0.0.1"):
        password = body.get("password")
        if not isinstance(password, str) or not password:
            raise ConsoleError("INVALID_BODY", "缺少 password 字段")
        if len(password) > MAX_PASSWORD_LEN:
            raise ConsoleError("INVALID_CREDENTIALS", "密码错误", status=401)
        if not self.secret.exists():
            raise ConsoleError("SETUP_REQUIRED", "尚未设置管理密码",
                               hint="请先设置管理密码", status=400)
        remaining = self.limiter.remaining(source)
        if remaining > 0:
            raise ConsoleError(
                "LOGIN_LOCKED", "登录失败次数过多，已临时锁定",
                hint="请 %d 秒后再试" % remaining, status=429,
                headers={"Retry-After": str(remaining)})
        try:
            ok = self.secret.verify(password)
        except ConsoleError:
            self.audit("login", "error", source=source)
            raise
        if not ok:
            locked_for = self.limiter.record_failure(source)
            self.audit("login", "deny", source=source)
            if locked_for:
                raise ConsoleError(
                    "LOGIN_LOCKED", "登录失败次数过多，已锁定 %d 秒" % locked_for,
                    hint="请等待后重试", status=429,
                    headers={"Retry-After": str(locked_for)})
            raise ConsoleError("INVALID_CREDENTIALS", "密码错误",
                               hint="连续失败 %d 次将锁定 %d 秒"
                                    % (self.limiter.max_failures,
                                       self.limiter.lockout_s),
                               status=401)
        self.limiter.record_success(source)
        token, _expires_at, nonce = self.sessions.issue()
        self.audit("login", "allow", source=source)
        cookies = [
            _cookie_header(SESSION_COOKIE, token, self.sessions.ttl_s, http_only=True),
            _cookie_header(CSRF_COOKIE, nonce, self.sessions.ttl_s, http_only=False),
        ]
        return ({"authenticated": True, "tool": self.tool,
                 "csrf_token": nonce, "expires_in": self.sessions.ttl_s}, cookies)

    def logout(self, source="127.0.0.1"):
        """登出：服务端吊销旧 Cookie（session_epoch+1）后再清客户端 Cookie。

        吊销范围为当前 secret.json 的全部会话——即**两个控制台一起失效**
        （本地单管理员模型，CONTRACT §7.1 允许并已注明）。
        """
        try:
            new_epoch = self.sessions.revoke_all()
        except ConsoleError as exc:
            self.audit("logout", "error", source=source, note=exc.code)
            raise
        self.audit("logout", "allow", source=source,
                   note="session_epoch=%d" % new_epoch)
        cookies = [
            _cookie_header(SESSION_COOKIE, "", 0, http_only=True),
            _cookie_header(CSRF_COOKIE, "", 0, http_only=False),
        ]
        return {"authenticated": False, "revoked": True}, cookies

    # ---- 审批 / 审计 API 数据 ----

    def list_approvals(self, status_filter):
        if status_filter not in ("pending", "all"):
            raise ConsoleError("INVALID_PARAM", "status 只能是 pending 或 all")
        return {"approvals": self.approvals.list(status_filter)}

    def decide_approval(self, approval_id, approve, body, source="127.0.0.1"):
        result = self.approvals.decide(approval_id, approve, body)
        return {"approval": result}

    def list_audit(self, query):
        params = _flat_query(query)
        # Preserve original limit callers while the paged API returns a complete envelope.
        paging_keys = ("page", "page_size", "snapshot", "actor", "decision", "alias")
        legacy_backend = self.policy_module is not None and not getattr(self.policy_module, "AUDIT_LOG", None)
        if ("limit" not in params and not legacy_backend) or any(key in params for key in paging_keys):
            try:
                from bindkit_catalog import read_audit_page
                path = (getattr(self.policy_module, "AUDIT_LOG", None)
                        or os.path.join(self.runtime_dir, "audit.log"))
                return read_audit_page(path, tool=params.get("tool") or self.tool,
                    page=int(params.get("page") or 1), page_size=int(params.get("page_size") or 50),
                    actor=params.get("actor") or None, decision=params.get("decision") or None,
                    alias=params.get("alias") or None, snapshot=params.get("snapshot") or None)
            except ValueError as exc:
                if "snapshot" in str(exc):
                    raise ConsoleError("AUDIT_SNAPSHOT_EXPIRED", "审计快照已更新，请返回第一页", status=409) from None
                raise ConsoleError("INVALID_PARAM", "审计分页参数无效（page ≥ 1，page_size 为 1–200）") from None
            except ImportError:
                raise ConsoleError("INTEGRATION_MISSING", "请重新运行安装程序以更新审计模块", status=503) from None
            except OSError:
                raise ConsoleError("AUDIT_READ_ERROR", "审计读取失败，请检查运行目录权限", status=500) from None
        raw_limit = params.get("limit")
        try:
            limit = int(raw_limit) if raw_limit not in (None, "") else AUDIT_DEFAULT_LIMIT
        except (TypeError, ValueError):
            raise ConsoleError("INVALID_PARAM", "limit 必须是整数")
        limit = max(1, min(limit, AUDIT_MAX_LIMIT))
        tool_filter = (params.get("tool") or self.tool).strip()
        if tool_filter not in ("ssh", "db", "all"):
            raise ConsoleError("INVALID_PARAM", "tool 只能是 ssh、db 或 all")
        return {"entries": self.read_audit(limit, tool_filter)}

    # ---- handler 回调 ----

    def validate_create_body(self, body):
        """create 前校验 name/alias（内核职责，CONTRACT §7.1.1）。"""
        if not isinstance(body, dict):
            raise ConsoleError("INVALID_BODY", "请求体必须是 JSON 对象")
        key = "name" if self.tool == "ssh" else "alias"
        if key not in body:
            raise ConsoleError("MISSING_FIELD", "缺少字段 %s" % key)
        name = _validate_name(body.get(key), field=key)
        return name

    def _audit_handler_call(self, verb, name, decision, detail=None):
        if verb in ("list", "get", "policy_get", "users"):
            return
        if verb in ("policy_put",):
            action = "policy.update"
            alias = None
        else:
            action = "%s.%s" % (self.resource, verb)
            alias = name
        self.audit(action, decision, alias=alias, target=alias, note=detail)

    def call_handler(self, verb, name=None, body=None, source="127.0.0.1"):
        """调用工具侧 handler，统一异常映射 + 审计；内核不碰工具状态。"""
        handler = self.handlers.get(verb)
        if not callable(handler):
            if verb == "get":
                raise ConsoleError("HANDLER_NOT_CONFIGURED",
                                   "该工具未实现单项查询接口", status=404)
            raise ConsoleError("HANDLER_NOT_CONFIGURED",
                               "该工具未实现接口：%s" % verb,
                               hint="请把工具更新到与 bindconsole 内核匹配的版本",
                               status=404)
        args_by_verb = {
            "list": [],
            "get": [name],
            "create": [body],
            "update": [name, body],
            "delete": [name, body],
            "test": [name],
            "users": [name],
            "unlock": [name, body],
            "policy_get": [],
            "policy_put": [body],
        }
        args = args_by_verb.get(verb)
        if args is None:
            raise ConsoleError("HANDLER_NOT_CONFIGURED", "未知 handler：%s" % verb, status=500)
        try:
            result = _call_handler_flexible(handler, args)
        except ConsoleError as exc:
            self._audit_handler_call(verb, name, "deny", "%s: %s" % (exc.code, exc.message))
            raise
        except ValueError as exc:
            message = _truncate(str(exc), 300) or "请求无效"
            self._audit_handler_call(verb, name, "deny", "INVALID_REQUEST: %s" % message)
            raise ConsoleError("INVALID_REQUEST", message, status=400)
        except Exception:  # noqa: BLE001 —— 绝不把 traceback 暴露给浏览器
            _warn("handler %s 异常：\n%s" % (verb, traceback.format_exc()))
            self._audit_handler_call(verb, name, "error", "INTERNAL")
            raise ConsoleError("INTERNAL", "服务端处理失败",
                               hint="详见服务端日志（%s）" % self.program, status=500)
        self._audit_handler_call(verb, name, "allow")
        return _normalize_handler_result(result)

    def call_list_handler(self):
        data = self.call_handler("list")
        return _normalize_list_result(data, self.resource)

    # ---- 静态资源 ----

    def _safe_static_segments(self, decoded_path):
        if "\x00" in decoded_path:
            raise ConsoleError("PATH_INVALID", "路径非法", status=400)
        normalized = decoded_path.replace("\\", "/")
        segments = []
        for segment in normalized.split("/"):
            if segment in ("", "."):
                continue
            if segment == ".." or re.fullmatch(r"\.{2,}", segment):
                raise ConsoleError("PATH_INVALID", "路径穿越被拒绝", status=400)
            if segment.startswith("."):
                raise ConsoleError("NOT_FOUND", "资源不存在", status=404)
            if len(segment) > 200:
                raise ConsoleError("NOT_FOUND", "资源不存在", status=404)
            segments.append(segment)
        if len(segments) > STATIC_MAX_SEGMENTS:
            raise ConsoleError("NOT_FOUND", "资源不存在", status=404)
        return segments

    def _read_static_file(self, path, ext):
        try:
            with open(path, "rb") as fh:
                payload = fh.read()
        except OSError:
            raise ConsoleError("NOT_FOUND", "资源不存在", status=404)
        content_type = STATIC_CONTENT_TYPES.get(ext) or mimetypes.guess_type(path)[0] \
            or "application/octet-stream"
        if ext == ".html":
            html = payload.decode("utf-8", "replace")
            payload = _inject_tool_into_html(html, self.tool).encode("utf-8")
            content_type = STATIC_CONTENT_TYPES[".html"]
        return {"status": 200, "body": payload, "content_type": content_type}

    def _serve_index(self):
        web_root = os.path.realpath(self.web_root)
        index_path = os.path.join(web_root, "index.html")
        if not os.path.isdir(web_root) or not os.path.isfile(index_path):
            raise ConsoleError(
                "WEB_UI_MISSING", "前端静态资源未安装：%s" % self.web_root,
                hint="请运行 bash bindconsole/install.sh 安装前端到 ~/.bindconsole/web/",
                status=503)
        try:
            with open(index_path, "rb") as fh:
                payload = fh.read()
        except OSError as exc:
            raise ConsoleError("WEB_UI_MISSING", "前端入口读取失败",
                               hint=_truncate(str(exc), 200), status=503)
        html = payload.decode("utf-8", "replace")
        payload = _inject_tool_into_html(html, self.tool).encode("utf-8")
        return {"status": 200, "body": payload,
                "content_type": STATIC_CONTENT_TYPES[".html"]}

    def resolve_static(self, decoded_path):
        """静态解析：白名单扩展名 + realpath 防穿越 + 不列目录 + SPA 回退 index.html。"""
        root = self.web_root
        if not os.path.isdir(root):
            raise ConsoleError(
                "WEB_UI_MISSING", "前端静态资源未安装：%s" % root,
                hint="请运行 bash bindconsole/install.sh 安装前端到 ~/.bindconsole/web/",
                status=503)
        root_real = os.path.realpath(root)
        segments = self._safe_static_segments(decoded_path)
        if not segments:
            return self._serve_index()
        candidate = os.path.realpath(os.path.join(root_real, *segments))
        if not _is_within(root_real, candidate):
            raise ConsoleError("PATH_INVALID", "路径穿越被拒绝", status=400)
        if os.path.isdir(candidate):
            # 不给目录列表，也不隐式索引子目录
            raise ConsoleError("NOT_FOUND", "资源不存在", status=404)
        if os.path.isfile(candidate):
            ext = os.path.splitext(candidate)[1].lower()
            if ext not in STATIC_CONTENT_TYPES:
                raise ConsoleError("NOT_FOUND", "资源不存在",
                                   hint="静态资源仅允许：%s"
                                        % " ".join(sorted(STATIC_CONTENT_TYPES)),
                                   status=404)
            return self._read_static_file(candidate, ext)
        # 不存在：仅“无扩展名的前端路由”回退 index.html（SPA）
        last = segments[-1]
        if "." not in last:
            return self._serve_index()
        raise ConsoleError("NOT_FOUND", "资源不存在", status=404)


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------

class ConsoleHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, server_address, app):
        self.app = app
        super().__init__(server_address, ConsoleRequestHandler)

    def server_bind(self):
        # The console accepts IP literals only. HTTPServer's default getfqdn()
        # reverse lookup is unnecessary and can block on managed/offline hosts.
        TCPServer.server_bind(self)
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]

    @property
    def urls(self):
        """面向用户的访问 URL 列表（0.0.0.0 时是全部局域网地址）。"""
        return self.app.access_urls()

    @property
    def url(self):
        urls = self.urls
        if urls:
            return urls[0]
        return "http://127.0.0.1:%d/" % int(self.server_address[1])

    def handle_error(self, request, client_address):
        _warn("处理请求异常：\n%s" % traceback.format_exc())


class ConsoleHTTPServerV6(ConsoleHTTPServer):
    """IPv6 回环（::1）专用；默认 ThreadingHTTPServer 是 AF_INET。"""

    address_family = socket.AF_INET6


class ConsoleRequestHandler(BaseHTTPRequestHandler):
    server_version = "bindconsole/" + KERNEL_VERSION
    protocol_version = "HTTP/1.1"
    timeout = 30

    def version_string(self):
        # 不回显 Python 解释器版本（减少信息暴露面）
        return "bindconsole/" + KERNEL_VERSION

    # ---- 基础 ----

    def log_request(self, code="-", size="-"):
        """失败请求的访问日志：method + 脱敏 path + 状态码 + 耗时，绝不记录请求体/Header。"""
        try:
            status = int(code)
        except (TypeError, ValueError):
            status = 0
        if status < 400:
            return                      # 只记失败请求，避免前端 5s 轮询刷屏
        started = getattr(self, "_request_started", None)
        duration_ms = int((time.monotonic() - started) * 1000) if started else 0
        target = _redact_request_target(getattr(self, "path", "") or "")
        self.log_message("%s %s -> %d (%dms)",
                         getattr(self, "command", "-") or "-", target,
                         status, duration_ms)

    def log_message(self, format, *args):
        """统一服务日志出口：所有文本先脱敏再写 stderr（daemon 时即 ~/.bindconsole/run/*.log）。"""
        try:
            message = format % args
        except (TypeError, ValueError):
            message = " ".join([str(format)] + [str(arg) for arg in args])
        line = "%s - - [%s] %s\n" % (self.address_string(),
                                      self.log_date_time_string(),
                                      _sanitize_log_text(message))
        try:
            sys.stderr.write(line)
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass

    def _source(self):
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def _cookies(self):
        header = self.headers.get("Cookie")
        if not header:
            return {}
        jar = SimpleCookie()
        try:
            jar.load(header)
        except CookieError:
            return {}
        return {name: morsel.value for name, morsel in jar.items()}

    def _session(self):
        token = self._cookies().get(SESSION_COOKIE)
        if not token:
            return None
        try:
            return self.server.app.sessions.verify(token)
        except Exception:  # noqa: BLE001 —— 任何解析/密钥异常都按“未登录”处理
            return None

    # ---- 响应 ----

    def _common_headers(self):
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)

    def _write_body(self, payload):
        try:
            self.wfile.write(payload)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _send_bytes(self, status, payload, content_type, head=False, cookies=None,
                    extra_headers=None):
        self.send_response(status)
        self._common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if not head:
            self._write_body(payload)

    def _send_json(self, status, payload, head=False, cookies=None, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8",
                         head=head, cookies=cookies, extra_headers=extra_headers)

    def _send_ok(self, status, data, head=False, cookies=None):
        self._send_json(status, {"ok": True, "data": data}, head=head, cookies=cookies)

    def _send_error(self, status, code, message, hint=None, head=False,
                    extra_headers=None):
        error = {"code": str(code), "message": _truncate(str(message), 500)}
        if hint:
            error["hint"] = _truncate(str(hint), 500)
        payload = {"ok": False, "error": error}
        headers = dict(extra_headers or {})
        if status in (411, 413):
            self.close_connection = True
        self._send_json(status, payload, head=head, extra_headers=headers)

    def _send_console_error(self, exc, head=False):
        self._send_error(exc.status, exc.code, exc.message, exc.hint, head=head,
                         extra_headers=exc.headers)

    # ---- 请求体 ----

    def _read_body_bytes(self):
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding and "chunked" in transfer_encoding.lower():
            raise ConsoleError("LENGTH_REQUIRED", "不支持 chunked 请求体",
                               hint="请发送 Content-Length", status=411)
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            raise ConsoleError("INVALID_REQUEST", "Content-Length 无效", status=400)
        if length < 0:
            raise ConsoleError("INVALID_REQUEST", "Content-Length 无效", status=400)
        limit = getattr(self, '_request_body_limit', MAX_BODY_BYTES)
        if length > limit:
            raise ConsoleError("PAYLOAD_TOO_LARGE", "请求体过大（上限 %d MiB）" % (limit >> 20), status=413)
        if length == 0:
            return b""
        data = self.rfile.read(length)
        if len(data) != length:
            raise ConsoleError("INVALID_REQUEST", "请求体不完整", status=400)
        return data

    def _parse_json_object(self, raw):
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ConsoleError("INVALID_JSON", "请求体不是合法 JSON")
        if not isinstance(value, dict):
            raise ConsoleError("INVALID_BODY", "请求体必须是 JSON 对象")
        return value

    # ---- 路由入口 ----

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("GET", head=True)

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PATCH(self):
        self._send_error(405, "METHOD_NOT_ALLOWED", "不支持的请求方法",
                         extra_headers={"Allow": "GET, HEAD, POST, PUT, DELETE"})

    def do_OPTIONS(self):
        self._send_error(405, "METHOD_NOT_ALLOWED", "不支持的请求方法",
                         extra_headers={"Allow": "GET, HEAD, POST, PUT, DELETE"})

    def _handle(self, method, head=False):
        self._request_started = time.monotonic()
        try:
            split = urllib.parse.urlsplit(self.path)
            decoded_path = urllib.parse.unquote(split.path or "/")
            query = urllib.parse.parse_qs(split.query or "", keep_blank_values=True)
            self._request_body_limit = MAX_BODY_BYTES
            if method == 'POST' and decoded_path.rstrip('/') == '/api/imports/preview':
                # Authenticate before accepting a larger body, including on keep-alive connections.
                session = self._session()
                if session is None:
                    self.close_connection = True
                    raise ConsoleError('AUTH_REQUIRED', '需要登录', status=401)
                try:
                    self._require_csrf(session)
                except ConsoleError:
                    self.close_connection = True
                    raise
                self._request_body_limit = MAX_IMPORT_BODY_BYTES
            if method in ("POST", "PUT", "DELETE", "PATCH"):
                self._body = self._parse_json_object(self._read_body_bytes())
            else:
                self._body = {}
                self._discard_body()
            if decoded_path == "/api" or decoded_path.startswith("/api/"):
                self._handle_api(method, head, decoded_path, query)
            else:
                self._handle_static(method, head, decoded_path)
        except ConsoleError as exc:
            self._send_console_error(exc, head=head)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            _warn("未捕获异常：\n%s" % traceback.format_exc())
            try:
                self._send_error(500, "INTERNAL", "服务器内部错误", head=head)
            except Exception:  # noqa: BLE001
                self.close_connection = True

    def _discard_body(self):
        """GET/HEAD 若带 body 也读掉，保持 keep-alive 连接流对齐。"""
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self.close_connection = True
            return
        if length <= 0:
            return
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            return
        try:
            self.rfile.read(length)
        except OSError:
            self.close_connection = True

    # ---- API ----

    def _handle_api(self, method, head, decoded_path, query):
        app = self.server.app
        if "\x00" in decoded_path:
            raise ConsoleError("PATH_INVALID", "路径非法", status=400)
        trimmed = decoded_path.rstrip("/")
        parts = [part for part in trimmed.split("/") if part]
        if not parts or parts[0] != "api":
            raise ConsoleError("NOT_FOUND", "接口不存在", status=404)
        rest = parts[1:]
        for part in rest:
            if part in ("..", ".") or "\\" in part:
                raise ConsoleError("PATH_INVALID", "路径非法", status=400)

        source = self._source()

        # -------- 公开 API --------
        if rest == ["status"]:
            self._require_method(method, ("GET",))
            session = self._session()
            self._send_ok(200, app.status_data(session, source), head=head)
            return
        if rest == ["setup"]:
            self._require_method(method, ("POST",))
            data = app.setup(self._body, source=source)
            self._send_ok(201, data, head=head)
            return
        if rest == ["login"]:
            self._require_method(method, ("POST",))
            data, cookies = app.login(self._body, source=source)
            self._send_ok(200, data, head=head, cookies=cookies)
            return

        # -------- 以下全部需要登录（未登录一律 401） --------
        session = self._session()
        if session is None:
            raise ConsoleError("AUTH_REQUIRED", "需要登录",
                               hint="请先登录 Web 控制台", status=401)
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            self._require_csrf(session)

        if rest == ["logout"]:
            self._require_method(method, ("POST",))
            data, cookies = app.logout(source=source)
            self._send_ok(200, data, head=head, cookies=cookies)
            return

        if rest and rest[0] in ("ai", "imports"):
            try:
                from bindkit_admin import dispatch, AdminError
            except ImportError:
                raise ConsoleError("INTEGRATION_MISSING", "请重新运行安装程序以更新管理模块", status=503) from None
            try:
                self._send_ok(200, dispatch(app, method, rest, self._body), head=head)
            except AdminError as exc:
                raise ConsoleError(exc.code, exc.message, status=exc.status) from None
            return

        if rest == ["approvals"]:
            self._require_method(method, ("GET",))
            status_filter = (_flat_query(query).get("status") or "pending").strip()
            self._send_ok(200, app.list_approvals(status_filter), head=head)
            return

        if len(rest) == 3 and rest[0] == "approvals" and rest[2] in ("approve", "reject"):
            self._require_method(method, ("POST",))
            data = app.decide_approval(rest[1], rest[2] == "approve", self._body,
                                       source=source)
            self._send_ok(200, data, head=head)
            return

        if rest == ["audit"]:
            self._require_method(method, ("GET",))
            self._send_ok(200, app.list_audit(query), head=head)
            return

        if rest == ["policy"]:
            if method == "GET":
                data = app.call_handler("policy_get")
                self._send_ok(200, data, head=head)
                return
            if method == "PUT":
                body = self._body if isinstance(self._body, dict) else {}
                data = app.call_handler("policy_put", body=body, source=source)
                self._send_ok(200, data, head=head)
                return
            self._method_not_allowed(("GET", "PUT"))

        # -------- 工具资源 API --------
        resource = app.resource
        if not rest or rest[0] != resource:
            raise ConsoleError("NOT_FOUND", "接口不存在", status=404)
        tail = rest[1:]
        if not tail:
            if method == "GET":
                self._send_ok(200, app.call_list_handler(), head=head)
                return
            if method == "POST":
                name = app.validate_create_body(self._body)
                data = app.call_handler("create", name=name, body=self._body,
                                        source=source)
                self._send_ok(201, data, head=head)
                return
            self._method_not_allowed(("GET", "POST"))
        if len(tail) == 1:
            name = _validate_name(tail[0], field="name" if app.tool == "ssh" else "alias")
            if method == "GET":
                self._send_ok(200, app.call_handler("get", name=name), head=head)
                return
            if method == "PUT":
                data = app.call_handler("update", name=name, body=self._body,
                                        source=source)
                self._send_ok(200, data, head=head)
                return
            if method == "DELETE":
                merged = _flat_query(query)
                if isinstance(self._body, dict):
                    merged.update(self._body)
                data = app.call_handler("delete", name=name, body=merged,
                                        source=source)
                self._send_ok(200, data, head=head)
                return
            self._method_not_allowed(("GET", "PUT", "DELETE"))
        if len(tail) == 2 and tail[1] == "test":
            name = _validate_name(tail[0], field="name" if app.tool == "ssh" else "alias")
            if method == "POST":
                data = app.call_handler("test", name=name, source=source)
                self._send_ok(200, data, head=head)
                return
            self._method_not_allowed(("POST",))
        if app.tool == "ssh" and len(tail) == 2 and tail[1] == "users":
            self._require_method(method, ("GET",))
            name = _validate_name(tail[0], field="name")
            self._send_ok(200, app.call_handler("users", name=name), head=head)
            return
        if app.tool == "ssh" and len(tail) == 2 and tail[1] == "unlock":
            self._require_method(method, ("POST",))
            name = _validate_name(tail[0], field="name")
            self._send_ok(200, app.call_handler("unlock", name=name, body=self._body), head=head)
            return
        raise ConsoleError("NOT_FOUND", "接口不存在", status=404)

    # ---- 认证辅助 ----

    def _require_method(self, method, allowed):
        if method not in allowed:
            self._method_not_allowed(allowed)

    def _method_not_allowed(self, allowed):
        raise ConsoleError("METHOD_NOT_ALLOWED", "不支持的请求方法",
                           status=405, headers={"Allow": ", ".join(allowed)})

    def _require_csrf(self, session):
        header = self.headers.get(CSRF_HEADER)
        cookie_nonce = self._cookies().get(CSRF_COOKIE)
        if not header:
            raise ConsoleError("CSRF_MISSING",
                               "缺少 %s 请求头" % CSRF_HEADER,
                               hint="非 GET 请求必须携带 CSRF token",
                               status=403)
        if not cookie_nonce or not _constant_time_eq(header, cookie_nonce) \
                or not _constant_time_eq(header, session.nonce):
            raise ConsoleError("CSRF_INVALID", "CSRF 校验失败",
                               hint="请刷新页面获取新的 CSRF token 后重试",
                               status=403)

    # ---- 静态 ----

    def _handle_static(self, method, head, decoded_path):
        if method != "GET":
            self._method_not_allowed(("GET", "HEAD"))
        result = self.server.app.resolve_static(decoded_path)
        self._send_bytes(result["status"], result["body"], result["content_type"],
                         head=head)


# ---------------------------------------------------------------------------
# 服务启动
# ---------------------------------------------------------------------------

def _port_in_use_hint(tool, port, target=None):
    program = TOOL_PROGRAMS.get(tool, "bindconsole")
    check_host = target.host if target is not None else "127.0.0.1"
    check_family = target.family if target is not None else socket.AF_INET
    for candidate in range(port + 1, min(port + 11, 65536)):
        if _port_available(candidate, check_host, check_family):
            return ("端口 %d 已被占用；换一个端口：%s --startserver --port %d"
                    % (port, program, candidate))
    return "端口 %d 已被占用；请用 --startserver --port <其他端口> 换一个端口" % port


def _port_available(port, host="127.0.0.1", family=socket.AF_INET):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def create_server(tool, port=None, handlers=None, host="127.0.0.1", home=None,
                  web_root=None, policy=None,
                  login_max_failures=LOGIN_MAX_FAILURES,
                  login_lockout_s=LOGIN_LOCKOUT_S,
                  session_ttl_s=SESSION_TTL_S):
    """创建（并绑定）一个控制台 HTTP 服务器，不启动 serve_forever。

    测试/前端联调可传 ``port=0`` 取随机端口、``home=<临时目录>``、``policy=False``。
    启动失败抛 :class:`ConsoleStartupError`（工具侧应打印原因+提示后退出）。
    """
    if tool not in ALLOWED_TOOLS:
        raise ValueError("tool 必须是 'ssh' 或 'db'，收到：%r" % (tool,))
    target = _classify_bind_host(host)      # CONTRACT §2 白名单，其他地址拒绝启动
    if port is None:
        port = default_port(tool)
    if isinstance(port, bool) or not isinstance(port, int):
        raise ConsoleStartupError("端口必须是整数，收到：%r" % (port,))
    if port < 0 or port > 65535:
        raise ConsoleStartupError("端口超出范围（0..65535）：%d" % port)

    app = ConsoleApp(tool, port, handlers=handlers, host=target.host,
                     bind_target=target, home=home, web_root=web_root,
                     policy=policy, login_max_failures=login_max_failures,
                     login_lockout_s=login_lockout_s, session_ttl_s=session_ttl_s)
    server_class = (ConsoleHTTPServerV6 if target.family == socket.AF_INET6
                    else ConsoleHTTPServer)
    try:
        httpd = server_class((target.host, port), app)
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1)):
            raise ConsoleStartupError(
                "端口 %d 已被占用（%s）" % (port, target.host),
                hint=_port_in_use_hint(tool, port, target))
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise ConsoleStartupError(
                "没有权限绑定端口 %d（%s）" % (port, target.host),
                hint="请换一个大于 1024 的端口：--startserver --port 8790")
        raise ConsoleStartupError(
            "无法绑定 %s:%d：%s" % (target.host, port, exc),
            hint="请检查 host/端口后重试（局域网 IP 必须是本机网卡地址）")
    bound_host = httpd.server_address[0]
    if bound_host != target.host:       # 双保险：实际绑定地址必须与请求一致
        httpd.server_close()
        raise ConsoleStartupError(
            "绑定地址异常（请求 %r，实际 %r），拒绝启动" % (target.host, bound_host))
    app.port = int(httpd.server_address[1])
    return httpd


def _print_banner(httpd, daemon_info=None):
    app = httpd.app
    urls = httpd.urls or ["http://127.0.0.1:%d/" % int(httpd.server_address[1])]
    lan_mode = app.bind_target.is_lan_mode
    lines = ["bindconsole · %s Web 控制台" % app.program]
    if lan_mode:
        lines.append("  模式:      局域网（--host %s）" % app.bind_target.host)
        lines.append("  ⚠ 警告:    HTTP 明文传输，密码/密钥会经过局域网；"
                     "仅用于临时导入，用完 Ctrl-C 关闭")
        lines.append("  ⚠ 警告:    同网段设备均可访问登录页，"
                     "请勿在不可信网络 / 公网环境长期开启")
        if app.bind_target.kind == "wildcard" and not urls:
            lines.append("  警告:      未检测到本机局域网 IPv4 地址，当前仅本机可访问")
        lines.append("  局域网地址:")
        for url in urls:
            lines.append("    %s" % url)
    else:
        lines.append("  地址:      %s" % urls[0])
    if daemon_info:
        lines.append("  状态:      已在后台运行（pid=%d）" % daemon_info["pid"])
        lines.append("  日志:      %s" % daemon_info["log"])
        lines.append("  停止:      kill $(cat %s)" % daemon_info["pid_file"])
    else:
        lines.append("  认证:      首次访问设置管理密码（两个控制台共用 ~/.bindconsole/secret.json）")
        lines.append("  停止:      Ctrl-C")
    if app.setup_requires_token():
        lines.append("")
        lines.append("  ⚠ 首次设置: 局域网模式需要一次性 setup token（只在本终端显示，设置密码时填入）")
        lines.append("    setup_token: %s" % app.setup_token)
    if not os.path.isdir(app.web_root):
        lines.append("  警告:      前端未安装（%s），API 可用但页面不可用；"
                     "请运行 bash bindconsole/install.sh" % app.web_root)
    if not app.handlers:
        lines.append("  警告:      未注册工具 handlers，资源 API 不可用")
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()


def _print_startup_error(program, exc):
    sys.stderr.write("[%s] Web 控制台启动失败\n" % program)
    sys.stderr.write("  原因: %s\n" % exc.message)
    if exc.hint:
        sys.stderr.write("  提示: %s\n" % exc.hint)
    sys.stderr.flush()


def _open_browser(url, program):
    try:
        opened = webbrowser.open(url)
    except Exception as exc:  # noqa: BLE001
        _warn("无法自动打开浏览器: %s" % exc)
        open_note = "请手动打开 %s" % url
    else:
        open_note = None if opened else "请手动打开 %s" % url
    if open_note:
        sys.stdout.write("  %s\n" % open_note)
        sys.stdout.flush()


def _serve_forever(httpd):
    def _signal_exit(_signum, _frame):
        raise KeyboardInterrupt

    if threading.current_thread() is threading.main_thread():
        try:
            signal.signal(signal.SIGTERM, _signal_exit)
            signal.signal(signal.SIGINT, signal.default_int_handler)
        except (ValueError, OSError):
            pass
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass


def _run_daemon(httpd, open_browser=False):
    """先绑定成功再 fork（前台就能报端口占用），父进程打印信息后退出 0。"""
    app = httpd.app
    if not hasattr(os, "fork"):
        _print_startup_error(app.program, ConsoleStartupError(
            "当前平台不支持 --daemon（缺少 os.fork）",
            hint="请以前台方式运行：%s --startserver" % app.program))
        httpd.server_close()
        return 1
    run_dir = os.path.join(app.runtime_dir, "run")
    _ensure_dir(run_dir, 0o700)
    pid_file = os.path.join(run_dir, "%s.pid" % app.tool)
    log_file = os.path.join(run_dir, "%s.log" % app.tool)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid > 0:
        os.close(write_fd)
        try:
            os.read(read_fd, 128)       # 等子进程完成 setsid/重定向/写 pid
        except OSError:
            pass
        finally:
            os.close(read_fd)
        _print_banner(httpd, daemon_info={"pid": pid, "log": log_file,
                                          "pid_file": pid_file})
        return 0
    # ---- 子进程 ----
    os.close(read_fd)
    exit_code = 0
    try:
        os.setsid()
        log_fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.dup2(log_fd, 0)
            os.dup2(log_fd, 1)
            os.dup2(log_fd, 2)
        finally:
            if log_fd > 2:
                os.close(log_fd)
        # fork 前调用方可能替换过 sys.stdout/sys.stderr 对象（测试/工具重定向），
        # dup2 只改 fd 不改 Python 对象；这里重建到新 fd，保证 daemon 日志确实落文件。
        try:
            sys.stdout = os.fdopen(os.dup(1), "w", buffering=1,
                                    encoding="utf-8", errors="replace")
            sys.stderr = os.fdopen(os.dup(2), "w", buffering=1,
                                    encoding="utf-8", errors="replace")
        except OSError:
            pass
        with open(pid_file, "w", encoding="ascii") as fh:
            fh.write("%d\n" % os.getpid())
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(pid_file, 0o600)
        except OSError:
            pass
        try:
            os.write(write_fd, b"ok\n")
        finally:
            os.close(write_fd)
        if open_browser:
            _open_browser(httpd.url, app.program)
        _serve_forever(httpd)
    except Exception:  # noqa: BLE001
        exit_code = 1
        try:
            _warn("后台运行异常：\n%s" % traceback.format_exc())
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            os.unlink(pid_file)
        except OSError:
            pass
        try:
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
    os._exit(exit_code)


def run_console(tool, port=None, handlers=None, daemon=False, open_browser=False,
                host="127.0.0.1", home=None, web_root=None):
    """统一启动入口（CONTRACT §7.1.1 冻结）。

    :param tool: ``"ssh"`` 或 ``"db"``
    :param port: 默认 ssh=8790 / db=8791
    :param handlers: 工具侧回调 dict，见模块 docstring
    :param daemon: 后台运行（fork + setsid，pid/log 在 ~/.bindconsole/run/）
    :param open_browser: 启动后自动打开浏览器
    :param host: 绑定地址，默认 127.0.0.1；允许 0.0.0.0 / ::1 / 本机局域网 IPv4
        （局域网模式会打印 LAN URL + 警告，首次 setup 需终端打印的一次性 setup_token）
    :returns: 进程退出码（0 成功、1 启动失败）
    """
    program = TOOL_PROGRAMS.get(tool, "bindconsole")
    try:
        httpd = create_server(tool, port=port, handlers=handlers, host=host,
                              home=home, web_root=web_root)
    except ConsoleStartupError as exc:
        _print_startup_error(program, exc)
        return 1
    except ValueError as exc:
        _print_startup_error(program, ConsoleStartupError(str(exc)))
        return 1

    if daemon:
        return _run_daemon(httpd, open_browser=open_browser)

    _print_banner(httpd)
    if open_browser:
        _open_browser(httpd.url, program)
    try:
        _serve_forever(httpd)
    finally:
        sys.stdout.write("bindconsole · %s 已停止\n" % program)
        sys.stdout.flush()
    return 0


# ---------------------------------------------------------------------------
# 开发/调试 CLI（工具侧只需 import run_console）
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bindkit_console",
        description="bindconsole 共享 Web 控制台内核（开发调试入口；生产由 sshbind/dbbind --startserver 调用）")
    parser.add_argument("--tool", choices=ALLOWED_TOOLS, default="ssh")
    parser.add_argument("--port", type=int, default=None,
                        help="默认 ssh=8790 / db=8791")
    parser.add_argument("--daemon", action="store_true", help="后台运行")
    parser.add_argument("--open", dest="open_browser", action="store_true",
                        help="启动后自动打开浏览器")
    parser.add_argument("--host", default="127.0.0.1",
                        help="绑定地址：127.0.0.1（默认）/ 0.0.0.0 / ::1 / "
                             "本机局域网 IPv4；其他地址拒绝启动")
    parser.add_argument("--home", default=None,
                        help="覆盖 HOME（仅测试/调试用）")
    parser.add_argument("--web-root", default=None,
                        help="覆盖静态根目录（仅测试/调试用，默认 ~/.bindconsole/web）")
    args = parser.parse_args(argv)
    return run_console(args.tool, port=args.port, handlers=None,
                       daemon=args.daemon, open_browser=args.open_browser,
                       host=args.host, home=args.home, web_root=args.web_root)


__all__ = [
    "run_console", "create_server", "main",
    "ConsoleError", "ConsoleStartupError",
    "KERNEL_VERSION", "VERSION", "DEFAULT_PORTS", "default_port", "is_loopback",
    "SESSION_COOKIE", "CSRF_COOKIE", "CSRF_HEADER", "SESSION_TTL_S",
    "PBKDF2_ITERATIONS", "MAX_BODY_BYTES", "TOOL_PROGRAMS",
    "BindTarget", "LOOPBACK_HOSTS", "WILDCARD_HOSTS", "LAN_ALLOWED_HINT",
]

if __name__ == "__main__":
    sys.exit(main())
