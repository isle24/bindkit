#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台联调测试：用 **backend 的真实内核** 验证工具侧 --startserver + handlers。

不 mock 内核：把 bindkit_console.py / bindkit_policy.py / web/ 复制到隔离 HOME 的
~/.bindconsole/，用 `dbbind --startserver` / `sshbind --startserver` 真启动两个控制台，
再用 HTTP 走完 setup→登录→资源列表→策略读写→测试→审批列表→审计→CSRF/401 负例，
并确认两个控制台可同时运行、互不影响。

用法：python3 tests/policy/test_console_integration.py [--keep]
退出码 0=全过（缺内核时 SKIP），1=有 FAIL。
"""

import http.cookiejar
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.abspath(os.path.join(HERE, "..", ".."))
WORKSPACE = os.path.abspath(os.path.join(PROJECT, ".."))
DBBIND = os.environ.get("DBBIND_NEW") or os.path.join(WORKSPACE, "dbbind", "dbbind")
SSHBIND = os.environ.get("SSHBIND_NEW") or os.path.join(WORKSPACE, "sshbind", "sshbind")
KEEP = "--keep" in sys.argv
PASS, FAIL, SKIP = [], [], []
PROCS = []
HOMES = []
PASSWORD = "console-test-pw-2026"


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  PASS  %s" % name)
    else:
        FAIL.append("%s  %s" % (name, detail))
        print("  FAIL  %s   %s" % (name, detail))


def skip(name, why):
    SKIP.append("%s（%s）" % (name, why))
    print("  SKIP  %s（%s）" % (name, why))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_home(tool):
    home = tempfile.mkdtemp(prefix="bindkit-console-")
    HOMES.append(home)
    # 工具状态
    if tool == "db":
        dbpath = os.path.join(home, "app.db")
        con = sqlite3.connect(dbpath)
        con.execute("create table users(id int, name text)")
        con.execute("insert into users values (1,'a')")
        con.commit()
        con.close()
        os.makedirs(os.path.join(home, ".dbbind"), exist_ok=True)
        with open(os.path.join(home, ".dbbind", "config.json"), "w") as f:
            json.dump({"version": 1, "databases": {
                "console-sqlite": {"engine": "sqlite", "file": dbpath}}}, f)
    else:
        sdir = os.path.join(home, ".ssh", "sshbind")
        os.makedirs(os.path.join(sdir, "keys"), exist_ok=True)
        fake_key = os.path.join(sdir, "keys", "fake")
        open(fake_key, "w").write("fake-key-content")
        with open(os.path.join(sdir, "servers.json"), "w") as f:
            json.dump({"version": 1, "servers": {
                "console-fake": {"name": "console-fake", "host": "127.0.0.1",
                                 "user": "root", "port": 22, "key": fake_key,
                                 "fingerprint": "SHA256:abc", "key_type": "ed25519",
                                 "restrict": False, "certificate": None,
                                 "source": "generated", "installed": True,
                                 "created_at": "2026-10-19T00:00:00"}}}, f)
    # 内核安装副本
    lib = os.path.join(home, ".bindconsole", "lib")
    os.makedirs(lib, exist_ok=True)
    for filename in os.listdir(PROJECT):
        if filename.startswith('bindkit_') and filename.endswith('.py'):
            shutil.copy(os.path.join(PROJECT, filename), lib)
    if not os.path.isfile(os.path.join(PROJECT, "bindkit_console.py")):
        return home, False
    shutil.copy(os.path.join(PROJECT, "bindkit_console.py"), lib)
    web_src = os.path.join(PROJECT, "web")
    if os.path.isdir(web_src):
        shutil.copytree(web_src, os.path.join(home, ".bindconsole", "web"))
    return home, True


class Client(object):
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.jar))
        self.token = None

    def csrf(self):
        for c in self.jar:
            if c.name == "bindconsole_csrf":
                return c.value
        return self.token

    def request(self, method, path, body=None, csrf=True, timeout=10):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if csrf and method != "GET":
            token = self.csrf()
            if token:
                headers["X-Bindconsole-CSRF"] = token
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                parsed = json.loads(raw) if raw.strip() else None
                if isinstance(parsed, dict):
                    data = parsed.get("data") if isinstance(parsed.get("data"), dict) else {}
                    if data.get("csrf_token"):
                        self.token = data["csrf_token"]
                return resp.status, parsed, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(raw), raw
            except ValueError:
                return e.code, None, raw
        except Exception as e:                 # noqa: BLE001
            return 0, None, str(e)


def wait_up(client, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if PROCS and PROCS[-1].poll() is not None:
            return False
        st, data, raw = client.request("GET", "/api/status", timeout=2)
        if st == 200 and data:
            return True
        time.sleep(0.2)
    return False


def local_lan_ip():
    """探测本机局域网 IPv4（UDP connect 不会真的发包）。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
        return ip if ip and not ip.startswith("127.") else None
    except OSError:
        return None


def run(cmd, home, inp=None, timeout=90):
    """跑一条命令（隔离 HOME）：(rc, stdout, stderr)。"""
    env = dict(os.environ)
    env["HOME"] = home
    env.pop("BINDCONSOLE_HOME", None)
    try:
        p = subprocess.run(cmd, input=(inp.encode() if inp is not None else None),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=(None if inp is not None else subprocess.DEVNULL),
                           env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def start_console_logged(tool_cmd, home, port, extra=()):
    """启动控制台并把 stdout/stderr 落文件（局域网模式要读启动 banner 里的 token/LAN URL）。"""
    env = dict(os.environ)
    env["HOME"] = home
    env.pop("BINDCONSOLE_HOME", None)
    log_path = os.path.join(home, "console-%d.log" % port)
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, tool_cmd, "--startserver", "--port", str(port)] + list(extra),
                            stdout=log, stderr=subprocess.STDOUT, env=env)
    PROCS.append(proc)
    return proc, log_path


def start_console(tool_cmd, tool, home, port):
    env = dict(os.environ)
    env["HOME"] = home
    env.pop("BINDCONSOLE_HOME", None)
    proc = subprocess.Popen([sys.executable, tool_cmd, "--startserver", "--port", str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    PROCS.append(proc)
    return proc


def login_flow(tool, home, port, prefix):
    base = "http://127.0.0.1:%d" % port
    c = Client(base)
    st, data, raw = c.request("GET", "/api/status")
    check("%s GET /api/status 200 + setup_required" % prefix,
          st == 200 and data and data.get("data", {}).get("setup_required") is True,
          "st=%s %s" % (st, raw[:160]))
    # 未登录访问资源 -> 401
    st, data, raw = c.request("GET", "/api/%s" % ("databases" if tool == "db"
                                                  else "servers"))
    check("%s 未登录 API -> 401" % prefix,
          st == 401 and data and data["error"]["code"] == "AUTH_REQUIRED", st)
    # setup
    st, data, raw = c.request("POST", "/api/setup", {"password": PASSWORD})
    check("%s POST /api/setup 201" % prefix, st in (200, 201), "st=%s %s" % (st, raw[:200]))
    check("%s setup 响应不含密码" % prefix, PASSWORD not in (raw or ""))
    # 登录（内核在登录响应里下发 CSRF cookie/token）
    st, data, raw = c.request("POST", "/api/login", {"password": PASSWORD})
    check("%s POST /api/login 200" % prefix, st == 200, "st=%s %s" % (st, raw[:200]))
    check("%s 登录后拿到 CSRF token" % prefix, c.csrf() is not None)
    # CSRF 负例：已登录后，非 GET 不带 header -> 403
    st, data, raw = c.request("PUT", "/api/policy", {"defaults": {"max_level": "read"}},
                              csrf=False)
    check("%s CSRF 缺失被拒（403）" % prefix,
          st == 403 and data and data["error"]["code"].startswith("CSRF"),
          "st=%s %s" % (st, raw[:160]))
    return c


def test_db_console(home, kernel_ok):
    print("\n== A. dbbind 控制台（--startserver + handlers + 真实内核）==")
    port = free_port()
    start_console(DBBIND, "db", home, port)
    base = "http://127.0.0.1:%d" % port
    if not wait_up(Client(base)):
        proc = PROCS[-1]
        proc.terminate()
        try:
            _, raw_error = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, raw_error = proc.communicate(timeout=5)
        err = (raw_error or b"").decode("utf-8", "replace")
        check("dbbind 控制台启动", False, err[-400:])
        return
    check("dbbind 控制台启动并监听", True)
    c = login_flow("db", home, port, "db")
    st, data, raw = c.request("GET", "/api/databases")
    payload = (data or {}).get("data") or {}
    items = payload.get("databases") or payload.get("items") or []
    names = [i["alias"] for i in items] if isinstance(items, list) else []
    check("GET /api/databases 返回工具真实状态",
          st == 200 and "console-sqlite" in names, "st=%s %s" % (st, raw[:200]))
    check("列表不回显密码/私钥", PASSWORD not in raw
          and all("password" not in i for i in items)
          and "PRIVATE KEY" not in raw, raw[:160])
    # 测试连通性
    st, data, raw = c.request("POST", "/api/databases/console-sqlite/test")
    check("POST .../test 真连 sqlite",
          st == 200 and (data.get("data") or {}).get("usable") is True,
          "st=%s %s" % (st, raw[:200]))
    # 策略读写
    st, data, raw = c.request("PUT", "/api/policy",
                              {"defaults": {"max_level": "write"}})
    check("PUT /api/policy 成功", st == 200, "st=%s %s" % (st, raw[:200]))
    pol_file = os.path.join(home, ".dbbind", "policy.json")
    check("策略文件已写入",
          os.path.isfile(pol_file)
          and json.load(open(pol_file))["defaults"]["max_level"] == "write")
    st, data, raw = c.request("GET", "/api/policy")
    check("GET /api/policy 反映写入",
          st == 200 and data.get("data", {}).get("policy", {})
          .get("defaults", {}).get("max_level") == "write", raw[:200])
    # 审批列表/审计
    st, data, raw = c.request("GET", "/api/approvals")
    check("GET /api/approvals 200", st == 200)
    st, data, raw = c.request("GET", "/api/audit")
    check("GET /api/audit 200", st == 200)
    # handler 业务错误的精确 4xx（backend 内核原样映射 ConsoleError.status）
    st, data, raw = c.request("GET", "/api/databases/no-such-alias")
    check("未知别名 -> 404 NOT_FOUND",
          st == 404 and data and data["error"]["code"] == "NOT_FOUND",
          "st=%s %s" % (st, raw[:160]))
    st, data, raw = c.request("POST", "/api/databases",
                              {"alias": "console-sqlite", "engine": "sqlite",
                               "file": "/tmp/x.db"})
    check("重复创建 -> 409 CONFLICT",
          st == 409 and data and data["error"]["code"] == "CONFLICT",
          "st=%s %s" % (st, raw[:160]))
    # 登出吊销（内核 HIGH 修复）：logout 后旧 Cookie 重放 -> 401，重新登录恢复
    old_cookie = None
    for ck in c.jar:
        if ck.name and "sess" in ck.name.lower():
            old_cookie = "%s=%s" % (ck.name, ck.value)
    st, data, raw = c.request("POST", "/api/logout")
    check("POST /api/logout 200 且 revoked=true",
          st == 200 and (data or {}).get("data", {}).get("revoked") is True,
          "st=%s %s" % (st, raw[:160]))
    if old_cookie:
        req2 = urllib.request.Request(c.base + "/api/databases",
                                      headers={"Cookie": old_cookie}, method="GET")
        try:
            with c.opener.open(req2, timeout=5) as resp:
                st2 = resp.status
        except urllib.error.HTTPError as e:
            st2 = e.code
        check("logout 后旧 Cookie 重放 -> 401", st2 == 401, st2)
    else:
        skip("logout 旧 Cookie 重放", "没抓到 session cookie 名")
    st, data, raw = c.request("POST", "/api/login", {"password": PASSWORD})
    check("重新登录 200", st == 200, st)
    st, data, raw = c.request("GET", "/api/databases")
    check("重新登录后 API 可用", st == 200, st)

    # 路径穿越
    st, data, raw = c.request("GET", "/api/databases/../etc/passwd")
    check("路径穿越被拒（4xx）", 400 <= st < 500, st)


def test_ssh_console(home, kernel_ok):
    print("\n== B. sshbind 控制台（--startserver + handlers + 真实内核）==")
    port = free_port()
    start_console(SSHBIND, "ssh", home, port)
    base = "http://127.0.0.1:%d" % port
    if not wait_up(Client(base)):
        proc = PROCS[-1]
        proc.terminate()
        try:
            _, raw_error = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, raw_error = proc.communicate(timeout=5)
        err = (raw_error or b"").decode("utf-8", "replace")
        check("sshbind 控制台启动", False, err[-400:])
        return
    check("sshbind 控制台启动并监听", True)
    c = login_flow("ssh", home, port, "ssh")
    st, data, raw = c.request("GET", "/api/servers")
    payload = (data or {}).get("data") or {}
    items = payload.get("servers") or payload.get("items") or []
    names = [i["name"] for i in items] if isinstance(items, list) else []
    check("GET /api/servers 返回工具真实状态",
          st == 200 and "console-fake" in names, "st=%s %s" % (st, raw[:200]))
    check("服务器列表不含私钥内容", "fake-key-content" not in raw)
    # 改 sudo 策略
    st, data, raw = c.request("PUT", "/api/servers/console-fake", {"sudo": "deny",
                                                                  "note": "web 改的"})
    check("PUT /api/servers/<name> 改 sudo 策略", st == 200,
          "st=%s %s" % (st, raw[:200]))
    pol_file = os.path.join(home, ".ssh", "sshbind", "policy.json")
    check("ssh 策略文件写入 sudo=deny",
          os.path.isfile(pol_file)
          and json.load(open(pol_file))["servers"]["console-fake"]["sudo"] == "deny")
    st, data, raw = c.request("GET", "/api/servers/no-such")
    check("ssh 未知服务器 -> 404 NOT_FOUND",
          st == 404 and data and data["error"]["code"] == "NOT_FOUND",
          "st=%s %s" % (st, raw[:160]))
    # 审批列表/审计
    st, data, raw = c.request("GET", "/api/approvals")
    check("ssh GET /api/approvals 200", st == 200)
    st, data, raw = c.request("GET", "/api/audit?tool=ssh")
    check("ssh GET /api/audit 200", st == 200)


def _banner_token(text):
    for line in text.splitlines():
        if "setup_token:" in line:
            return line.split("setup_token:", 1)[1].strip()
    return None


def _banner_lan_urls(text):
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("http://") and "127.0.0.1" not in line and "::1" not in line:
            urls.append(line.rstrip("/"))
    return urls


def test_lan_mode():
    print("\n== C. 局域网模式 --host（CONTRACT §2）==")
    # --- dbbind --host 0.0.0.0 ---
    home, ok = make_home("db")
    if not ok:
        skip("局域网模式", "内核缺失")
        return
    port = free_port()
    proc, log_path = start_console_logged(DBBIND, home, port, ["--host", "0.0.0.0"])
    base = "http://127.0.0.1:%d" % port
    if not wait_up(Client(base)):
        check("dbbind --host 0.0.0.0 启动", False, "未监听")
        return
    check("dbbind --host 0.0.0.0 启动并监听", True)
    time.sleep(0.2)
    banner = open(log_path, encoding="utf-8").read()
    check("banner 打印局域网模式 + 警告",
          "局域网（--host 0.0.0.0）" in banner and "HTTP 明文传输" in banner
          and "局域网地址:" in banner, banner[:200])
    lan_urls = _banner_lan_urls(banner)
    check("banner 打印可用局域网 URL", bool(lan_urls), banner[:200])
    token = _banner_token(banner)
    check("banner 打印一次性 setup token", bool(token) and len(token) >= 8)
    c = Client(base)
    st, data, raw = c.request("GET", "/api/status")
    check("status.setup_requires_token=true",
          st == 200 and (data or {}).get("data", {}).get("setup_requires_token") is True,
          raw[:160])
    st, data, raw = c.request("POST", "/api/setup", {"password": PASSWORD})
    check("无 token setup -> 403 SETUP_TOKEN_REQUIRED",
          st == 403 and (data or {}).get("error", {}).get("code") == "SETUP_TOKEN_REQUIRED",
          raw[:160])
    st, data, raw = c.request("POST", "/api/setup",
                              {"password": PASSWORD, "setup_token": "wrong-token"})
    check("错 token -> 403 SETUP_TOKEN_INVALID",
          st == 403 and (data or {}).get("error", {}).get("code") == "SETUP_TOKEN_INVALID",
          raw[:160])
    st, data, raw = c.request("POST", "/api/setup",
                              {"password": PASSWORD, "setup_token": token})
    check("带正确 token -> 成功设置", st in (200, 201), "st=%s %s" % (st, raw[:160]))
    st, data, raw = c.request("GET", "/api/status")
    check("setup 后 setup_requires_token=false",
          (data or {}).get("data", {}).get("setup_requires_token") is False)
    st, data, raw = c.request("POST", "/api/login", {"password": PASSWORD})
    check("局域网模式可登录", st == 200, st)
    st, data, raw = c.request("GET", "/api/databases")
    check("局域网模式资源 API 可用", st == 200, st)
    # 通过真实 LAN IP 访问（如果本机有 LAN 地址）
    if lan_urls:
        lan_client = Client(lan_urls[0])
        st, data, raw = lan_client.request("GET", "/api/status", timeout=5) \
            if hasattr(lan_client, "request") else (0, None, "")
        try:
            st, data, raw = lan_client.request("GET", "/api/status")
            check("通过 LAN URL 可访问（%s）" % lan_urls[0], st == 200, st)
        except Exception as e:                 # noqa: BLE001
            check("通过 LAN URL 可访问（%s）" % lan_urls[0], False, str(e)[:120])
        check("LAN URL 端口正确", (":%d" % port) in lan_urls[0], lan_urls)
    else:
        skip("通过 LAN URL 访问", "本机未检测到局域网 IPv4")

    # --- 绑定「本机某个具体局域网 IP」 ---
    lan_ip = local_lan_ip()
    if lan_ip:
        port_ip = free_port()
        home_ip = make_home("db")[0]      # 新 HOME：secret.json 不存在，才需要 setup token
        proc_ip, log_ip = start_console_logged(DBBIND, home_ip, port_ip,
                                               ["--host", lan_ip])
        # 绑定具体 IP 时只在该 IP 上监听，不能用 127.0.0.1 探活
        up_ip = wait_up(Client("http://%s:%d" % (lan_ip, port_ip)))
        check("--host %s（具体局域网 IP）启动" % lan_ip, up_ip)
        if up_ip:
            time.sleep(0.2)
            banner_ip = open(log_ip, encoding="utf-8").read()
            check("banner 模式为局域网（具体 IP）",
                  ("局域网（--host %s）" % lan_ip) in banner_ip
                  and (":%d" % port_ip) in banner_ip and lan_ip in banner_ip,
                  banner_ip[:200])
            st, data, raw = Client("http://%s:%d" % (lan_ip, port_ip)) \
                .request("GET", "/api/status")
            check("通过具体 LAN IP 可访问", st == 200, st)
            check("具体 IP 模式同样要求 setup token",
                  (data or {}).get("data", {}).get("setup_requires_token") is True)
    else:
        skip("--host 具体局域网 IP", "本机无局域网 IPv4")

    # --- 公网地址必须拒绝 ---
    rc, out, err = run([DBBIND, "--startserver", "--port", str(free_port()),
                        "--host", "8.8.8.8"], home)
    check("--host 公网地址 -> 拒绝启动 rc≠0", rc != 0, "rc=%s %s" % (rc, err[:160]))
    check("拒绝时给出允许范围提示", "允许" in err or "不受支持" in err, err[:200])

    # --- 回环模式不受影响（无 token 要求）---
    home2, _ = make_home("db")
    port2 = free_port()
    proc2, log2 = start_console_logged(DBBIND, home2, port2, [])
    up2 = wait_up(Client("http://127.0.0.1:%d" % port2))
    check("缺省回环模式仍正常", up2)
    if up2:
        time.sleep(0.2)
        banner2 = open(log2, encoding="utf-8").read()
        check("回环模式无 setup token 要求", _banner_token(banner2) is None,
              banner2[:200])
        st, data, raw = Client("http://127.0.0.1:%d" % port2).request("GET", "/api/status")
        check("回环 setup_requires_token=false",
              (data or {}).get("data", {}).get("setup_requires_token") is False)

    # --- sshbind --host=0.0.0.0（等号写法）---
    home3 = make_home("ssh")[0]
    port3 = free_port()
    proc3, log3 = start_console_logged(SSHBIND, home3, port3, ["--host=0.0.0.0"])
    up3 = wait_up(Client("http://127.0.0.1:%d" % port3))
    check("sshbind --host=0.0.0.0（等号写法）启动", up3)
    if up3:
        time.sleep(0.2)
        banner3 = open(log3, encoding="utf-8").read()
        check("sshbind 局域网 banner + token",
              "局域网（--host 0.0.0.0）" in banner3
              and bool(_banner_token(banner3)), banner3[:200])
        st, data, raw = Client("http://127.0.0.1:%d" % port3).request("GET", "/api/status")
        check("sshbind 局域网 status.setup_requires_token=true",
              (data or {}).get("data", {}).get("setup_requires_token") is True)


def test_two_consoles():
    print("\n== D. 两个控制台同时运行、互不影响 ==")
    home_db, ok_db = make_home("db")
    home_ssh, ok_ssh = make_home("ssh")
    if not (ok_db and ok_ssh):
        skip("双控制台隔离", "内核缺失")
        return
    port_db, port_ssh = free_port(), free_port()
    start_console(DBBIND, "db", home_db, port_db)
    start_console(SSHBIND, "ssh", home_ssh, port_ssh)
    c_db = Client("http://127.0.0.1:%d" % port_db)
    c_ssh = Client("http://127.0.0.1:%d" % port_ssh)
    up_db, up_ssh = wait_up(c_db), wait_up(c_ssh)
    check("两个控制台同时启动", up_db and up_ssh, "db=%s ssh=%s" % (up_db, up_ssh))
    if up_db and up_ssh:
        st1, _, _ = c_db.request("GET", "/api/status")
        st2, _, _ = c_ssh.request("GET", "/api/status")
        check("两个 status 都正常", st1 == 200 and st2 == 200)
        # 杀掉 db 控制台，ssh 控制台应不受影响
        PROCS[0].terminate()
        time.sleep(0.5)
        st2b, data2b, _ = c_ssh.request("GET", "/api/status")
        check("杀掉一个控制台，另一个照常", st2b == 200, st2b)


def main():
    for path in (DBBIND, SSHBIND):
        if not os.path.isfile(path):
            print("缺少文件：%s" % path)
            return 1
    if not os.path.isfile(os.path.join(PROJECT, "bindkit_console.py")):
        print("SKIP：backend 的 bindkit_console.py 尚未落地")
        return 0
    try:
        home_db, ok_db = make_home("db")
        home_ssh, ok_ssh = make_home("ssh")
        test_db_console(home_db, ok_db)
        test_ssh_console(home_ssh, ok_ssh)
        test_lan_mode()
        test_two_consoles()
    finally:
        for proc in PROCS:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if KEEP:
            print("\n临时 HOME 保留：%s" % HOMES)
        else:
            for home in HOMES:
                shutil.rmtree(home, ignore_errors=True)
    print("\n===== 控制台联调：PASS %d  FAIL %d  SKIP %d =====" %
          (len(PASS), len(FAIL), len(SKIP)))
    for f in FAIL:
        print("  FAILED: " + f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
