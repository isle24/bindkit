#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bindkit_policy 单元回归测试（不依赖工具、不依赖网络）。

覆盖 CONTRACT bindconsole 的策略判定：
  * 无策略=allow（向后兼容，零副作用）
  * ssh sudo 关键字（§8.1.2 全表）与位置绕过
  * db 等级分类 / max_level 上限 / 白名单 / 元数据 / mysql 系统库禁用
  * 审批单全生命周期（建单/复用/批准/消费/拒绝/过期/并发只消费一次）
  * fail-closed 边界（§8.1.1：损坏策略、审批目录不可写）
  * 审计（决策齐全、绝不写密码）

用法：python3 tests/policy/test_policy_unit.py
退出码 0=全过，1=有失败。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, _PROJECT)

# 必须在 import bindkit_policy 之前隔离 HOME（模块导入时求值路径）
_TMP = tempfile.mkdtemp(prefix="bindkit-unit-")
os.environ["HOME"] = _TMP
os.environ.pop("BINDCONSOLE_HOME", None)

import bindkit_policy as P  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  PASS  %s" % name)
    else:
        FAIL.append("%s  %s" % (name, detail))
        print("  FAIL  %s   %s" % (name, detail))


def drop_policy(tool):
    path = P.tool_paths(tool)["policy"]
    if os.path.exists(path):
        os.remove(path)


def drop_approvals(tool):
    directory = P.tool_paths(tool)["approvals"]
    if os.path.isdir(directory):
        for name in os.listdir(directory):
            if name.endswith(".json"):
                os.remove(os.path.join(directory, name))


def clean(tool=None):
    for t in ([tool] if tool else ["ssh", "db"]):
        drop_policy(t)
        drop_approvals(t)


# ---------------------------------------------------------------------------
# 1. 向后兼容：无策略 → allow
# ---------------------------------------------------------------------------
def test_no_policy():
    print("\n== 1. 无策略 = allow（向后兼容）==")
    clean()
    audit_was = os.path.exists(P.AUDIT_LOG)
    r = P.gate_ssh("any", "sudo systemctl restart x")
    check("ssh 无策略 allow", r == {"decision": "allow"}, r)
    r = P.gate_db("any", "drop table t", "mysql", "db1")
    check("db 无策略 allow", r == {"decision": "allow"}, r)
    check("无策略不写审计（零副作用）",
          os.path.exists(P.AUDIT_LOG) == audit_was)
    check("policy_present false", P.policy_present("ssh") is False)


# ---------------------------------------------------------------------------
# 2. ssh 提权识别与判定
# ---------------------------------------------------------------------------
def test_ssh_sudo():
    print("\n== 2. ssh sudo 关键字与判定 ==")
    clean("ssh")
    P.write_policy("ssh", {"version": 1,
                           "defaults": {"sudo": "ask", "approval_ttl_s": 600},
                           "servers": {"nj": {"sudo": "allow"},
                                       "denybox": {"sudo": "deny"}}})
    # §8.1.2 全表：任意词边界出现即视为提权
    words = ["sudo", "sudoedit", "doas", "pkexec", "su", "runuser", "systemd-run",
             "machinectl", "nsenter", "chroot", "mount", "umount", "setcap",
             "passwd", "useradd", "usermod", "visudo"]
    for w in words:
        hit, word = P.is_sudo_command("echo x; %s --help" % w)
        check("关键字命中 %-12s" % w, hit and word == w)
    # 位置绕过样本
    bypass = ["sudo ls", "bash -c 'sudo rm -rf /'", 'sh -c "sudo systemctl x"',
              "echo $(sudo whoami)", "`sudo id`", "eval sudo ls",
              "x; sudo ls", "x && /usr/bin/sudo ls", "env FOO=1 sudo ls",
              "\n" + "sudo ls", "  \t " + "sudo ls"]
    for cmd in bypass:
        check("位置绕过被识别 %r" % cmd[:34], P.is_sudo_command(cmd)[0])
    # 引号/反斜杠拆词（shell 会拼回 sudo；只做归一化检测，执行仍用原串）
    for cmd in ['s""udo id', 's\\udo id', "s''udo id", 'su""do -i',
                "echo `s''udo id`", 's\\""udo id']:
        check("拆词绕过被识别 %r" % cmd, P.is_sudo_command(cmd)[0])
    # 非提权
    for cmd in ["ls -la", "echo hello", "df -h", "grep ERROR app.log"]:
        check("非提权放行 %r" % cmd, not P.is_sudo_command(cmd)[0])
    # 策略三档
    check("sudo=allow -> allow", P.gate_ssh("nj", "sudo ls")["decision"] == "allow")
    r = P.gate_ssh("denybox", "sudo ls")
    check("sudo=deny -> SUDO_DENIED", r["decision"] == "deny" and r["code"] == "SUDO_DENIED", r)
    r = P.gate_ssh("other", "sudo ls")
    check("缺省 sudo=ask -> APPROVAL_REQUIRED",
          r["decision"] == "ask" and r["code"] == "APPROVAL_REQUIRED"
          and r.get("request_id"), r)
    # 非提权命令在有策略时也 allow 并写审计
    check("非提权命令 allow", P.gate_ssh("other", "uptime")["decision"] == "allow")


# ---------------------------------------------------------------------------
# 3. 审批单生命周期
# ---------------------------------------------------------------------------
def test_approvals():
    print("\n== 3. 审批单生命周期 ==")
    clean("ssh")
    P.write_policy("ssh", {"version": 1, "defaults": {"sudo": "ask"}})
    cmd = "sudo systemctl restart nginx"
    r1 = P.gate_ssh("s1", cmd)
    check("首次 -> ask + request_id", r1["decision"] == "ask" and r1["request_id"].startswith("apr_"))
    r2 = P.gate_ssh("s1", cmd)
    check("同 fingerprint 复用 pending", r2.get("request_id") == r1["request_id"])
    check("不同命令 -> 新单", P.gate_ssh("s1", "sudo reboot").get("request_id") != r1["request_id"])
    ap = P.get_approval("ssh", r1["request_id"])
    check("审批单字段齐全",
          all(k in ap for k in ("id", "tool", "alias", "action", "target", "fingerprint",
                                "requester", "created_at", "expires_at", "status",
                                "decided_at", "decided_by", "consumes_left", "note")))
    check("初始 status=pending", ap["status"] == "pending")

    # 未批准时不能消费
    check("未批准仍 ask", P.gate_ssh("s1", cmd)["decision"] == "ask")
    # 批准 → 重试 → 消费
    approved = P.approve("ssh", r1["request_id"], consumes=1, ttl_s=300, note="ok")
    check("approve -> approved + consumes_left=1",
          approved["status"] == "approved" and approved["consumes_left"] == 1)
    exp = P._parse_iso(approved["expires_at"])
    check("approve TTL 语义 = now+ttl", abs((exp - P._now()).total_seconds() - 300) < 5,
          approved["expires_at"])
    r3 = P.gate_ssh("s1", cmd)
    check("批准后重试 -> allow（消费）", r3["decision"] == "allow"
          and r3.get("consumed_approval") == r1["request_id"], r3)
    check("消费后 status=consumed",
          P.get_approval("ssh", r1["request_id"])["status"] == "consumed")
    r4 = P.gate_ssh("s1", cmd)
    check("再次执行 -> 重新要审批（新单）",
          r4["decision"] == "ask" and r4["request_id"] != r1["request_id"])
    # 重复批准同一单：只有一次生效（第二次抛 ValueError）
    try:
        P.approve("ssh", r1["request_id"])
        check("重复批准被拒", False, "没有抛错")
    except ValueError:
        check("重复批准被拒", True)
    # 拒绝
    rid = r4["request_id"]
    P.reject("ssh", rid, note="不允许")
    check("reject -> denied", P.get_approval("ssh", rid)["status"] == "denied")
    check("拒绝后重试 -> 重新 ask", P.gate_ssh("s1", cmd)["decision"] == "ask")
    # 路径穿越
    check("审批单 id 白名单（../）", P.get_approval("ssh", "../../etc/passwd") is None)
    for bad in ("..%2f", "apr_x/../../y", ""):
        try:
            P.approve("ssh", bad)
            check("非法 id 批准被拒 %r" % bad, False)
        except ValueError:
            check("非法 id 批准被拒 %r" % bad, True)
    # expires_at 过期的单不能消费
    rid2 = P.gate_ssh("s1", "sudo reboot")["request_id"]
    ap = P.get_approval("ssh", rid2)
    ap["status"] = "approved"
    ap["consumes_left"] = 1
    ap["expires_at"] = P._iso(P._now() - P.timedelta(seconds=10))
    P._save_approval("ssh", ap)
    r5 = P.gate_ssh("s1", "sudo reboot")
    check("过期批准不可消费 -> ask", r5["decision"] == "ask")


# ---------------------------------------------------------------------------
# 4. 并发：同一批准单只消费一次
# ---------------------------------------------------------------------------
def test_concurrent_consume():
    print("\n== 4. 并发消费（跨进程）==")
    clean("ssh")
    P.write_policy("ssh", {"version": 1, "defaults": {"sudo": "ask"}})
    cmd = "sudo systemctl restart concurrent"
    rid = P.gate_ssh("c1", cmd)["request_id"]
    P.approve("ssh", rid, consumes=1, ttl_s=300)
    script = r'''
import json, os, sys
sys.path.insert(0, %r)
import bindkit_policy as P
print(json.dumps(P.gate_ssh("c1", %r)))
''' % (_PROJECT, cmd)
    env = dict(os.environ, HOME=_TMP)
    procs = [subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env) for _ in range(2)]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        try:
            results.append(json.loads(out.decode().strip().splitlines()[-1]))
        except Exception:                      # noqa: BLE001
            results.append({"decision": "error", "raw": out.decode() + err.decode()})
    allows = [r for r in results if r.get("decision") == "allow"]
    asks = [r for r in results if r.get("decision") == "ask"]
    check("并发只消费一次（1 allow + 1 ask）",
          len(allows) == 1 and len(asks) == 1, results)


# ---------------------------------------------------------------------------
# 5. db 等级 / 上限 / 审批
# ---------------------------------------------------------------------------
def _set_db_policy(databases, defaults=None):
    clean("db")
    P.write_policy("db", {"version": 1,
                          "defaults": defaults or {"max_level": "read",
                                                   "approval": {"write": False, "ddl": True},
                                                   "allow_metadata": True},
                          "databases": databases})


def test_db_levels():
    print("\n== 5. db 等级与 max_level 上限 ==")
    corpus = [
        ("SELECT 1", "read"), ("SHOW TABLES", "read"), ("DESCRIBE t", "read"),
        ("EXPLAIN SELECT 1", "read"), ("WITH x AS (SELECT 1) SELECT * FROM x", "read"),
        ("INSERT INTO t VALUES (1)", "write"), ("UPDATE t SET a=1", "write"),
        ("DELETE FROM t", "write"), ("REPLACE INTO t VALUES (1)", "write"),
        ("MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN DELETE", "write"),
        ("CREATE TABLE t(i int)", "ddl"), ("ALTER TABLE t ADD c int", "ddl"),
        ("DROP TABLE t", "ddl"), ("TRUNCATE TABLE t", "ddl"),
        ("RENAME TABLE a TO b", "ddl"), ("GRANT ALL ON *.* TO u", "ddl"),
        ("REVOKE ALL ON *.* FROM u", "ddl"), ("VACUUM", "ddl"),
        ("ATTACH DATABASE 'x' AS y", "ddl"), ("/*!50000 DROP TABLE t */", "ddl"),
        ("SELECT 1; DROP TABLE t", "ddl"), ("BEGIN", "ddl"),
        ("SET SESSION TRANSACTION READ WRITE", "ddl"),
        ("PRAGMA writable_schema=on", "ddl"),
        ("SELECT * INTO newtable FROM t", "ddl"),
        ("DO $$ BEGIN DELETE FROM t; END $$", "ddl"),
        ("WITH x AS (SELECT 1) DELETE FROM appdb.users", "write"),
        ("SELECT 'DROP TABLE t'", "ddl"),          # 宁可误报
    ]
    for sql, want in corpus:
        got = P.sql_required_level(sql, "mysql")
        check("等级 %-46s = %s" % (sql[:46], want), got == want, "got %s" % got)
    check("PRAGMA table_info 是 read",
          P.sql_required_level("PRAGMA table_info(t)", "sqlite") == "read")
    check("多语句取最高（select+update）",
          P.sql_required_level("SELECT 1; UPDATE t SET a=1", "mysql") == "write")

    _set_db_policy({"ro": {"max_level": "read"}})
    r = P.gate_db("ro", "INSERT INTO t VALUES (1)", "mysql", "db1", requested_write=True)
    check("max_level=read 压住 --write -> AUTHZ_DENIED",
          r["decision"] == "deny" and r["code"] == "AUTHZ_DENIED", r)
    r = P.gate_db("ro", "DROP TABLE t", "mysql", "db1", requested_unsafe=True)
    check("max_level=read 压住 --unsafe -> AUTHZ_DENIED",
          r["decision"] == "deny" and r["code"] == "AUTHZ_DENIED", r)
    check("max_level=read 的 SELECT 放行", P.gate_db("ro", "SELECT 1", "mysql", "db1")["decision"] == "allow")
    check("别名不在策略里 -> 用 defaults（read）",
          P.gate_db("unknown-alias", "DELETE FROM t", "mysql", "db1")["decision"] == "deny")

    _set_db_policy({"w": {"max_level": "write", "approval": {"write": False, "ddl": True}}})
    check("max_level=write + INSERT -> allow",
          P.gate_db("w", "INSERT INTO t VALUES (1)", "mysql", "db1")["decision"] == "allow")
    r = P.gate_db("w", "DROP TABLE t", "mysql", "db1")
    check("max_level=write + DROP -> deny", r["decision"] == "deny", r)


def test_db_approval():
    print("\n== 6. db 审批（write/ddl 开关）==")
    _set_db_policy({"a": {"max_level": "ddl",
                          "approval": {"write": True, "ddl": True}}})
    sql = "UPDATE users SET a=1 WHERE id=2"
    r1 = P.gate_db("a", sql, "mysql", "db1")
    check("write 审批开启 -> ask", r1["decision"] == "ask" and r1["code"] == "APPROVAL_REQUIRED", r1)
    P.approve("db", r1["request_id"], consumes=1, ttl_s=120)
    r2 = P.gate_db("a", sql, "mysql", "db1")
    check("批准后同一 SQL -> allow + 消费", r2["decision"] == "allow")
    check("审批单 consumed",
          P.get_approval("db", r1["request_id"])["status"] == "consumed")
    ddl_sql = "DROP TABLE t"
    r3 = P.gate_db("a", ddl_sql, "mysql", "db1")
    check("ddl 审批开启 -> ask", r3["decision"] == "ask", r3)
    check("ddl 与 write 指纹不同", r3["request_id"] != r1["request_id"])


# ---------------------------------------------------------------------------
# 7. 白名单 / 元数据 / mysql 系统库
# ---------------------------------------------------------------------------
def test_whitelist():
    print("\n== 7. 白名单 / 元数据 / mysql 系统库 ==")
    _set_db_policy({"wl": {"max_level": "ddl",
                           "allowed_databases": ["appdb", "analytics"]},
                    "free": {"max_level": "read"},
                    "nometa": {"max_level": "read", "allow_metadata": False},
                    "tbl": {"max_level": "read", "allowed_tables": ["users", "orders"]}})
    cases = [
        ("wl", "SELECT * FROM appdb.users", None, "allow", "白名单内库"),
        ("wl", "SELECT * FROM `appdb`.users", None, "allow", "白名单内库（反引号）"),
        ("wl", "SELECT * FROM `otherdb`.secret", None, "deny", "白名单外库（反引号）"),
        ("wl", 'SELECT * FROM "otherdb".secret', None, "deny", "白名单外库（双引号）"),
        ("wl", "SELECT * FROM otherdb.secret", None, "deny", "白名单外库"),
        ("wl", "SELECT 1", "otherdb", "deny", "default_db 白名单外"),
        ("wl", "USE otherdb; SELECT 1", "appdb", "deny", "USE 白名单外"),
        ("wl", "SET search_path = otherdb, public; SELECT 1", "appdb", "deny",
         "search_path 白名单外"),
        ("wl", "SHOW TABLES FROM otherdb", "appdb", "deny", "SHOW TABLES FROM 白名单外"),
        ("wl", "SHOW TABLES FROM appdb", "appdb", "allow", "SHOW TABLES FROM 白名单内"),
        ("wl", "SHOW COLUMNS FROM t", "appdb", "allow", "SHOW COLUMNS 不带库"),
        ("wl", "SHOW COLUMNS FROM t FROM otherdb", "appdb", "deny",
         "SHOW COLUMNS ... FROM 白名单外"),
        ("wl", "SELECT * FROM information_schema.tables", "appdb", "allow",
         "元数据读（allow_metadata=true）"),
        ("nometa", "SELECT * FROM information_schema.tables", "appdb", "deny",
         "元数据读（allow_metadata=false）"),
        ("wl", "SELECT * FROM pg_catalog.pg_class", "appdb", "allow", "pg_catalog 元数据"),
        ("free", "SELECT * FROM mysql.user", "db1", "deny", "mysql 系统库永远拒绝"),
        ("wl", "SELECT * FROM mysql.user", "appdb", "deny", "mysql 系统库永远拒绝"),
        ("tbl", "SELECT * FROM users", "db1", "allow", "allowed_tables 内"),
        ("tbl", "SELECT * FROM secrets", "db1", "deny", "allowed_tables 外"),
        ("tbl", "SELECT 1", "db1", "allow", "allowed_tables 无法确定 -> 放行"),
        ("tbl", "WITH c AS (SELECT 1) SELECT * FROM c", "db1", "allow",
         "CTE 名不算表"),
    ]
    for alias, sql, ddb, want, label in cases:
        r = P.gate_db(alias, sql, "mysql", ddb)
        check("%-34s -> %s" % (label, want), r["decision"] == want, r)

    # ---- PostgreSQL：a.b 里的 a 是 schema，不参与库白名单（Lead 复审 P1）----
    print("  -- PostgreSQL schema 语义 --")
    _set_db_policy({"pg": {"max_level": "ddl", "allowed_databases": ["appuser"]},
                    "pgsch": {"max_level": "read", "allowed_schemas": ["public"]}})
    pg_cases = [
        ("pg", "SELECT * FROM public.x", "appuser", "allow", "PG public.x 不误杀"),
        ("pg", "SELECT * FROM appuser.x", "appuser", "allow", "PG 连接库.schema 放行"),
        ("pg", "SELECT * FROM other_schema.x", "appuser", "allow", "PG schema 不参与库白名单"),
        ("pg", "SELECT * FROM public.messages LIMIT 1", "appuser", "allow",
         "PG public.messages 不误杀"),
        ("pg", "SELECT 1", "otherdb", "deny", "PG 连接库不在白名单 -> deny"),
        ("pgsch", "SELECT * FROM public.x", "appuser", "allow",
         "allowed_schemas 含 public -> 放行"),
        ("pgsch", "SELECT * FROM secret.x", "appuser", "deny",
         "allowed_schemas 外 -> deny"),
    ]
    for alias, sql, ddb, want, label in pg_cases:
        r = P.gate_db(alias, sql, "postgres", ddb)
        check("%-38s -> %s" % (label, want), r["decision"] == want, r)
    # PG DDL：schema 前缀不影响等级/审批（Moviepilot 白名单内 -> ask）
    r = P.gate_db("pg", "CREATE TABLE public.zz1 (i INT)", "postgres", "appuser")
    check("PG CREATE TABLE public.zz1 -> ask（不是 deny）", r["decision"] == "ask", r)
    r = P.gate_db("pg", "CREATE TABLE appuser.zz1 (i INT)", "postgres", "appuser")
    check("PG CREATE TABLE 连接库.schema -> ask", r["decision"] == "ask", r)
    # PG dblink（跨库通道）按高风险
    check("PG dblink(...) 等级 = ddl（跨库高风险）",
          P.sql_required_level("SELECT * FROM dblink('x','select 1') AS t(a int)",
                               "postgres") == "ddl")
    r = P.gate_db("pgread", "SELECT * FROM dblink('x','select 1') AS t(a int)",
                  "postgres", "appuser")
    _set_db_policy({"pgread": {"max_level": "read"}})
    r = P.gate_db("pgread", "SELECT * FROM dblink('x','select 1') AS t(a int)",
                  "postgres", "appuser")
    check("PG read 别名上 dblink -> deny", r["decision"] == "deny", r)
    # ---- CRITICAL-1：FROM 子句里每一个表引用都要检查（逗号/JOIN/子查询/UNION）----
    print("  -- 多表 FROM 白名单（防数据泄漏）--")
    _set_db_policy({"multi": {"max_level": "ddl", "allowed_databases": ["testdb"]}})
    multi_cases = [
        ("SELECT * FROM testdb.t1, testdb2.secret", "deny", "逗号连接（越界在后）"),
        ("SELECT * FROM testdb2.secret, testdb.t1", "deny", "逗号连接（越界在前）"),
        ("SELECT * FROM testdb.t1 CROSS JOIN testdb2.secret", "deny", "CROSS JOIN"),
        ("SELECT * FROM testdb.t1 JOIN testdb2.secret ON 1=1", "deny", "JOIN"),
        ("SELECT * FROM testdb.t1 LEFT JOIN testdb2.secret ON 1=1", "deny", "LEFT JOIN"),
        ("SELECT * FROM (SELECT * FROM testdb2.secret) x", "deny", "子查询"),
        ("SELECT * FROM (SELECT * FROM testdb2.s) a, (SELECT * FROM testdb.t) b",
         "deny", "两个子查询（一个越界）"),
        ("SELECT * FROM testdb.t1 UNION SELECT * FROM testdb2.secret", "deny", "UNION"),
        ("SELECT * FROM testdb.t1, testdb.t2", "allow", "两个都在白名单"),
        ("SELECT * FROM testdb.t1 a, testdb.t2 b WHERE a.id=b.id", "allow", "带别名"),
        ("SELECT * FROM testdb.t1 JOIN testdb.t2 ON testdb.t1.id=testdb.t2.id",
         "allow", "JOIN 都在白名单"),
        ("SELECT * FROM generate_series(1,3) g", "allow", "函数调用不算表"),
    ]
    for sql, want, label in multi_cases:
        r = P.gate_db("multi", sql, "mysql", "testdb")
        check("%-28s -> %s" % (label, want), r["decision"] == want,
              "%s => %s" % (sql, r))
    # ---- C1：FROM 里混元数据表不能让整条语句短路（verifier 实测泄漏）----
    print("  -- 元数据 + 其它表 混用（C1）--")
    _set_db_policy({"meta": {"max_level": "read", "allowed_databases": ["testdb"]}})
    c1_cases = [
        ("SELECT * FROM information_schema.tables, testdb2.secret LIMIT 1",
         "deny", "元数据在前 + 白名单外"),
        ("SELECT * FROM testdb2.secret, information_schema.tables LIMIT 1",
         "deny", "白名单外在前 + 元数据"),
        ("SELECT * FROM information_schema.tables, testdb.t LIMIT 1",
         "allow", "元数据 + 白名单内"),
        ("SELECT * FROM information_schema.tables", "allow", "单表元数据"),
        ("SELECT * FROM testdb.t1, testdb.t2", "allow", "白名单内两表"),
        ("SELECT * FROM (SELECT 1) x, testdb2.secret", "deny", "子查询 + 白名单外"),
        ("SELECT * FROM mysql.user, information_schema.tables", "deny",
         "mysql 系统库永远拒绝"),
    ]
    for sql, want, label in c1_cases:
        r = P.gate_db("meta", sql, "mysql", "testdb")
        check("%-28s -> %s" % (label, want), r["decision"] == want,
              "%s => %s" % (sql, r))
    # allow_metadata=false 时元数据仍被拒（不受本次改动影响）
    _set_db_policy({"nometa": {"max_level": "read", "allow_metadata": False}})
    r = P.gate_db("nometa", "SELECT * FROM information_schema.tables, testdb.t",
                  "mysql", "testdb")
    check("allow_metadata=false + 混表 -> deny", r["decision"] == "deny", r)

    # ---- PG 易用性 warning：配了 allowed_databases 但没配 allowed_schemas ----
    _set_db_policy({"pgw": {"max_level": "read", "allowed_databases": ["appuser"]}})
    r = P.gate_db("pgw", "SELECT * FROM public.x", "postgres", "appuser")
    check("PG 只配 allowed_databases -> 带 schema 提示 warning",
          r["decision"] == "allow" and any("allowed_schemas" in w
                                           for w in (r.get("warnings") or [])), r)
    _set_db_policy({"pgw2": {"max_level": "read", "allowed_databases": ["appuser"],
                             "allowed_schemas": ["public"]}})
    r = P.gate_db("pgw2", "SELECT * FROM public.x", "postgres", "appuser")
    check("PG 配了 allowed_schemas -> 无该 warning", not (r.get("warnings") or []), r)
    check("PG 无 allowed_databases -> 无该 warning",
          "PG 的 schema" not in "".join(P.policy_warnings("postgres", {
              "allowed_databases": None, "allowed_schemas": None})))
    check("MySQL 不产生 PG schema 提示",
          P.policy_warnings("mysql", {"allowed_databases": ["x"],
                                      "allowed_schemas": None}) == [])

    # PG：逗号连接里的 schema 也要被 allowed_schemas 收口
    _set_db_policy({"pgm": {"max_level": "read", "allowed_schemas": ["public"]}})
    check("PG 逗号连接：schema 在 allowed_schemas 内 -> allow",
          P.gate_db("pgm", "SELECT * FROM public.a, public.b", "postgres",
                    "appuser")["decision"] == "allow")
    r = P.gate_db("pgm", "SELECT * FROM public.a, secretschema.b", "postgres",
                  "appuser")
    check("PG 逗号连接：越界 schema -> deny", r["decision"] == "deny", r)
    r = P.gate_db("pgm", "SELECT * FROM (SELECT * FROM secret.b) x", "postgres",
                  "appuser")
    check("PG 子查询越界 schema -> deny", r["decision"] == "deny", r)

    # 方括号标识符（MySQL 语法上非法，但规范化层面别漏）
    check("方括号标识符被规范化识别",
          P.sql_targets("SELECT * FROM [otherdb].x", "mysql", "appdb")["databases"]
          == ["appdb", "otherdb"])


# ---------------------------------------------------------------------------
# 8. fail-closed 边界（§8.1.1）
# ---------------------------------------------------------------------------
def test_fail_closed():
    print("\n== 8. fail-closed 边界 ==")
    clean("ssh")
    P.write_policy("ssh", {"version": 1, "defaults": {"sudo": "ask"}})
    with open(P.tool_paths("ssh")["policy"], "w", encoding="utf-8") as f:
        f.write("{ 这不是 JSON")
    r = P.gate_ssh("x", "sudo ls")
    check("损坏策略 -> STATE_CORRUPT deny",
          r["decision"] == "deny" and r["code"] == "STATE_CORRUPT", r)
    clean("db")
    P.write_policy("db", {"version": 1, "databases": {"a": {"max_level": "ddl",
                                                            "approval": {"ddl": True}}}})
    path = P.tool_paths("db")["policy"]
    with open(path, "w", encoding="utf-8") as f:
        f.write("not json at all")
    r = P.gate_db("a", "SELECT 1", "mysql", "db1")
    check("db 损坏策略 -> STATE_CORRUPT", r["code"] == "STATE_CORRUPT", r)
    # 审批目录「已存在但不可写」→ deny，且**不得把权限改回 0700**（MED-2）
    clean("db")
    P.write_policy("db", {"version": 1,
                          "databases": {"a": {"max_level": "ddl",
                                              "approval": {"ddl": True}}}})
    adir2 = P.tool_paths("db")["approvals"]
    _ensure = getattr(P, "_ensure_dir", None)
    import stat as _stat
    os.makedirs(adir2, exist_ok=True)
    os.chmod(adir2, 0o500)
    try:
        r = P.gate_db("a", "DROP TABLE t", "mysql", "db1")
        check("已存在目录不可写 -> deny STATE_CORRUPT",
              r["decision"] == "deny" and r["code"] == "STATE_CORRUPT", r)
        mode = _stat.S_IMODE(os.stat(adir2).st_mode)
        check("审批目录权限未被静默改回（保持 0500）", mode == 0o500, oct(mode))
        left = [x for x in os.listdir(adir2) if x.endswith(".json")]
        check("未创建审批单", left == [], left)
    finally:
        os.chmod(adir2, 0o700)

    # 父目录不可写（目录不存在）→ deny（不是崩溃/放行）
    clean("db")
    P.write_policy("db", {"version": 1,
                          "databases": {"a": {"max_level": "ddl",
                                              "approval": {"ddl": True}}}})
    adir = P.tool_paths("db")["approvals"]
    shutil.rmtree(adir, ignore_errors=True)      # 让 approvals 无法被创建
    db_home = os.path.dirname(adir)
    os.chmod(db_home, 0o500)
    try:
        r = P.gate_db("a", "DROP TABLE t", "mysql", "db1")
        check("审批目录不可写 -> deny STATE_CORRUPT",
              r["decision"] == "deny" and r["code"] == "STATE_CORRUPT", r)
    finally:
        os.chmod(db_home, 0o700)


# ---------------------------------------------------------------------------
# 9. 审计
# ---------------------------------------------------------------------------
def test_audit():
    print("\n== 9. 审计 ==")
    clean()
    if os.path.exists(P.AUDIT_LOG):
        os.remove(P.AUDIT_LOG)
    P.write_policy("db", {"version": 1, "databases": {"a": {"max_level": "ddl"}}})
    P.write_policy("ssh", {"version": 1, "defaults": {"sudo": "ask"}})
    P.write_policy("db", {"version": 1, "databases": {"a": {"max_level": "read"}}})
    P.gate_db("a", "DROP TABLE t", "mysql", "db1")      # 超等级 -> deny
    P.write_policy("db", {"version": 1, "databases": {"a": {"max_level": "ddl"}}})
    P.gate_db("a", "ALTER USER app IDENTIFIED BY 'super-secret-pw'", "mysql", "db1")
    P.gate_ssh("s", "ssh host 'password=hunter2'")
    P.gate_db("a", "SELECT 1", "mysql", "db1")
    audit_text = open(P.AUDIT_LOG, encoding="utf-8").read() if os.path.exists(P.AUDIT_LOG) else ""
    check("审计文件存在且非空", len(audit_text.strip()) > 0)
    check("审计无明文密码（IDENTIFIED BY）", "super-secret-pw" not in audit_text)
    check("审计无明文密码（password=）", "hunter2" not in audit_text)
    lines = [json.loads(x) for x in audit_text.strip().splitlines() if x.strip()]
    check("审计字段齐全",
          all(all(k in r for k in ("ts", "tool", "actor", "alias", "action",
                                   "decision", "request_id", "target", "source", "note"))
              for r in lines))
    check("决策含 allow", any(r["decision"] == "allow" for r in lines))
    check("决策含 deny", any(r["decision"] == "deny" for r in lines))
    check("actor 合法", all(r["actor"] in ("ai", "web") for r in lines))
    # read_audit 尾部读取 + tool 过滤
    tail = P.read_audit(limit=2)
    check("read_audit limit", len(tail) == 2, len(tail))
    check("read_audit 新的在前",
          tail[0]["ts"] >= tail[1]["ts"] if len(tail) > 1 else True)
    only_db = P.read_audit("db", 100)
    check("read_audit tool 过滤", all(r["tool"] == "db" for r in only_db))
    check("read_audit 大文件尾部倒读可用", len(P.read_audit(limit=1)) == 1)


# ---------------------------------------------------------------------------
# 10. 审批列表 / 策略摘要（控制台接口）
# ---------------------------------------------------------------------------
def test_console_helpers():
    print("\n== 10. 控制台辅助接口 ==")
    clean()
    P.write_policy("ssh", {"version": 1, "defaults": {"sudo": "ask"}})
    P.write_policy("db", {"version": 1, "databases": {"a": {"max_level": "ddl",
                                                           "approval": {"ddl": True}}}})
    P.gate_ssh("s", "sudo ls")
    P.gate_db("a", "DROP TABLE t", "mysql", "db1")
    allap = P.list_approvals()
    check("list_approvals 跨工具", len([a for a in allap if a["tool"] == "ssh"]) == 1
          and len([a for a in allap if a["tool"] == "db"]) == 1, len(allap))
    check("list_approvals status 过滤",
          all(a["status"] == "pending" for a in P.list_approvals(status="pending")))
    check("list_approvals tool 过滤",
          all(a["tool"] == "ssh" for a in P.list_approvals("ssh")))
    summ = P.policy_summary("db")
    check("policy_summary 结构", summ["exists"] and summ["policy"]["databases"]["a"], summ)
    eff = P.effective_db_policy(summ["policy"], "a")
    check("effective_db_policy 合并", eff["max_level"] == "ddl" and eff["approval"]["ddl"], eff)
    eff_ssh = P.effective_ssh_policy(P.read_policy("ssh")["data"], "zzz")
    check("effective_ssh_policy 缺省 ask", eff_ssh["sudo"] == "ask" and
          eff_ssh["approval_ttl_s"] == 600, eff_ssh)
    # 签名冻结（防止以后误改）
    import inspect
    check("approve 签名兼容扩展",
          str(inspect.signature(P.approve)) ==
          "(tool, approval_id, consumes=1, ttl_s=600, note=None, decided_by='web', expected_fingerprint=None, expected_policy_revision=None)",
          inspect.signature(P.approve))
    check("reject 签名兼容扩展",
          str(inspect.signature(P.reject)) ==
          "(tool, approval_id, note=None, decided_by='web', expected_fingerprint=None, expected_policy_revision=None)", inspect.signature(P.reject))
    check("list_approvals 签名", str(inspect.signature(P.list_approvals)).startswith("(tool=None"))
    check("read_audit 签名", str(inspect.signature(P.read_audit)).startswith("(tool=None"))
    check("gate_ssh 签名", str(inspect.signature(P.gate_ssh)) ==
          "(alias, command, requester='ai', context=None)", inspect.signature(P.gate_ssh))
    check("gate_db 签名", str(inspect.signature(P.gate_db)) ==
          "(alias, sql, engine, default_db, requested_write=False, "
          "requested_unsafe=False, requester='ai', context=None)", inspect.signature(P.gate_db))


def main():
    tests = [test_no_policy, test_ssh_sudo, test_approvals, test_concurrent_consume,
             test_db_levels, test_db_approval, test_whitelist, test_fail_closed,
             test_audit, test_console_helpers]
    try:
        for fn in tests:
            fn()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print("\n===== bindkit_policy 单测：PASS %d  FAIL %d =====" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  FAILED: " + f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
