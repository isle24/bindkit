#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台 handlers 测试（不依赖 backend 的 HTTP 内核）。

把 dbbind / sshbind 当模块加载（隔离 HOME），直接调用它们的
`build_console_handlers()` 里的回调，验证：
  * 增/删/改/查/测试/策略读写 的语义
  * 「编辑留空=不改」、密码只在传入时更新
  * 绝不返回 password / 私钥
  * 路径/名称白名单、配置源别名不可删
  * 策略字段（max_level / 白名单 / 审批开关 / sudo / note）落到 policy.json

用法：python3 tests/policy/test_handlers.py
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.abspath(os.path.join(HERE, "..", ".."))
WORKSPACE = os.path.abspath(os.path.join(PROJECT, ".."))
DBBIND = os.path.join(WORKSPACE, "dbbind", "dbbind")
SSHBIND = os.path.join(WORKSPACE, "sshbind", "sshbind")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  PASS  %s" % name)
    else:
        FAIL.append("%s  %s" % (name, detail))
        print("  FAIL  %s   %s" % (name, detail))


def load_module(path, name):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def expect_error(fn, *args, **kw):
    try:
        fn(*args, **kw)
        return None
    except Exception as e:                     # noqa: BLE001
        return e


def main():
    home = tempfile.mkdtemp(prefix="bindkit-handlers-")
    os.environ["HOME"] = home
    os.environ.pop("BINDCONSOLE_HOME", None)
    try:
        # 环境：sqlite 库 + 配置文件别名 + 内核模块 + 空 servers.json
        dbpath = os.path.join(home, "app.db")
        con = sqlite3.connect(dbpath)
        con.execute("create table users(id int, name text)")
        con.execute("insert into users values (1,'a')")
        con.commit()
        con.close()
        os.makedirs(os.path.join(home, ".dbbind"), exist_ok=True)
        with open(os.path.join(home, ".dbbind", "config.json"), "w") as f:
            json.dump({"version": 1, "databases": {
                "cfg-ro": {"engine": "sqlite", "file": dbpath}}}, f)
        os.makedirs(os.path.join(home, ".ssh", "sshbind", "keys"), exist_ok=True)
        with open(os.path.join(home, ".ssh", "sshbind", "servers.json"), "w") as f:
            json.dump({"version": 1, "servers": {
                "fake": {"name": "fake", "host": "127.0.0.1", "user": "root",
                         "port": 22, "key": os.path.join(home, ".ssh", "sshbind",
                                                          "keys", "fake"),
                         "fingerprint": "SHA256:x", "key_type": "ed25519",
                         "restrict": False, "certificate": None,
                         "source": "generated", "installed": False,
                         "created_at": "2026-10-19T00:00:00"}}}, f)
        # 假密钥文件（删除测试用，绝不指向真实密钥）
        open(os.path.join(home, ".ssh", "sshbind", "keys", "fake"), "w").write("x")
        lib = os.path.join(home, ".bindconsole", "lib")
        os.makedirs(lib, exist_ok=True)
        shutil.copy(os.path.join(PROJECT, "bindkit_policy.py"), lib)

        print("== A. dbbind handlers ==")
        db = load_module(DBBIND, "dbbind_mod")
        H = db.build_console_handlers()
        check("handlers 键齐全",
              all(k in H for k in ("resource", "list", "get", "create", "update",
                                   "delete", "test", "policy_get", "policy_put")))
        check("resource=databases", H["resource"] == "databases")
        items = H["list"]()["items"]
        check("list 含配置别名", [i["alias"] for i in items] == ["cfg-ro"], items)
        check("list 不返回密码（无 password 键、无明文值）",
              all("password" not in i and "pw-secret" not in json.dumps(i)
                  for i in items))
        check("list 含策略字段",
              all(k in items[0] for k in ("max_level", "allowed_databases",
                                          "allowed_tables", "allow_metadata",
                                          "approval", "usable")))

        # create（sqlite）
        r = H["create"]({"alias": "new-sqlite", "engine": "sqlite", "file": dbpath})
        check("create sqlite", r.get("ok") and r.get("alias") == "new-sqlite", r)
        check("create 后 list 两条", len(H["list"]()["items"]) == 2)
        rights = os.stat(os.path.join(home, ".dbbind", "databases.json")).st_mode & 0o777
        check("databases.json 0600", rights == 0o600, oct(rights))
        check("重复 create -> 报错", expect_error(H["create"],
              {"alias": "new-sqlite", "engine": "sqlite", "file": dbpath}) is not None)
        check("非法别名 -> 报错", expect_error(H["create"],
              {"alias": "../evil", "engine": "sqlite", "file": dbpath}) is not None)
        check("sqlite 缺 file -> 报错", expect_error(H["create"],
              {"alias": "x1", "engine": "sqlite"}) is not None)

        # create（mysql，不连库，只写状态）+ 密码规则
        r = H["create"]({"alias": "m1", "engine": "mysql", "host": "127.0.0.1",
                         "port": 13306, "user": "root", "password": "pw-secret-1",
                         "database": "testdb"})
        check("create mysql", r.get("ok"), r)
        item = H["get"]("m1")
        check("get 不返回密码", "password" not in item
              and "pw-secret" not in json.dumps(item), item)
        state = db.load_state()
        check("密码已写入状态", state["databases"]["m1"]["password"] == "pw-secret-1")
        # update：留空不改连接参数、空密码不改
        H["update"]("m1", {"host": "", "database": "otherdb", "password": ""})
        state = db.load_state()
        check("update 留空不改 host", state["databases"]["m1"]["host"] == "127.0.0.1")
        check("update 改 database", state["databases"]["m1"]["database"] == "otherdb")
        check("空密码不覆盖旧密码",
              state["databases"]["m1"]["password"] == "pw-secret-1")
        H["update"]("m1", {"password": "pw-secret-2"})
        check("新密码生效", db.load_state()["databases"]["m1"]["password"] == "pw-secret-2")
        # update 策略字段
        H["update"]("m1", {"max_level": "ddl",
                           "allowed_databases": ["a", "b"],
                           "allowed_tables": ["t1"],
                           "allow_metadata": False,
                           "approval": {"write": True, "ddl": True}})
        pol = json.load(open(os.path.join(home, ".dbbind", "policy.json")))
        entry = pol["databases"]["m1"]
        check("update 写 policy（max_level/白名单/审批）",
              entry["max_level"] == "ddl" and entry["allowed_databases"] == ["a", "b"]
              and entry["allowed_tables"] == ["t1"]
              and entry["allow_metadata"] is False
              and entry["approval"] == {"write": True, "ddl": True}, entry)
        check("policy 文件 0600",
              os.stat(os.path.join(home, ".dbbind", "policy.json")).st_mode & 0o777 == 0o600)
        # 配置源别名：不能改连接参数，但可改策略
        check("配置别名改连接参数 -> 报错", expect_error(
            H["update"], "cfg-ro", {"host": "1.2.3.4"}) is not None)
        H["update"]("cfg-ro", {"max_level": "write"})
        check("配置别名可改策略",
              json.load(open(os.path.join(home, ".dbbind", "policy.json")))
              ["databases"]["cfg-ro"]["max_level"] == "write")
        # test（sqlite 真连）
        t = H["test"]("m1")
        check("test 不可用别名返回 ok:false", t.get("ok") is False and t.get("message"))
        t = H["test"]("cfg-ro")
        check("test 可用别名 ok:true", t.get("ok") is True, t)
        # policy get/put
        pg = H["policy_get"]()
        check("policy_get 结构", "policy" in pg and "path" in pg, pg.keys())
        r = H["policy_put"]({"defaults": {"max_level": "write",
                                          "approval": {"write": True, "ddl": False}}})
        check("policy_put 默认值写入", r.get("ok"), r)
        pol = json.load(open(os.path.join(home, ".dbbind", "policy.json")))
        check("policy_put 生效", pol["defaults"]["max_level"] == "write", pol)
        check("policy_put 非法 max_level -> 报错", expect_error(
            H["policy_put"], {"defaults": {"max_level": "superuser"}}) is not None)
        # delete
        check("delete sqlite", H["delete"]("new-sqlite").get("ok"))
        check("delete 后不存在", expect_error(H["get"], "new-sqlite") is not None)
        check("delete 配置别名 -> 报错", expect_error(H["delete"], "cfg-ro") is not None)

        print("\n== B. sshbind handlers ==")
        sh = load_module(SSHBIND, "sshbind_mod")
        S = sh.build_console_handlers()
        check("resource=servers", S["resource"] == "servers")
        items = S["list"]()["items"]
        check("ssh list 含服务器", [i["name"] for i in items] == ["fake"], items)
        check("ssh list 不返回私钥/密码",
              all("key" not in i and "password" not in i for i in items)
              and "PRIVATE KEY" not in json.dumps(items))
        check("ssh list 含 sudo/策略字段",
              all(k in items[0] for k in ("sudo", "usable", "installed", "has_key")))
        # update：sudo 策略 + 备注
        r = S["update"]("fake", {"sudo": "deny", "note": "生产机"})
        check("ssh update sudo/note", r.get("ok"), r)
        pol = json.load(open(os.path.join(home, ".ssh", "sshbind", "policy.json")))
        check("ssh policy 写入", pol["servers"]["fake"]["sudo"] == "deny"
              and pol["servers"]["fake"]["note"] == "生产机", pol)
        item = S["get"]("fake")
        check("get 反映 sudo 策略", item["sudo"] == "deny" and item["note"] == "生产机", item)
        check("sudo 非法值 -> 报错", expect_error(S["update"], "fake", {"sudo": "yes"}) is not None)
        check("update 不存在服务器 -> 报错", expect_error(S["update"], "nope",
              {"sudo": "ask"}) is not None)
        # policy get/put
        pg = S["policy_get"]()
        check("ssh policy_get", "policy" in pg and "path" in pg)
        r = S["policy_put"]({"defaults": {"sudo": "ask", "approval_ttl_s": 900}})
        check("ssh policy_put", r.get("ok"), r)
        pol = json.load(open(os.path.join(home, ".ssh", "sshbind", "policy.json")))
        check("ssh policy_put 生效", pol["defaults"]["sudo"] == "ask"
              and pol["defaults"]["approval_ttl_s"] == 900, pol)
        check("ssh policy_put 非法 sudo -> 报错", expect_error(
            S["policy_put"], {"defaults": {"sudo": "maybe"}}) is not None)
        # test：fake 没装（installed False）→ sshbind test 会尝试连接 127.0.0.1:22 失败
        t = S["test"]("fake")
        check("ssh test 失败返回 ok:false（不抛异常）", t.get("ok") is False, t)
        check("ssh test 不存在 -> 报错", expect_error(S["test"], "nope") is not None)
        # delete：只删本地（临时 HOME 里的假密钥）
        r = S["delete"]("fake", {})
        check("ssh delete 成功", r.get("ok"), r)
        check("ssh delete 后 list 空", S["list"]()["items"] == [])
        check("ssh delete 不存在 -> 报错", expect_error(S["delete"], "fake", {}) is not None)
        # create 参数校验（不触发网络）
        check("ssh create 缺 host -> 报错", expect_error(S["create"], {"name": "n1"}) is not None)
        check("ssh create 缺凭证 -> 报错", expect_error(
            S["create"], {"name": "n1", "host": "1.2.3.4"}) is not None)
        check("ssh create 非法名 -> 报错", expect_error(
            S["create"], {"name": "../x", "host": "1.2.3.4",
                          "auth": {"password": "x"}}) is not None)
    finally:
        shutil.rmtree(home, ignore_errors=True)

    print("\n===== handlers：PASS %d  FAIL %d =====" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  FAILED: " + f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
