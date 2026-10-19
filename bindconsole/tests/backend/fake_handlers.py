#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试用 fake handlers / fake policy / 审批文件工具。

后端测试**不依赖真实 sshbind/dbbind**：内核只做 HTTP/认证/CSRF/路由，
工具状态在这里用内存假实现注入，从而能独立验证内核行为。
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # bindconsole/
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bindkit_console import ConsoleError  # noqa: E402


# ---------------------------------------------------------------------------
# fake 工具状态与 handlers
# ---------------------------------------------------------------------------

class FakeState:
    """内核测试用的工具侧状态（只存在于内存，绝不回显凭证）。"""

    def __init__(self, tool):
        self.tool = tool
        self.items = {}                 # name/alias -> item dict（含内部 _password 标记）
        self.credentials = {}           # name/alias -> {"password": ..., "private_key": ...}
        self.calls = []                 # [(verb, *args)]，参数已脱敏
        self.policy = {"version": 1, "defaults": {}, self.resource_key: {}}
        self.fail_next = None           # 控制下一次 create 抛哪类异常

    @property
    def resource_key(self):
        return "servers" if self.tool == "ssh" else "databases"


SSH_DEFAULTS = {
    "user": "root", "host": "127.0.0.1", "port": 22, "source": "imported",
    "installed": True, "usable": True, "usable_reason": None,
    "sudo": "ask", "approval_ttl_s": 600, "note": None, "last_test": None,
}
DB_DEFAULTS = {
    "name": None, "engine": "sqlite", "host": None, "port": None, "user": None,
    "database": None, "file": "/tmp/fake.sqlite", "origin": "local",
    "usable": True, "usable_reason": None, "max_level": "read",
    "allowed_databases": None, "allowed_tables": None,
    "allowed_schemas": None, "allow_metadata": True,
    "approval": {"write": False, "ddl": True}, "approval_ttl_s": 600,
    "note": None, "last_test": None,
}

_SSH_EDITABLE = ("user", "host", "port", "sudo", "approval_ttl_s", "note")
_DB_EDITABLE = ("engine", "host", "port", "user", "database", "file",
                "max_level", "allowed_databases", "allowed_tables",
                "allowed_schemas", "allow_metadata", "approval",
                "approval_ttl_s", "note")


def _sanitize(item, tool):
    out = dict(item)
    out["has_password"] = bool(out.pop("_password", False))
    out["has_key"] = bool(out.pop("_private_key", False))
    out.pop("password", None)
    out.pop("private_key", None)
    return out


def make_fake_handlers(tool="ssh"):
    """返回 (handlers, state)，形状与 CONTRACT §7.1.1 完全一致。

    行为：内存 CRUD；list 返回 {"items": [...]}；凭证只进 state.credentials，
    返回体只给 has_password/has_key（验证内核/API 不回显凭证）。
    """
    state = FakeState(tool)
    name_key = "name" if tool == "ssh" else "alias"
    resource = "servers" if tool == "ssh" else "databases"
    singular = "server" if tool == "ssh" else "database"

    def rec(verb, *args):
        state.calls.append((verb,) + tuple(args))

    def list_fn():
        rec("list")
        return {"items": [_sanitize(state.items[name], tool)
                          for name in sorted(state.items)]}

    def get_fn(name):
        rec("get", name)
        if name not in state.items:
            raise ConsoleError("NOT_FOUND", "%s 不存在：%s" % (singular, name), status=404)
        return _sanitize(state.items[name], tool)

    def _maybe_fail():
        mode = state.fail_next
        if not mode:
            return
        state.fail_next = None
        if mode == "console_error":
            raise ConsoleError("FAKE_CONFLICT", "业务错误（fake）",
                               hint="fake hint", status=409)
        if mode == "value_error":
            raise ValueError("人话错误（fake）")
        if mode == "runtime_error":
            raise RuntimeError("内部细节 password=hunter2-should-never-leak")
        if mode == "internal_with_hint":
            raise ConsoleError("INTERNAL", "服务内部错误（fake）", status=500)
        if mode == "ok_false":
            return {"ok": False,
                    "error": {"code": "FAKE_DENIED", "message": "handler 返回错误体（fake）",
                              "hint": "fake ok:false", "status": 422}}

    def create_fn(body):
        rec("create", {k: v for k, v in body.items()
                       if k not in ("password", "private_key")})
        failed = _maybe_fail()
        if failed is not None:                  # handler 直接返回 {"ok":false,...} 的约定
            return failed
        name = body.get(name_key)
        if not name:
            raise ConsoleError("MISSING_FIELD", "缺少 %s" % name_key)
        if name in state.items:
            raise ConsoleError("ALREADY_EXISTS", "%s 已存在：%s" % (singular, name),
                               status=409)
        item = {name_key: name}
        if tool == "ssh":
            item.update(SSH_DEFAULTS)
        else:
            item.update(DB_DEFAULTS)
        item[name_key] = name
        for key in (("user", "host", "port", "sudo", "note") if tool == "ssh"
                    else _DB_EDITABLE):
            if key in body:
                item[key] = body[key]
        creds = {}
        if body.get("password"):
            creds["password"] = body["password"]
            item["_password"] = True
        if body.get("private_key"):
            creds["private_key"] = body["private_key"]
            item["_private_key"] = True
        state.credentials[name] = creds
        state.items[name] = item
        # 绝不把凭证回显给调用方
        return _sanitize(item, tool)

    def update_fn(name, body):
        rec("update", name, {k: v for k, v in body.items()
                             if k not in ("password", "private_key")})
        if name not in state.items:
            raise ConsoleError("NOT_FOUND", "%s 不存在：%s" % (singular, name), status=404)
        item = state.items[name]
        editable = _SSH_EDITABLE if tool == "ssh" else _DB_EDITABLE
        for key, value in body.items():
            if key in editable:
                item[key] = value
        if body.get("password"):                     # 密码留空=不改
            state.credentials.setdefault(name, {})["password"] = body["password"]
            item["_password"] = True
        return _sanitize(item, tool)

    def delete_fn(name, body=None):
        body = body or {}
        rec("delete", name, dict(body))
        if name not in state.items:
            raise ConsoleError("NOT_FOUND", "%s 不存在：%s" % (singular, name), status=404)
        state.items.pop(name)
        delete_key = body.get("delete_key") in (True, "true", "1", 1)
        if delete_key:
            state.credentials.pop(name, None)
        return {"deleted": True, name_key: name, "key_removed": bool(delete_key)}

    def test_fn(name):
        rec("test", name)
        if name not in state.items:
            raise ConsoleError("NOT_FOUND", "%s 不存在：%s" % (singular, name), status=404)
        return {"ok": True, "message": "连接成功（fake）", "duration_ms": 3}

    def policy_get():
        rec("policy_get")
        return json.loads(json.dumps(state.policy, ensure_ascii=False))

    def policy_put(body):
        rec("policy_put", json.loads(json.dumps(body, ensure_ascii=False)))
        if not isinstance(body, dict):
            raise ConsoleError("INVALID_BODY", "策略必须是 JSON 对象")
        state.policy.update(body)
        return json.loads(json.dumps(state.policy, ensure_ascii=False))

    handlers = {
        "resource": resource,
        "list": list_fn,
        "get": get_fn,
        "create": create_fn,
        "update": update_fn,
        "delete": delete_fn,
        "test": test_fn,
        "policy_get": policy_get,
        "policy_put": policy_put,
    }
    return handlers, state


# ---------------------------------------------------------------------------
# fake policy 模块（验证生产分支：内核必须调用 bindkit_policy 接口）
# ---------------------------------------------------------------------------

class FakePolicy:
    """实现内核生产路径所需的 bindkit_policy 子集（内存版，仅测试用）。"""

    def __init__(self):
        self.approvals = []
        self.audit_records = []
        self.calls = []

    def add_pending(self, tool="ssh", approval_id="apr_test_0001", alias="demo-server",
                    action="sudo", target="sudo systemctl restart nginx"):
        ap = {
            "id": approval_id, "tool": tool, "alias": alias, "action": action,
            "target": target, "fingerprint": "sha256:fake",
            "requester": "ai",
            "created_at": "2026-10-19T09:30:00+08:00",
            "expires_at": "2099-10-19T09:40:00+08:00",
            "status": "pending", "decided_at": None, "decided_by": None,
            "consumes_left": 1, "note": None,
        }
        self.approvals.append(ap)
        return ap

    def list_approvals(self, tool=None, status=None, alias=None):
        self.calls.append(("list_approvals", tool, status))
        items = [dict(a) for a in self.approvals
                 if (tool is None or a["tool"] == tool)
                 and (status is None or a["status"] == status)
                 and (alias is None or a["alias"] == alias)]
        return items

    def get_approval(self, tool, approval_id):
        self.calls.append(("get_approval", tool, approval_id))
        for ap in self.approvals:
            if ap["id"] == approval_id and ap["tool"] == tool:
                return dict(ap)
        return None

    def approve(self, tool, approval_id, consumes=1, ttl_s=600, note=None,
                decided_by="web"):
        self.calls.append(("approve", tool, approval_id, consumes, ttl_s, note))
        ap = None
        for item in self.approvals:
            if item["id"] == approval_id and item["tool"] == tool:
                ap = item
                break
        if ap is None:
            raise ValueError("审批单不存在：%s" % approval_id)
        if ap["status"] != "pending":
            raise ValueError("审批单状态不是 pending（当前 %s），不能批准" % ap["status"])
        ap["status"] = "approved"
        ap["consumes_left"] = int(consumes)
        ap["decided_by"] = decided_by
        ap["decided_at"] = "2026-10-19T10:00:00+08:00"
        ap["ttl_s"] = int(ttl_s)
        if note:
            ap["note"] = note
        self.audit(tool, "web", ap["alias"], ap["action"], "approve",
                   request_id=approval_id, target=ap["target"])
        return dict(ap)

    def reject(self, tool, approval_id, note=None, decided_by="web"):
        self.calls.append(("reject", tool, approval_id, note))
        ap = None
        for item in self.approvals:
            if item["id"] == approval_id and item["tool"] == tool:
                ap = item
                break
        if ap is None:
            raise ValueError("审批单不存在：%s" % approval_id)
        if ap["status"] != "pending":
            raise ValueError("审批单状态不是 pending（当前 %s），不能拒绝" % ap["status"])
        ap["status"] = "denied"
        ap["decided_by"] = decided_by
        ap["decided_at"] = "2026-10-19T10:00:00+08:00"
        ap["note"] = note
        self.audit(tool, "web", ap["alias"], ap["action"], "reject",
                   request_id=approval_id, target=ap["target"], note=note)
        return dict(ap)

    def audit(self, tool, actor, alias, action, decision, request_id=None,
              target=None, source="127.0.0.1", note=None):
        record = {
            "ts": "2026-10-19T10:00:00+08:00", "tool": tool, "actor": actor,
            "alias": alias, "action": action, "decision": decision,
            "request_id": request_id, "target": target, "source": source,
            "note": note,
        }
        self.audit_records.append(record)
        return record

    def read_audit(self, tool=None, limit=200):
        self.calls.append(("read_audit", tool, limit))
        items = [dict(r) for r in self.audit_records
                 if tool is None or r["tool"] == tool]
        items.reverse()
        return items[:limit]


def make_fake_policy():
    return FakePolicy()


# ---------------------------------------------------------------------------
# 审批单文件工具（policy=False 测试降级路径用）
# ---------------------------------------------------------------------------

def tool_home(home, tool):
    if tool == "ssh":
        return os.path.join(home, ".ssh", "sshbind")
    return os.path.join(home, ".dbbind")


def approvals_dir(home, tool):
    return os.path.join(tool_home(home, tool), "approvals")


def write_approval(home, tool, approval):
    directory = approvals_dir(home, tool)
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "%s.json" % approval["id"])
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(approval, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.chmod(path, 0o600)
    return path


def read_approval(home, tool, approval_id):
    path = os.path.join(approvals_dir(home, tool), "%s.json" % approval_id)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def make_approval(approval_id="apr_20261019_ab12cd", tool="ssh", alias="demo-server",
                  action="sudo", target="sudo systemctl restart nginx",
                  status="pending", created_offset=-60, expires_offset=540,
                  consumes_left=1, note=None):
    import datetime
    now = datetime.datetime.now().astimezone()
    created = (now + datetime.timedelta(seconds=created_offset)).isoformat(timespec="seconds")
    expires = (now + datetime.timedelta(seconds=expires_offset)).isoformat(timespec="seconds")
    return {
        "id": approval_id, "tool": tool, "alias": alias, "action": action,
        "target": target, "fingerprint": "sha256:demo", "requester": "ai",
        "created_at": created, "expires_at": expires, "status": status,
        "decided_at": None, "decided_by": None,
        "consumes_left": consumes_left, "note": note,
    }
