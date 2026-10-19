#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内核 ↔ 真实 bindkit_policy 的集成 smoke test（生产路径 policy=None）。

用途：验证腾讯 Web 控制台内核在**不注入 fake policy** 时，会真的调用
`bindkit_policy` 的 list_approvals / approve / audit / read_audit 接口，
并落盘到契约 §5.2/§6 规定的审批单文件与 audit.log。

由 test_console.IntegrationTests 通过子进程调用（HOME 已隔离到临时目录），
也可手动运行：

    HOME=$(mktemp -d) python3 bindconsole/tests/backend/integration_real_policy.py

最后一行输出 JSON 结果，便于机器断言。
"""

import json
import os
import sys
import threading
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))           # bindconsole/
for _path in (ROOT, HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import bindkit_console as bc          # noqa: E402
import bindkit_policy as policy       # noqa: E402  （真实策略/审批/审计单一真源）
import fake_handlers                  # noqa: E402

from test_console import TestClient, stop_server      # noqa: E402  复用测试 HTTP 客户端


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def main():
    home = os.path.expanduser("~")
    tool = "ssh"
    password = "Integration-real-policy-1"

    # 0) 断言策略模块路径已随 HOME 隔离（本脚本须在隔离 HOME 子进程中运行）
    expected_runtime = os.path.join(home, ".bindconsole")
    assert policy.BINDCONSOLE_HOME == expected_runtime, (
        "bindkit_policy 未随 HOME 隔离：%r != %r"
        % (policy.BINDCONSOLE_HOME, expected_runtime))
    assert policy.SSH_HOME == os.path.join(home, ".ssh", "sshbind"), policy.SSH_HOME

    # 1) 真实策略文件 + 真实 pending 审批单（契约 §3.1 / §5.2 格式）
    _write(os.path.join(policy.SSH_HOME, "policy.json"),
           json.dumps({"version": 1, "defaults": {"sudo": "ask"}}, ensure_ascii=False))
    approval = fake_handlers.make_approval(approval_id="apr_integration_1",
                                           alias="demo-server")
    fake_handlers.write_approval(home, tool, approval)

    # 2) 静态根 + fake 工具 handlers（内核不碰工具状态；审批/审计走真实 policy）
    web_root = os.path.join(home, ".bindconsole", "web")
    os.makedirs(web_root, exist_ok=True)
    _write(os.path.join(web_root, "index.html"),
           '<script>window.__BINDCONSOLE_TOOL__ = "__BINDCONSOLE_TOOL__";</script>\n')
    handlers, state = fake_handlers.make_fake_handlers(tool)

    # 3) 生产路径：policy=None → 内核自动 import bindkit_policy
    server = bc.create_server(tool, port=0, handlers=handlers, home=home,
                              web_root=web_root, policy=None)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    port = server.server_address[1]
    client = TestClient(port)
    result = {"ok": False, "port": port}
    try:
        assert server.app.policy_module is policy, "内核未加载真实 bindkit_policy"
        result["policy_module"] = policy.__name__

        assert client.get("/api/status").json["data"]["setup_required"] is True
        assert client.post("/api/setup", {"password": password}).status == 201
        login = client.post("/api/login", {"password": password})
        assert login.status == 200, login.text
        client.csrf = login.data["csrf_token"]

        # 审批列表来自真实 policy.list_approvals
        approvals = client.get("/api/approvals").json["data"]["approvals"]
        assert [a["id"] for a in approvals] == ["apr_integration_1"], approvals
        result["pending"] = approvals[0]["id"]

        # 批准：真实 policy.approve 原子写审批单 + 写审计
        approve = client.post("/api/approvals/apr_integration_1/approve",
                              {"consumes": 2, "ttl_s": 300})
        assert approve.status == 200, approve.text
        approved = approve.json["data"]["approval"]
        assert approved["status"] == "approved", approved
        assert approved["consumes_left"] == 2, approved
        result["approval_status"] = approved["status"]
        result["consumes_left"] = approved["consumes_left"]

        # 直接读磁盘校验（唯一真源是 bindkit_policy 的文件）
        on_disk = policy.get_approval(tool, "apr_integration_1")
        assert on_disk["status"] == "approved", on_disk
        result["on_disk"] = on_disk["status"]

        # 工具 handler 调用 → 内核写审计（经 policy.audit）
        created = client.post("/api/servers", {
            "name": "demo-server", "user": "root", "host": "10.0.0.8",
            "password": "integration-secret-never-log", "sudo": "ask"})
        assert created.status == 201, created.text
        assert "integration-secret-never-log" not in created.text

        # 真实 audit.log：approve 记录 + servers.create 记录，且无凭证
        with open(os.path.join(expected_runtime, "audit.log"), "r",
                  encoding="utf-8") as fh:
            audit_text = fh.read()
        records = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
        assert any(r.get("decision") == "approve"
                   and r.get("request_id") == "apr_integration_1"
                   for r in records), records
        assert any(r.get("action") == "servers.create"
                   and r.get("decision") == "allow" for r in records), records
        assert "integration-secret-never-log" not in audit_text
        result["audit_records"] = len(records)

        # /api/audit 走真实 policy.read_audit
        audit_api = client.get("/api/audit?tool=all&limit=50")
        assert audit_api.status == 200, audit_api.text
        entries = audit_api.json["data"]["entries"]
        assert any(e.get("action") == "servers.create" for e in entries), entries
        result["audit_api_entries"] = len(entries)

        result["ok"] = True
    finally:
        stop_server(server, thread)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        traceback.print_exc()
        print(json.dumps({"ok": False, "error": "assertion: %s" % exc},
                         ensure_ascii=False))
        sys.exit(1)
