#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bindkit_policy — bindconsole 共享策略引擎（单一真源）

被三处使用：
  1. `sshbind exec` / `dbbind exec` 的策略闸门（gate_ssh / gate_db）
  2. Web 控制台内核（审批列表、批准/拒绝、审计、策略读写）
  3. 安装脚本自检

设计原则（CONTRACT §3/§4/§5/§6/§8.1）：
  * **绝不抛异常给调用方**：内部任何异常 → fail-closed（deny）+ 审计
  * 策略文件不存在 → allow（与改造前行为完全一致，向后兼容硬要求）
  * 策略文件损坏 → deny（fail-closed），不得静默放行
  * 审批单：原子写（临时文件 + os.replace）、0600、磁盘即真相
  * 审计：JSONL 追加到 ~/.bindconsole/audit.log，0600，**绝不写密码/私钥/完整连接串**
  * 纯标准库，Python 3.9+

文件布局（可用环境变量覆盖，便于隔离测试）：
  $BINDCONSOLE_HOME  默认 ~/.bindconsole     （audit.log 所在）
  ssh 策略：~/.ssh/sshbind/policy.json      审批：~/.ssh/sshbind/approvals/
  db  策略：~/.dbbind/policy.json           审批：~/.dbbind/approvals/
"""

import hashlib
import json
import os
import re
import tempfile
import time
from datetime import datetime, timedelta

VERSION = 1

# ---------------------------------------------------------------------------
# 路径（模块导入时求值：测试可用 HOME/BINDCONSOLE_HOME 隔离）
# ---------------------------------------------------------------------------

HOME = os.path.expanduser("~")
BINDCONSOLE_HOME = os.environ.get("BINDCONSOLE_HOME") or os.path.join(HOME, ".bindconsole")
SSH_HOME = os.path.join(HOME, ".ssh", "sshbind")
DB_HOME = os.path.join(HOME, ".dbbind")

TOOL_PATHS = {
    "ssh": {
        "policy": os.path.join(SSH_HOME, "policy.json"),
        "approvals": os.path.join(SSH_HOME, "approvals"),
        "label": "sshbind",
    },
    "db": {
        "policy": os.path.join(DB_HOME, "policy.json"),
        "approvals": os.path.join(DB_HOME, "approvals"),
        "label": "dbbind",
    },
}

AUDIT_LOG = os.path.join(BINDCONSOLE_HOME, "audit.log")

LEVELS = ("read", "write", "ddl")
LEVEL_RANK = {"read": 0, "write": 1, "ddl": 2}
SUDO_MODES = ("allow", "ask", "deny")
DEFAULT_SDO = "ask"
DEFAULT_TTL_S = 600
TTL_MIN_S, TTL_MAX_S = 60, 86400

# 元数据模式（CONTRACT §3.2 / 修补后）：
#   METADATA_READ_OK   —— allow_metadata=true 时允许**只读**的元数据库
#   METADATA_FORBIDDEN —— 永远不放行（mysql 库存口令哈希等凭据，不能因为
#                         allow_metadata 或白名单为 null 就交出去）
METADATA_READ_OK = {"information_schema", "performance_schema", "sys", "pg_catalog"}
METADATA_FORBIDDEN = {"mysql"}

TARGET_TRUNCATE = 500


# ---------------------------------------------------------------------------
# 小工具：时间 / 原子写 / 权限
# ---------------------------------------------------------------------------

def _now():
    return datetime.now().astimezone()


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _parse_iso(text):
    try:
        dt = datetime.fromisoformat(str(text))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:                      # 容忍无时区的历史值
        dt = dt.astimezone()
    return dt


def _ensure_dir(path, mode=0o700):
    """确保目录存在。

    **已存在的目录绝不 chmod** —— 管理员可能刻意为 approvals/ 设了更严的权限，
    静默改回 0700 等于撤销加固（CONTRACT §8.1.1 复审 MED-2）。只在本次真正
    创建目录时设置权限。
    """
    if os.path.isdir(path):
        return True
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
        os.chmod(path, mode)
        return True
    except OSError:
        return False


def _atomic_write_json(path, obj):
    """原子写 JSON：同目录临时文件 + fsync + os.replace + 0600。失败抛 OSError。"""
    directory = os.path.dirname(path) or "."
    _ensure_dir(directory, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path):
    """读 JSON（容忍注释/尾随逗号）。返回 (ok, obj)。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        return False, "read_error:%s" % e
    try:
        return True, _loads_tolerant(text)
    except ValueError as e:
        return False, "parse_error:%s" % e


# ---------------------------------------------------------------------------
# 容错 JSON（策略文件是手写的，允许 // 与 /* */ 注释、尾随逗号）
# ---------------------------------------------------------------------------

def _strip_jsonc(text):
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            i += 2
            while i < n and not text.startswith("*/", i):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    clean = "".join(out)
    # 尾随逗号
    return re.sub(r",(\s*[}\]])", r"\1", clean)


def _loads_tolerant(text):
    return json.loads(_strip_jsonc(text))


# ---------------------------------------------------------------------------
# 审计（CONTRACT §6）
# ---------------------------------------------------------------------------

# (正则, 保留前 N 个分组, 替换文案) —— 密码/私钥/口令一律抹掉
_REDACT_RULES = [
    # PostgreSQL PASSWORD '...'；同时处理 SQL 的双单引号转义。
    (re.compile(r"(?i)(\b(?:password|identified\s+by)\s+(?:E)?)(?:'(?:''|\\.|[^'])*'|\"(?:\"\"|[^\"])*\")"), 1),
    # 连接 URI 中的 user:password@（包括百分号编码后的口令）。
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+(?=@)"), 1),
    # 键值形式：password=xxx / "token": "xxx"
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|passphrase)"
                r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), 2),
    # SQL：IDENTIFIED BY '...'
    (re.compile(r"(?i)(identified\s+by\s+)(\"[^\"]*\"|'[^']*'|\S+)"), 1),
    # 命令行：--password xxx / --password=xxx
    (re.compile(r"(?i)(--password[=\s]+)(\S+)"), 1),
    # 私钥块
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
                r"(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), 0),
]


def redact(text):
    """把可能的口令/私钥抹掉。审计/日志只准用这个函数处理过的文本。"""
    if text is None:
        return None
    s = str(text)
    for pattern, keep in _REDACT_RULES:
        def _repl(m, _keep=keep):
            parts = [(m.group(i) if m.lastindex and i <= m.lastindex else "")
                     for i in range(1, _keep + 1)]
            return "".join(parts) + "***"
        s = pattern.sub(_repl, s)
    return s


def _truncate(text, limit=TARGET_TRUNCATE):
    s = "" if text is None else str(text)
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def audit(tool, actor, alias, action, decision, request_id=None, target=None,
          source="127.0.0.1", note=None):
    """追加一条 JSONL 审计。**绝不抛异常**（写失败只 stderr 警告）。"""
    try:
        _ensure_dir(BINDCONSOLE_HOME, 0o700)
        record = {
            "ts": _iso(_now()),
            "tool": tool,
            "actor": actor if actor in ("ai", "web") else "ai",
            "alias": alias,
            "action": action,
            "decision": decision,
            "request_id": request_id,
            "target": _truncate(redact(target)),
            "source": source,
            "note": _truncate(redact(note)) if note is not None else None,
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        created = not os.path.exists(AUDIT_LOG)
        # O_APPEND 保证多进程追加不互相截断
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        if created:                      # 已存在的文件不 chmod（尊重管理员加固）
            try:
                os.chmod(AUDIT_LOG, 0o600)
            except OSError:
                pass
        return record
    except Exception as e:                     # noqa: BLE001 —— 审计绝不能影响主流程
        try:
            import sys
            sys.stderr.write("bindkit_policy: 审计写入失败: %s\n" % e)
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# 策略文件读写
# ---------------------------------------------------------------------------

_SSH_DEFAULT_POLICY = {
    "version": VERSION,
    "defaults": {"sudo": DEFAULT_SDO, "approval_ttl_s": DEFAULT_TTL_S},
    "servers": {},
}

_DB_DEFAULT_POLICY = {
    "version": VERSION,
    "defaults": {"max_level": "read",
                 "approval": {"write": False, "ddl": True},
                 "allow_metadata": True,
                 "approval_ttl_s": DEFAULT_TTL_S},
    "databases": {},
}


def default_policy(tool):
    """返回该工具的默认策略骨架（深拷贝）。"""
    base = _SSH_DEFAULT_POLICY if tool == "ssh" else _DB_DEFAULT_POLICY
    return json.loads(json.dumps(base))


def tool_paths(tool):
    return dict(TOOL_PATHS.get(tool) or TOOL_PATHS["db"])


def policy_present(tool):
    """策略文件是否存在。

    给工具侧在「内核模块导入失败」时判定 fail-open / fail-closed 用
    （CONTRACT §8.1.1：模块缺失 + policy.json 不存在 → allow；policy.json 存在 → deny）。
    """
    try:
        return os.path.exists(tool_paths(tool)["policy"])
    except Exception:                          # noqa: BLE001
        return False


def read_policy(tool):
    """读原始策略文件。

    返回 {"exists": bool, "corrupt": bool, "data": dict|None, "error": str|None}
    * 不存在 → exists=False, data=None（= allow，向后兼容）
    * 损坏   → corrupt=True, data=None（= deny，fail-closed）
    """
    path = tool_paths(tool)["policy"]
    if not os.path.exists(path):
        return {"exists": False, "corrupt": False, "data": None, "error": None}
    ok, obj = _read_json(path)
    if not ok:
        return {"exists": True, "corrupt": True, "data": None, "error": str(obj)}
    if not isinstance(obj, dict):
        return {"exists": True, "corrupt": True, "data": None,
                "error": "策略文件顶层必须是 JSON 对象"}
    return {"exists": True, "corrupt": False, "data": obj, "error": None}


def write_policy(tool, data):
    """原子写策略文件（0600）。写失败抛 OSError，由调用方决定如何报错。"""
    path = tool_paths(tool)["policy"]
    if not isinstance(data, dict):
        raise ValueError("policy 必须是 JSON 对象")
    _atomic_write_json(path, data)
    return path


def _clamp_ttl(value, default=DEFAULT_TTL_S):
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        return default
    return max(TTL_MIN_S, min(TTL_MAX_S, ttl))


def _merge_dict(base, over):
    out = dict(base or {})
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_dict(out[k], v)
        else:
            out[k] = v
    return out


def effective_ssh_policy(raw, alias):
    """把 defaults + 服务器条目合并成生效策略。"""
    data = raw or {}
    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    servers = data.get("servers") if isinstance(data.get("servers"), dict) else {}
    entry = servers.get(alias) if isinstance(servers.get(alias), dict) else {}
    mode = entry.get("sudo", defaults.get("sudo", DEFAULT_SDO))
    if mode not in SUDO_MODES:
        mode = DEFAULT_SDO
    ttl = _clamp_ttl(entry.get("approval_ttl_s", defaults.get("approval_ttl_s",
                                                             DEFAULT_TTL_S)))
    return {"sudo": mode, "approval_ttl_s": ttl}


def effective_db_policy(raw, alias):
    """把 defaults + 数据库条目合并成生效策略（别名不在策略里 → 用 defaults）。"""
    data = raw or {}
    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    databases = data.get("databases") if isinstance(data.get("databases"), dict) else {}
    entry = databases.get(alias) if isinstance(databases.get(alias), dict) else {}

    level = entry.get("max_level", defaults.get("max_level", "read"))
    level = level if level in LEVELS else "read"

    approval = _merge_dict(defaults.get("approval") or {"write": False, "ddl": True},
                           entry.get("approval") or {})
    approval = {"write": bool(approval.get("write", False)),
                "ddl": bool(approval.get("ddl", True))}

    if "allowed_databases" in entry:
        allowed_dbs = entry.get("allowed_databases")
    else:
        allowed_dbs = defaults.get("allowed_databases")       # 默认 None = 不限
    if allowed_dbs is not None and not isinstance(allowed_dbs, list):
        allowed_dbs = None

    if "allowed_tables" in entry:
        allowed_tables = entry.get("allowed_tables")
    else:
        allowed_tables = defaults.get("allowed_tables")
    if allowed_tables is not None and not isinstance(allowed_tables, list):
        allowed_tables = None

    # PG 专用：schema 白名单（默认 None=不限）。PG 里 a.b 的 a 是 schema 不是库，
    # 所以 schema 不参与 allowed_databases 比对，需要单独收口时用这个字段。
    if "allowed_schemas" in entry:
        allowed_schemas = entry.get("allowed_schemas")
    else:
        allowed_schemas = defaults.get("allowed_schemas")
    if allowed_schemas is not None and not isinstance(allowed_schemas, list):
        allowed_schemas = None

    allow_metadata = entry.get("allow_metadata", defaults.get("allow_metadata", True))
    allow_metadata = True if allow_metadata is None else bool(allow_metadata)

    ttl = _clamp_ttl(entry.get("approval_ttl_s", defaults.get("approval_ttl_s",
                                                             DEFAULT_TTL_S)))
    return {
        "max_level": level,
        "approval": approval,
        "allowed_databases": allowed_dbs,
        "allowed_tables": allowed_tables,
        "allowed_schemas": allowed_schemas,
        "allow_metadata": allow_metadata,
        "approval_ttl_s": ttl,
    }


# ---------------------------------------------------------------------------
# sudo 识别（CONTRACT §8.1.2 收紧版）
#
# 原「命令位置匹配」可被 bash -c 'sudo ...' / sh -c "sudo ..." / echo $(sudo ...) /
# eval sudo ... 绕过。现行规则：**命令字符串里任意词边界出现提权关键字就一律视为提权**，
# 不做位置判断（CONTRACT §8.1.2）。
# 代价：`grep sudo /var/log/auth.log`、`cat /etc/passwd`、`mount` 之类也会走审批 ——
# 这是**刻意接受的误报**：宁可多点一次批准，也不能让提权命令溜过去。
# 提示文案统一写「检测到提权关键字」。
# ---------------------------------------------------------------------------

# 顺序按「最长/最具体优先」，同一位置先命中更具体的词（只影响审计里的命中词）
SUDO_WORDS = (
    "sudoedit", "systemd-run", "machinectl", "runuser", "nsenter", "visudo",
    "useradd", "usermod", "setcap", "pkexec", "chroot", "mount", "umount",
    "passwd", "sudo", "doas", "su",
)
_SUDO_WORD_RE = re.compile(r"\b(%s)\b" % "|".join(re.escape(w) for w in SUDO_WORDS),
                           re.I)


_SUDO_STRIP_CHARS = ("'", '"', "\\")


def is_sudo_command(command):
    r"""命令里是否出现提权关键字 → (bool, 命中的词)。

    shell 允许多种「拆词」写法逃过关键字匹配：s""udo id、s\udo、s''udo
    远端都会真的执行 sudo。所以先用**归一化副本**（去掉引号/反斜杠）再匹配一次；
    归一化只用于检测，绝不用于执行（执行始终用原始命令串）。
    已知限制：s u d o 这种空格拆词无法归一化（会引入大量误报），保持不拦。
    """
    if not command:
        return False, None
    raw = str(command)
    m = _SUDO_WORD_RE.search(raw)
    if m:
        return True, m.group(1).lower()
    normalized = raw
    for ch in _SUDO_STRIP_CHARS:
        if ch in normalized:
            normalized = normalized.replace(ch, "")
    if normalized != raw:
        m = _SUDO_WORD_RE.search(normalized)
        if m:
            return True, m.group(1).lower()
    return False, None


# ---------------------------------------------------------------------------
# SQL 等级分类（CONTRACT §4）
#
# 与 dbbind 的只读守卫保持同一套词表/上下文规则（dbbind 是单文件、必须独立，
# 这里是策略侧的唯一真源；测试里有一致性用例防止两边漂移）。
# ---------------------------------------------------------------------------

DML_KEYWORDS = {"INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE"}

DDL_KEYWORDS = {
    "TRUNCATE", "DROP", "ALTER", "CREATE", "RENAME", "GRANT", "REVOKE", "ATTACH",
    "DETACH", "VACUUM", "LOCK", "UNLOCK", "COPY", "PRAGMA", "LOAD", "DO",
    "CALL", "EXECUTE", "PREPARE", "FLUSH", "OPTIMIZE", "REINDEX", "REFRESH",
    "SHUTDOWN", "INSTALL", "UNINSTALL",
    # 事务控制：读写翻转/提交回滚在只读授权下都不该出现
    "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT",
}
ALL_KEYWORDS = sorted(DML_KEYWORDS | DDL_KEYWORDS)

_PRAGMA_READ_OK = {
    "table_info", "table_xinfo", "table_list", "index_list", "index_info",
    "index_xinfo", "foreign_key_list", "database_list", "compile_options",
    "collation_list", "function_list", "module_list", "pragma_list",
    "integrity_check", "quick_check", "encoding", "page_count", "page_size",
    "freelist_count", "user_version", "schema_version", "application_id",
    "auto_vacuum", "journal_mode", "synchronous", "cache_size", "mmap_size",
    "temp_store", "locking_mode", "max_page_count", "secure_delete",
    "recursive_triggers", "foreign_keys", "defer_foreign_keys",
    "read_uncommitted", "query_only", "threads", "data_version", "stats",
    "busy_timeout", "wal_autocheckpoint", "cell_size_check", "trusted_schema",
}

_COMMENT_MARKS = re.compile(r"/\*!?\d*|\*/|--[^\n]*|#[^\n]*")
_INSERT_INTO_RE = re.compile(r"\b(?:INSERT|REPLACE|MERGE)\s+INTO\b", re.I)

_CONTEXT_DDL = [
    # SELECT ... INTO newtable / INTO OUTFILE、COPY ... INTO
    (re.compile(r"\bCOPY\b[\s\S]*\bINTO\b", re.I), "COPY INTO"),
    (re.compile(r"\bSELECT\b[\s\S]*\bINTO\b", re.I), "SELECT INTO"),
    (re.compile(r"\bSTART\s+TRANSACTION\b", re.I), "START TRANSACTION"),
    (re.compile(r"\bCOMMENT\s+ON\b", re.I), "COMMENT ON"),
    # 翻转只读
    (re.compile(r"\bREAD\s+WRITE\b", re.I), "READ WRITE"),
    (re.compile(r"\bSET\b[^;]*\b(?:transaction_read_only|default_transaction_read_only|"
                r"read_only)\b[^;]*?(?:=|\bTO\b)\s*(?:off|false|0|no)\b", re.I),
     "SET READ ONLY OFF"),
]


def _flatten(sql, join=False):
    if join:
        return _COMMENT_MARKS.sub("", sql)
    return re.sub(r"/\*!?\d*|\*/", " ", re.sub(r"--[^\n]*|#[^\n]*", " ", sql))


def _pragma_is_write(text):
    for m in re.finditer(r"\bPRAGMA\b\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
                         r"([A-Za-z_][A-Za-z0-9_]*)?", text, re.I):
        name = (m.group(1) or "").lower()
        if not name or name not in _PRAGMA_READ_OK:
            return True
        seg = text[m.end():m.end() + 80].split(";")[0]
        if "=" in seg:
            return True
    return False


def sql_scan(sql, engine="mysql"):
    """扫描 SQL → (sig_end, statements)。

    sig_end = 最后一个有效字符之后的位置（注释/空白不算）；
    statements = [(start, end)] 顶层语句区间。识别引号/注释/$tag$ 引用。
    """
    n = len(sql or "")
    i = 0
    sig_end = 0
    stmts = []
    cur_start = None
    in_sq = in_dq = in_bt = in_br = False
    line_comment = block_comment = False
    dollar_tag = None
    while i < n:
        ch = sql[i]
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if sql.startswith("*/", i):
                block_comment = False
                i += 2
                continue
            i += 1
            continue
        if dollar_tag is not None:
            if sql.startswith(dollar_tag, i):
                i += len(dollar_tag)
                dollar_tag = None
                sig_end = i
                continue
            i += 1
            continue
        if in_sq:
            if ch == "\\" and i + 1 < n:
                i += 2
                sig_end = i
                continue
            if ch == "'":
                in_sq = False
            i += 1
            sig_end = i
            continue
        if in_dq:
            if ch == '"':
                in_dq = False
            i += 1
            sig_end = i
            continue
        if in_bt:
            if ch == "`":
                in_bt = False
            i += 1
            sig_end = i
            continue
        if in_br:
            if ch == "]":
                in_br = False
            i += 1
            sig_end = i
            continue
        if sql.startswith("--", i):
            line_comment = True
            i += 2
            continue
        if engine == "mysql" and ch == "#":
            line_comment = True
            i += 1
            continue
        if sql.startswith("/*", i):
            block_comment = True
            i += 2
            continue
        if ch == "'":
            in_sq = True
        elif ch == '"':
            in_dq = True
        elif ch == "`":
            in_bt = True
        elif ch == "[":
            in_br = True
        elif ch == "$":
            m = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[i:])
            if m:
                dollar_tag = m.group(0)
                i += len(dollar_tag)
                sig_end = i
                continue
        elif ch == ";":
            if cur_start is not None:
                stmts.append((cur_start, i))
                cur_start = None
            i += 1
            sig_end = i
            continue
        elif not ch.isspace():
            if cur_start is None:
                cur_start = i
        i += 1
        sig_end = i
    if cur_start is not None:
        stmts.append((cur_start, n))
    return sig_end, stmts


def strip_sql_tail(sql, engine="mysql"):
    sig_end, _ = sql_scan(sql, engine)
    body = sql[:sig_end].rstrip()
    while body.endswith(";"):
        body = body[:-1].rstrip()
    return body


def count_statements(sql, engine="mysql"):
    _, stmts = sql_scan(sql, engine)
    return len([s for s in stmts if sql[s[0]:s[1]].strip()])


# PG 跨库只能走 dblink/FDW —— dblink 系列函数能对远端库执行任意 SQL，按高风险处理
_PG_HIGH_RISK = [
    (re.compile(r"\bdblink\w*\s*\(", re.I), "DBLINK"),
]


def sql_hits_highest(sql, engine="mysql"):
    """返回命中的最高等级：'read' | 'write' | 'ddl'，以及命中词列表。"""
    text_sources = [sql or ""]
    flat = _flatten(sql or "")
    if flat != sql:
        text_sources.append(flat)
    flat_join = _flatten(sql or "", join=True)
    if flat_join not in text_sources:
        text_sources.append(flat_join)

    dml, ddl = [], []
    for text in text_sources:
        if not text:
            continue
        for word in ALL_KEYWORDS:
            if word == "PRAGMA":
                continue
            if re.search(r"\b%s\b" % word, text, re.I):
                if word in DML_KEYWORDS:
                    if word not in dml:
                        dml.append(word)
                elif word in DDL_KEYWORDS:
                    if word not in ddl:
                        ddl.append(word)
        if re.search(r"\bPRAGMA\b", text, re.I) and _pragma_is_write(text):
            if "PRAGMA" not in ddl:
                ddl.append("PRAGMA")
        ctx = _INSERT_INTO_RE.sub(" ", text)
        for pat, label in _CONTEXT_DDL:
            if pat.search(ctx) and label not in ddl:
                ddl.append(label)
        if engine == "postgres":
            for pat, label in _PG_HIGH_RISK:
                if pat.search(text) and label not in ddl:
                    ddl.append(label)
    if ddl:
        return "ddl", ddl + dml
    if dml:
        return "write", dml
    return "read", []


def sql_required_level(sql, engine="mysql"):
    """语句要求的权限等级（多语句取最高）。"""
    level, _hits = sql_hits_highest(sql, engine)
    return level


def _strip_ident_quotes(name):
    return str(name).strip().strip('`"[]')


# 表引用提取：FROM/JOIN/UPDATE/INTO/TABLE 之后，**以及 FROM 子句里逗号分隔的后续表**。
# 只匹配第一个表引用是不够的：`FROM whitelisted.t, other.secret` 会漏掉后者
# （verifier 实测的数据泄漏路径，CONTRACT §4.2 已明确要求逐个检查）。
_IDENT_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")

# 这些关键字表示 FROM 子句结束（回到其它子句）
_CLAUSE_STOP = frozenset((
    "WHERE", "GROUP", "ORDER", "LIMIT", "HAVING", "UNION", "EXCEPT", "INTERSECT",
    "WINDOW", "RETURNING", "INTO", "SET", "VALUES", "FOR", "LOCK", "OFFSET",
    "FETCH", "SELECT", "FROM", "JOIN", "STRAIGHT_JOIN", "UPDATE", "TABLE",
))
# 出现在表引用前但不改变「下一个是表」的修饰词
_TRANSPARENT_WORDS = frozenset((
    "LATERAL", "ONLY", "IF", "NOT", "EXISTS", "TEMPORARY", "TEMP", "UNLOGGED",
    "EXTERNAL",
))
# 出现在表位置但不是表的东西（子查询/函数/集合）
_NON_TABLE_WORDS = frozenset(("SELECT", "VALUES", "JSON_TABLE", "UNNEST", "ROWS"))


def _parse_table_ref(sql, i):
    """从 i 解析一个表引用（`t` / `schema.t` / 带引号形式）。

    返回 (first, table, next_index)。first 是限定前缀（MySQL=库 / PG=schema /
    SQLite=attach 库名），table 是表名。
    """
    n = len(sql)

    def read_ident(j):
        if j >= n:
            return None, j
        ch = sql[j]
        if ch in ("`", '"', "["):
            close = {"`": "`", '"': '"', "[": "]"}[ch]
            k = j + 1
            while k < n and sql[k] != close:
                k += 1
            if k >= n:
                return None, j
            return sql[j + 1:k], k + 1
        m = _IDENT_WORD_RE.match(sql, j)
        return (m.group(0), m.end()) if m else (None, j)

    name, j = read_ident(i)
    if name is None:
        return None, None, i
    k = j
    while k < n and sql[k].isspace():
        k += 1
    if k < n and sql[k] == ".":
        k += 1
        while k < n and sql[k].isspace():
            k += 1
        name2, j2 = read_ident(k)
        if name2 is not None:
            return name, name2, j2
    return None, name, j


def _iter_table_refs(sql_clean):
    """遍历所有表引用 → [(first, table)]。

    覆盖：FROM a, b / CROSS JOIN / JOIN 链 / 子查询 / UNION 各分支 /
    UPDATE / INTO / TABLE / DELETE FROM。括号深度感知：子查询里的 FROM 也会被发现。
    """
    refs = []
    n = len(sql_clean)
    i = 0
    depth = 0
    from_depths = set()          # 当前哪些括号深度处于 FROM 子句
    pending = False              # 下一个标识符是否是表引用
    while i < n:
        ch = sql_clean[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            depth += 1
            # FROM ONLY (schema.table) / FROM (a JOIN b ...)：表位置的括号
            # 保留 pending；遇 SELECT 时由 _NON_TABLE_WORDS 转入子查询扫描。
            if pending:
                from_depths.add(depth)
            i += 1
            continue
        if ch == ")":
            from_depths.discard(depth)
            depth = max(0, depth - 1)
            pending = False
            i += 1
            continue
        if ch == ",":
            if depth in from_depths:
                pending = True       # FROM 子句里的逗号 = 下一个表引用
            i += 1
            continue
        if ch in ("`", '"', "[") or ch.isalpha() or ch == "_":
            if pending:
                m = _IDENT_WORD_RE.match(sql_clean, i)
                if m and m.group(0).upper() in _TRANSPARENT_WORDS:
                    i = m.end()      # 修饰词，保持 pending
                    continue
                if m and m.group(0).upper() in _NON_TABLE_WORDS:
                    pending = False
                    i = m.end()
                    continue
                first, table, j = _parse_table_ref(sql_clean, i)
                if table:
                    k = j
                    while k < n and sql_clean[k].isspace():
                        k += 1
                    if k < n and sql_clean[k] == "(":
                        # 函数调用（FROM generate_series(...) 等），不是表
                        pending = False
                        i = j
                        continue
                    refs.append((first, table))
                pending = False
                i = max(j, i + 1)
                continue
            m = _IDENT_WORD_RE.match(sql_clean, i)
            if not m:
                i += 1
                continue
            word = m.group(0)
            up = word.upper()
            if up == "FROM":
                from_depths.add(depth)
                pending = True
            elif up in ("JOIN", "STRAIGHT_JOIN", "UPDATE", "INTO", "TABLE"):
                pending = True
            elif up in _CLAUSE_STOP:
                from_depths.discard(depth)
                pending = False
            i = m.end()
            continue
        i += 1
    return refs


# 库/Schema 名模式（USE / SET search_path / CTE）
_USE_DB_RE = re.compile(r"\bUSE\s+([`\"\[]?[A-Za-z_][A-Za-z0-9_$]*[`\"\]]?)", re.I)
_SEARCH_PATH_RE = re.compile(r"\bSET\s+(?:(?:SESSION|LOCAL)\s+)?search_path\s*(?:=|TO)\s*([^;]+)", re.I)
_CTE_RE = re.compile(r"\bWITH\s+(?:RECURSIVE\s+)?([A-Za-z_][A-Za-z0-9_$]*)"
                     r"(?:\s*\([^)]*\))?\s+AS\s*\(", re.I)


def _normalize_sql_for_targets(sql, engine="mysql"):
    """规范化 SQL 以便提取目标库/表。

    * 单引号字符串 → 置空（内容不是标识符）
    * **反引号/双引号/方括号标识符保留**（否则 `otherdb`.secret 这类会被漏掉）
    * 注释：`--` / `#` 行注释与普通块注释置空；MySQL 版本注释 `/*!50000 ... */`
      保留内容（它会被服务端执行，不能当注释丢掉）
    """
    out = []
    i, n = 0, len(sql or "")
    in_sq = in_dq = in_bt = in_br = False
    while i < n:
        ch = sql[i]
        if in_sq:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_sq = False
                out.append("''")
            i += 1
            continue
        if in_dq:
            out.append(ch)
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if in_bt:
            out.append(ch)
            if ch == "`":
                in_bt = False
            i += 1
            continue
        if in_br:
            out.append(ch)
            if ch == "]":
                in_br = False
            i += 1
            continue
        # MySQL 的 -- 后须有空白/控制字符；1--1 是算术表达式。
        dash_comment = sql.startswith("--", i) and (
            engine != "mysql" or i + 2 >= n or sql[i + 2].isspace()
            or ord(sql[i + 2]) < 32)
        if dash_comment or (engine == "mysql" and ch == "#"):
            while i < n and sql[i] != "\n":
                i += 1
            out.append(" ")
            continue
        if sql.startswith("/*", i):
            if sql.startswith("/*!", i):
                i += 3
                while i < n and sql[i].isdigit():     # 吃掉 /*!50000 的版本号
                    i += 1
                continue                              # 内容保留，继续正常扫描
            end = sql.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
            continue
        if ch == "'":
            in_sq = True
            i += 1
            continue
        if ch == '"':
            in_dq = True
            out.append(ch)
            i += 1
            continue
        if ch == "`":
            in_bt = True
            out.append(ch)
            i += 1
            continue
        if ch == "[":
            in_br = True
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# 兼容旧名字（内部/测试可能引用）
def _strip_sql_literals(sql):
    return _normalize_sql_for_targets(sql)


# SHOW 语句的库名：SHOW TABLES FROM db / SHOW COLUMNS FROM t FROM db
_SHOW_DB_PATTERNS = [
    re.compile(r"\bSHOW\s+(?:FULL\s+)?(?:TABLES|TABLE\s+STATUS|TRIGGERS|EVENTS)"
               r"\s+(?:FROM|IN)\s+([`\"\[]?[A-Za-z_][A-Za-z0-9_$]*[`\"\]]?)", re.I),
    # SHOW COLUMNS FROM <table> FROM <db> / SHOW INDEX FROM <table> IN <db>
    re.compile(r"\bSHOW\s+(?:FULL\s+)?(?:COLUMNS|FIELDS|INDEX|INDEXES|KEYS)"
               r"\s+(?:FROM|IN)\s+\S+\s+(?:FROM|IN)\s+"
               r"([`\"\[]?[A-Za-z_][A-Za-z0-9_$]*[`\"\]]?)", re.I),
]


def sql_targets(sql, engine="mysql", default_db=None):
    """启发式提取 SQL 的目标库 / schema / 表。

    引擎差异（关键，CONTRACT §4.2 + Lead 复审）：
      * **PostgreSQL**：`a.b` 里的 `a` 是 **schema，不是库**（PG 跨库要 dblink/FDW，
        SQL 语法层面没有跨库）。所以 PG 的库白名单只比对「连接默认库」；
        schema 只在显式配了 allowed_schemas 时收口，`public.*` 默认不受限。
      * **MySQL**：`a.b` 里的 `a` 是 database；`USE db` 也是 database。
      * **SQLite**：`a.b` 里的 `a` 是 attach 进来的库名（等价 database）。

    返回 {"databases": [...], "schemas": [...], "tables": [...], "resolved": bool}
    """
    is_pg = (engine == "postgres")
    dbs, schemas, tables = [], [], []
    resolved = False
    sql_clean = _normalize_sql_for_targets(sql, engine)
    if default_db:
        dbs.append(str(default_db))

    # 逐个检查**所有**表引用（FROM a, b / JOIN / 子查询 / UNION 分支），
    # 只查第一个会被 `FROM 白名单表, 越界表` 绕过（CONTRACT §4.2）
    _refs = _iter_table_refs(sql_clean)
    for first, table in _refs:
        if first:
            if is_pg:
                schemas.append(first)      # PG：a.b 的 a 是 schema
            else:
                dbs.append(first)          # MySQL/SQLite：a.b 的 a 是库
        if table:
            tables.append(table)
        resolved = True
    if not is_pg:
        for m in _USE_DB_RE.finditer(sql_clean):    # USE 是 MySQL/SQLite 语法
            dbs.append(_strip_ident_quotes(m.group(1)))
    for m in _SEARCH_PATH_RE.finditer(sql_clean):
        for part in m.group(1).split(","):
            name = _strip_ident_quotes(part.strip())
            if not name or name.lower() in ("default", "$user"):
                continue
            (schemas if is_pg else dbs).append(name)
    for pat in _SHOW_DB_PATTERNS:
        for m in pat.finditer(sql_clean):
            name = _strip_ident_quotes(m.group(1))
            if name:
                (schemas if is_pg else dbs).append(name)

    ctes = {m.group(1).lower() for m in _CTE_RE.finditer(sql_clean)}
    tables = [t for t in tables if t.lower() not in ctes]

    def _uniq(seq):
        seen, out = set(), []
        for item in seq:
            key = str(item).lower()
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    return {"databases": _uniq(dbs), "schemas": _uniq(schemas),
            "tables": _uniq(tables), "resolved": resolved,
            "refs": [(f, t) for (f, t) in _refs if t.lower() not in ctes]}


# ---------------------------------------------------------------------------
# 审批单（CONTRACT §5）
# ---------------------------------------------------------------------------

_APPROVAL_ID_RE = re.compile(r"^apr_[0-9]{8}_[0-9a-f]{6}$")
APPROVAL_STATUSES = ("pending", "approved", "denied", "consumed", "expired")


def _approvals_dir(tool):
    return tool_paths(tool)["approvals"]


def _new_approval_id():
    return "apr_%s_%s" % (time.strftime("%Y%m%d"), os.urandom(3).hex())


def fingerprint(tool, alias, action, target):
    """审批指纹：同工具+同别名+同动作+同目标（命令/SQL 原文）才算同一件事。"""
    raw = json.dumps({"tool": tool, "alias": alias, "action": action,
                      "target": target}, ensure_ascii=False, sort_keys=True)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


class _ApprovalLock(object):
    """审批目录的跨进程互斥锁（fcntl.flock）。拿不到锁时降级为无锁（仍原子写）。"""

    def __init__(self, tool):
        self.tool = tool
        self.path = os.path.join(_approvals_dir(tool), ".lock")
        self.fd = None

    def __enter__(self):
        try:
            _ensure_dir(_approvals_dir(self.tool), 0o700)
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX)
            except (ImportError, OSError):
                pass
        except OSError:
            self.fd = None
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                try:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        return False


def _load_approval_file(path):
    ok, obj = _read_json(path)
    if not ok or not isinstance(obj, dict):
        return None
    return obj


def _save_approval(tool, ap):
    path = os.path.join(_approvals_dir(tool), "%s.json" % ap["id"])
    _atomic_write_json(path, ap)
    return path


def _is_expired(ap, now=None):
    now = now or _now()
    exp = _parse_iso(ap.get("expires_at"))
    return bool(exp and exp <= now)


def _refresh_expired_quietly(tool, ap):
    """过期的 pending/approved 惰性落盘为 expired（失败静默）。"""
    if ap.get("status") in ("pending", "approved") and _is_expired(ap):
        ap["status"] = "expired"
        try:
            _save_approval(tool, ap)
        except OSError:
            pass
    return ap


def iter_approvals(tool, refresh=True):
    """遍历审批单（按 created_at 倒序）。读失败的文件跳过并记 warning 到返回结构。"""
    directory = _approvals_dir(tool)
    out = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json") or name.startswith(".tmp-"):
            continue
        ap = _load_approval_file(os.path.join(directory, name))
        if not ap or not ap.get("id"):
            continue
        if refresh:
            ap = _refresh_expired_quietly(tool, ap)
        out.append(ap)
    out.sort(key=lambda a: (a.get("created_at") or "", a.get("id") or ""), reverse=True)
    return out


def list_approvals(tool=None, status=None, alias=None):
    """给控制台用的审批列表。

    tool=None 时返回两个工具的全部审批单（每条自带 tool 字段）；可按 status/alias 过滤。
    """
    tools = [tool] if tool in ("ssh", "db") else ["ssh", "db"]
    items = []
    for t in tools:
        for ap in iter_approvals(t):
            if status and ap.get("status") != status:
                continue
            if alias and ap.get("alias") != alias:
                continue
            item = dict(ap)
            item.setdefault("tool", t)
            items.append(item)
    items.sort(key=lambda a: (a.get("created_at") or "", a.get("id") or ""),
               reverse=True)
    return items


def get_approval(tool, approval_id):
    if not approval_id or not re.match(r"^apr_[A-Za-z0-9_]+$", str(approval_id)):
        return None
    path = os.path.join(_approvals_dir(tool), "%s.json" % approval_id)
    ap = _load_approval_file(path)
    if not ap:
        return None
    return _refresh_expired_quietly(tool, ap)


def _find_approved_for(tool, fp, now):
    """找到可消费的批准单（同 fingerprint / approved / 未过期 / consumes_left>0）。"""
    for ap in iter_approvals(tool):
        if ap.get("fingerprint") != fp:
            continue
        if ap.get("status") != "approved":
            continue
        if _is_expired(ap, now):
            continue
        try:
            left = int(ap.get("consumes_left", 0))
        except (TypeError, ValueError):
            left = 0
        if left > 0:
            return ap
    return None


def _consume_approval(tool, ap):
    """消费一次：consumes_left-1；归零则 status=consumed。返回更新后的单。"""
    left = int(ap.get("consumes_left", 0)) - 1
    ap["consumes_left"] = max(0, left)
    if left <= 0:
        ap["status"] = "consumed"
        ap["consumed_at"] = _iso(_now())
    _save_approval(tool, ap)
    return ap


def _find_pending_for(tool, fp, now):
    for ap in iter_approvals(tool):
        if ap.get("fingerprint") == fp and ap.get("status") == "pending" \
                and not _is_expired(ap, now):
            return ap
    return None


def _create_approval(tool, alias, action, target, fp, ttl_s, requester, note=None):
    now = _now()
    ap = {
        "id": _new_approval_id(),
        "tool": tool,
        "alias": alias,
        "action": action,
        "target": _truncate(redact(target)),
        "fingerprint": fp,
        "requester": requester if requester in ("ai", "web") else "ai",
        "created_at": _iso(now),
        "expires_at": _iso(now + timedelta(seconds=ttl_s)),
        "status": "pending",
        "decided_at": None,
        "decided_by": None,
        "consumes_left": 1,
        "note": _truncate(redact(note)) if note else None,
    }
    _save_approval(tool, ap)
    return ap


def approve(tool, approval_id, consumes=1, ttl_s=600, note=None, decided_by="web"):
    """批准一张 pending 单（原子写、并发安全：重复批准只生效一次）。

    ttl_s 语义：expires_at = 批准时刻 + ttl_s（覆盖建单时的过期时间）。
    consumes：允许重试消费的次数（1..10）。
    返回：更新后的审批单全字段 dict。单不存在/状态不对时抛 ValueError（给 Web 内核）。
    """
    if tool not in ("ssh", "db"):
        raise ValueError("tool 必须是 ssh 或 db：%r" % (tool,))
    try:
        consumes = int(consumes)
    except (TypeError, ValueError):
        consumes = 1
    consumes = max(1, min(10, consumes))
    ttl = _clamp_ttl(ttl_s if ttl_s is not None else DEFAULT_TTL_S)
    with _ApprovalLock(tool):
        ap = get_approval(tool, approval_id)
        if not ap:
            raise ValueError("审批单不存在：%s" % approval_id)
        if ap.get("status") != "pending":
            raise ValueError("审批单状态不是 pending（当前 %s），不能批准"
                             % ap.get("status"))
        now = _now()
        ap["status"] = "approved"
        ap["decided_at"] = _iso(now)
        ap["decided_by"] = decided_by if decided_by in ("ai", "web") else "web"
        ap["consumes_left"] = consumes
        ap["expires_at"] = _iso(now + timedelta(seconds=ttl))
        ap["ttl_s"] = ttl
        if note is not None:
            ap["note"] = _truncate(redact(note))
        _save_approval(tool, ap)
    audit(tool, "web", ap.get("alias"), ap.get("action"), "approve",
          request_id=ap.get("id"), target=ap.get("target"),
          note="consumes=%s ttl=%ss" % (consumes, ttl))
    return ap


def reject(tool, approval_id, note=None, decided_by="web"):
    """拒绝一张 pending 单（原子写、并发安全）。返回更新后的审批单全字段 dict。"""
    if tool not in ("ssh", "db"):
        raise ValueError("tool 必须是 ssh 或 db：%r" % (tool,))
    with _ApprovalLock(tool):
        ap = get_approval(tool, approval_id)
        if not ap:
            raise ValueError("审批单不存在：%s" % approval_id)
        if ap.get("status") != "pending":
            raise ValueError("审批单状态不是 pending（当前 %s），不能拒绝"
                             % ap.get("status"))
        ap["status"] = "denied"
        ap["decided_at"] = _iso(_now())
        ap["decided_by"] = decided_by if decided_by in ("ai", "web") else "web"
        ap["note"] = _truncate(redact(note)) if note else None
        _save_approval(tool, ap)
    audit(tool, "web", ap.get("alias"), ap.get("action"), "reject",
          request_id=ap.get("id"), target=ap.get("target"), note=note)
    return ap


def _ask_or_allow(tool, alias, action, target, ttl_s, requester, message, hint_prefix):
    """审批流公共部分：命中已批准单→消费放行；否则复用/新建 pending 并返回 ask。"""
    now = _now()
    fp = fingerprint(tool, alias, action, target)
    try:
        with _ApprovalLock(tool):
            approved = _find_approved_for(tool, fp, now)
            if approved:
                ap = _consume_approval(tool, approved)
                audit(tool, requester, alias, action, "consume",
                      request_id=ap.get("id"), target=target,
                      note="consumes_left=%s" % ap.get("consumes_left"))
                return {"decision": "allow",
                        "consumed_approval": ap.get("id"),
                        "consumes_left": ap.get("consumes_left")}
            pending = _find_pending_for(tool, fp, now)
            if pending:
                ap = pending
            else:
                ap = _create_approval(tool, alias, action, target, fp, ttl_s,
                                      requester)
    except OSError as e:
        # 契约 §8.1.1：需要建审批单但目录不可写 → deny（fail-closed）
        audit(tool, requester, alias, action, "error", target=target,
              note="审批目录不可写：%s" % e)
        return _deny("STATE_CORRUPT",
                    "无法创建审批单（审批目录不可写），已按 fail-closed 拒绝",
                    "检查 %s 的权限（应为 0700）" % _approvals_dir(tool))
    audit(tool, requester, alias, action, "ask", request_id=ap.get("id"), target=target)
    return {
        "decision": "ask",
        "code": "APPROVAL_REQUIRED",
        "request_id": ap.get("id"),
        "expires_at": ap.get("expires_at"),
        "message": message,
        "hint": "%s；request_id: %s" % (hint_prefix, ap.get("id")),
    }


# ---------------------------------------------------------------------------
# 闸门：ssh
# ---------------------------------------------------------------------------

def _deny(code, message, hint=None):
    return {"decision": "deny", "code": code, "message": message, "hint": hint}


def gate_ssh(alias, command, requester="ai"):
    """ssh 命令闸门。**绝不抛异常**；返回 §8.1 的三种 dict 之一。

    无 policy.json → allow（完全维持原行为，不写审计，零副作用）。
    """
    try:
        pol = read_policy("ssh")
        if not pol["exists"]:
            return {"decision": "allow"}
        if pol["corrupt"]:
            audit("ssh", requester, alias, "exec", "error", target=command,
                  note="策略文件损坏：%s" % pol["error"])
            return _deny("STATE_CORRUPT",
                        "ssh 策略文件损坏，已按 fail-closed 拒绝：%s"
                        % tool_paths("ssh")["policy"],
                        "修复或删除 ~/.ssh/sshbind/policy.json 后重试")
        sudo, word = is_sudo_command(command)
        policy = effective_ssh_policy(pol["data"], alias)
        mode = policy["sudo"]
        if not sudo:
            audit("ssh", requester, alias, "exec", "allow", target=command,
                  note="非提权命令")
            return {"decision": "allow"}
        action = "sudo"
        if mode == "allow":
            audit("ssh", requester, alias, action, "allow", target=command,
                  note="策略 sudo=allow（检测到提权关键字：%s）" % word)
            return {"decision": "allow"}
        if mode == "deny":
            audit("ssh", requester, alias, action, "deny", target=command,
                  note="策略 sudo=deny（命中 %s）" % word)
            return _deny("SUDO_DENIED",
                        "服务器 %s 的策略禁止提权操作（sudo=deny）" % alias,
                        "检测到提权关键字 %s；如确需执行，请在控制台把该服务器的 "
                        "sudo 策略改为 ask 或 allow" % word)
        # ask
        return _ask_or_allow(
            "ssh", alias, action, command, policy["approval_ttl_s"], requester,
            "检测到提权关键字（%s），该操作需要人工审批（服务器 %s）"
            % (word, alias),
            "打开 http://127.0.0.1:8790 审批后重试同一命令")
    except Exception as e:                     # noqa: BLE001 —— 闸门绝不抛异常
        try:
            audit("ssh", requester, alias, "exec", "error", target=command,
                  note="闸门内部错误：%s" % e)
        except Exception:
            pass
        return _deny("AUTHZ_DENIED", "策略校验内部错误，已按 fail-closed 拒绝",
                     "查看 ~/.bindconsole/audit.log")


# ---------------------------------------------------------------------------
# 闸门：db
# ---------------------------------------------------------------------------

def _check_db_whitelist(alias, sql, engine, default_db, policy, level):
    """白名单/元数据检查。返回 (ok, message, hint, note)。

    **元数据放行只作用于「该表引用本身」**：`FROM information_schema.tables, 越界.表`
    里元数据表放行后，其它引用必须继续逐个过白名单——否则一条语句里混一个元数据表
    就能把整条语句的检查短路掉（verifier C1 实测的数据泄漏）。
    """
    targets = sql_targets(sql, engine, default_db)
    refs = targets.get("refs") or []
    is_pg = (engine == "postgres")
    meta_allowed_level = (level == "read" and policy["allow_metadata"])

    # 未限定的表引用使用连接默认库，不能只检查显式 db.table。
    namespaces = targets["schemas"] if is_pg else targets["databases"]
    if any(str(ns).lower() in METADATA_FORBIDDEN for ns in namespaces):
        return (False, "禁止访问系统库 mysql（存口令哈希等凭据）",
                "该库永远不在授权范围内；请让管理员使用独立运维账号处理", None)
    if not policy["allow_metadata"] and any(
            str(ns).lower() in METADATA_READ_OK for ns in namespaces):
        return (False, "该别名禁止读取元数据模式（information_schema/pg_catalog/...）",
                "需要读元数据请让管理员把 allow_metadata 设为 true", None)

    # ---- 逐引用：mysql 禁库永远拒；元数据引用按 allow_metadata 单独放行 ----
    for first, table in refs:
        ns = str(first or "").lower()
        if ns in METADATA_FORBIDDEN:
            return (False,
                    "禁止访问系统库：%s（存口令哈希等凭据）" % ns,
                    "该库永远不在授权范围内；如确需运维请用独立高权账号直连", None)
        if ns in METADATA_READ_OK:
            if meta_allowed_level:
                continue                      # 只放行这个引用，继续查其它引用
            if not policy["allow_metadata"]:
                return (False,
                        "该别名禁止读取元数据模式（information_schema/pg_catalog/...）",
                        "需要读元数据请让管理员把 allow_metadata 设为 true", None)
            # 写元数据：当普通对象走下面的白名单判定

    # ---- 库白名单（MySQL/SQLite 的 a.b；PG 只有连接默认库）----
    allowed = policy["allowed_databases"]
    if allowed is not None:
        norm = {str(x).lower() for x in allowed}
        dbs = targets["databases"]
        if meta_allowed_level:
            dbs = [d for d in dbs if str(d).lower() not in METADATA_READ_OK]
        outside = [d for d in dbs if str(d).lower() not in norm]
        if outside:
            return (False,
                    "目标库不在白名单内：%s" % "、".join(outside[:5]),
                    "该别名允许的库：%s" % "、".join(sorted(norm)[:10]), None)

    # ---- PG schema 白名单（默认 null=不限；public.* 不受限）----
    allowed_schemas = policy.get("allowed_schemas")
    if allowed_schemas is not None and is_pg:
        norm_s = {str(x).lower() for x in allowed_schemas}
        schemas = targets["schemas"]
        if meta_allowed_level:
            schemas = [x for x in schemas if str(x).lower() not in METADATA_READ_OK]
        outside_s = [x for x in schemas if str(x).lower() not in norm_s]
        if outside_s:
            return (False,
                    "目标 schema 不在白名单内：%s" % "、".join(outside_s[:5]),
                    "该别名允许的 schema：%s" % "、".join(sorted(norm_s)[:10]), None)

    # ---- 表白名单：跳过「已被 allow_metadata 放行的元数据引用」----
    allowed_tables = policy["allowed_tables"]
    if allowed_tables is not None:
        if not targets["resolved"]:
            return True, None, None, "白名单外无法确定目标表，按契约放行并记 warning"
        norm_t = {str(x).lower() for x in allowed_tables}
        check_tables = []
        if refs:
            for first, table in refs:
                if meta_allowed_level and str(first or "").lower() in METADATA_READ_OK:
                    continue
                check_tables.append(table)
        else:
            check_tables = list(targets["tables"])
        outside_t = [t for t in check_tables if str(t).lower() not in norm_t]
        if outside_t:
            return (False,
                    "目标表不在白名单内：%s" % "、".join(outside_t[:5]),
                    "该别名允许的表：%s" % "、".join(sorted(norm_t)[:10]), None)
    return True, None, None, None


def policy_warnings(engine, policy):
    """配置易用性提示（不阻断执行）。

    PG 的 a.b 是 schema：只配 allowed_databases 不会限制 schema，
    用户常误以为已经隔离 —— 提示一句，让他们知道要配 allowed_schemas。
    """
    hints = []
    if engine == "postgres" and policy.get("allowed_databases") is not None \
            and policy.get("allowed_schemas") is None:
        hints.append("PG 的 schema 不受 allowed_databases 限制；如需按 schema 收口，"
                     "请在该别名/默认策略里配置 allowed_schemas")
    return hints


def gate_db(alias, sql, engine, default_db, requested_write=False,
            requested_unsafe=False, requester="ai"):
    """数据库 SQL 闸门。**绝不抛异常**；返回 §8.1 的三种 dict 之一。

    无 policy.json → allow（完全维持原行为，不写审计，零副作用）。
    策略上限优先于 requested_write/requested_unsafe（CONTRACT §4 / §8.3）。
    """
    try:
        pol = read_policy("db")
        if not pol["exists"]:
            return {"decision": "allow"}
        if pol["corrupt"]:
            audit("db", requester, alias, "exec", "error", target=sql,
                  note="策略文件损坏：%s" % pol["error"])
            return _deny("STATE_CORRUPT",
                        "db 策略文件损坏，已按 fail-closed 拒绝：%s"
                        % tool_paths("db")["policy"],
                        "修复或删除 ~/.dbbind/policy.json 后重试")
        policy = effective_db_policy(pol["data"], alias)
        required = sql_required_level(sql, engine)
        max_level = policy["max_level"]
        note_bits = ["required=%s max=%s" % (required, max_level)]
        if requested_write or requested_unsafe:
            note_bits.append("requested=%s"
                             % ("unsafe" if requested_unsafe else "write"))

        # 1) 策略上限（优先于用户参数）
        if LEVEL_RANK[required] > LEVEL_RANK[max_level]:
            audit("db", requester, alias, required, "deny", target=sql,
                  note="超授权等级：" + " ".join(note_bits))
            return _deny(
                "AUTHZ_DENIED",
                "别名 %s 的策略上限是 %s，该语句需要 %s 权限"
                % (alias, max_level, required),
                "即使传 --write/--unsafe 也无法越过策略上限；如确需请让管理员"
                "把该别名的 max_level 调到 %s 或更高" % required)

        # 2) 白名单 / 元数据
        ok, message, hint, wl_note = _check_db_whitelist(
            alias, sql, engine, default_db, policy, required)
        if not ok:
            audit("db", requester, alias, required, "deny", target=sql,
                  note="白名单拒绝：" + (wl_note or message or ""))
            return _deny("AUTHZ_DENIED", message, hint)
        if wl_note:
            note_bits.append(wl_note)

        # 3) 审批
        need_approval = bool(policy["approval"].get(required)) if required != "read" else False
        if not need_approval:
            audit("db", requester, alias, required, "allow", target=sql,
                  note=" ".join(note_bits))
            result = {"decision": "allow"}
            hints = policy_warnings(engine, policy)
            if hints:
                result["warnings"] = hints      # 易用性提示，不影响放行
            return result
        # 同一 SQL 在不同库有不同副作用，审批必须同时绑定引擎与实际默认库。
        approval_target = json.dumps({"engine": engine, "database": default_db, "sql": sql},
                                     ensure_ascii=False, sort_keys=True)
        return _ask_or_allow(
            "db", alias, required, approval_target, policy["approval_ttl_s"], requester,
            "该操作需要人工审批（别名 %s / 等级 %s）" % (alias, required),
            "打开 http://127.0.0.1:8791 审批后重试同一命令")
    except Exception as e:                     # noqa: BLE001 —— 闸门绝不抛异常
        try:
            audit("db", requester, alias, "exec", "error", target=sql,
                  note="闸门内部错误：%s" % e)
        except Exception:
            pass
        return _deny("AUTHZ_DENIED", "策略校验内部错误，已按 fail-closed 拒绝",
                     "查看 ~/.bindconsole/audit.log")


# ---------------------------------------------------------------------------
# 控制台辅助：把策略/审批映射成可展示结构
# ---------------------------------------------------------------------------

def policy_summary(tool):
    """给控制台 policy_get 用：宽松解析，损坏也能展示状态。"""
    pol = read_policy(tool)
    if not pol["exists"]:
        return {"exists": False, "corrupt": False, "policy": default_policy(tool),
                "path": tool_paths(tool)["policy"]}
    if pol["corrupt"]:
        return {"exists": True, "corrupt": True, "policy": None,
                "path": tool_paths(tool)["policy"], "error": pol["error"]}
    return {"exists": True, "corrupt": False, "policy": pol["data"],
            "path": tool_paths(tool)["policy"]}


# 审计读取（控制台审计页）
def read_audit(tool=None, limit=200):
    """读最近 limit 条审计（新的在前）。文件不存在返回 []。

    实现：按字节从文件尾部倒读（审计会持续增长，不整文件读入）。
    """
    try:
        limit = max(1, min(int(limit), 2000))
    except (TypeError, ValueError):
        limit = 200
    path = AUDIT_LOG
    try:
        f = open(path, "rb")
    except OSError:
        return []
    with f:
        try:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            data = b""
            need_lines = limit * 3 + 1          # 过滤 tool 后仍够 limit 条
            max_bytes = 4 * 1024 * 1024         # 尾部最多读 4MB，防超大行拖死
            while pos > 0 and data.count(b"\n") < need_lines \
                    and len(data) < max_bytes:
                step = min(65536, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
        except OSError:
            return []
    items = []
    for raw in data.split(b"\n"):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        if tool and rec.get("tool") != tool:
            continue
        items.append(rec)
    items.reverse()
    return items[:limit]


# 供安装自检/测试使用
__all__ = [
    "gate_ssh", "gate_db", "is_sudo_command", "sql_required_level",
    "sql_targets", "sql_scan", "count_statements", "strip_sql_tail",
    "audit", "redact", "read_policy", "write_policy", "default_policy",
    "effective_ssh_policy", "effective_db_policy", "policy_summary",
    "fingerprint", "list_approvals", "get_approval", "approve", "reject",
    "iter_approvals", "read_audit", "tool_paths", "policy_present",
    "policy_warnings", "AUDIT_LOG",
    "BINDCONSOLE_HOME", "LEVELS", "LEVEL_RANK",
]
