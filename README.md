# BindKit

[![CI](https://github.com/isle24/bindkit/actions/workflows/ci.yml/badge.svg)](https://github.com/isle24/bindkit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/isle24/bindkit)](https://github.com/isle24/bindkit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**把 SSH 和数据库连接绑定为别名，让你和 AI agent 使用同一套 CLI、Web 管理与人工审批。**

BindKit is a local SSH/database alias manager with JSON output, web consoles and human approvals.
It runs on macOS and Linux with Python 3.9+; the core has no pip dependencies.

| 工具 | 用途 |
|---|---|
| `sshbind` | 密码/已有私钥/SSH agent 首次认证，生成或纳管密钥，FinalShell 导入，远程执行 |
| `dbbind` | MySQL、PostgreSQL、SQLite；配置文件管理；结构查询、SQL 执行、导出 |
| Web 控制台 | 分别管理服务器/数据库、权限策略、一次性审批和审计 |

## 一键安装

需要 **Python 3.9+、OpenSSH（ssh / ssh-keygen）、curl**。支持 macOS/Linux；不需要 sudo。

```bash
curl -fsSL https://github.com/isle24/bindkit/releases/latest/download/install.sh | bash
```

安装器会下载同一版本的发行包、校验 SHA-256，再安装到当前用户目录。
已有连接、私钥、密码、策略、审批和管理密码保持不变；替换已有程序前会在旁边留下备份。
首次安装不会替你配置连接或创建管理密码。

默认命令放在 `~/.local/bin`。如果 shell 找不到命令，加入 PATH：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

也可以先下载、阅读再执行：

```bash
curl -fL https://github.com/isle24/bindkit/releases/latest/download/install.sh -o install-bindkit.sh
less install-bindkit.sh
bash install-bindkit.sh
```

安装指定版本 / 从源码安装：

```bash
curl -fsSL https://github.com/isle24/bindkit/releases/download/v1.0.0/install.sh | bash
# 或下载/clone 本仓库后：
bash install.sh
```

升级时重新执行安装命令，然后重启已打开的控制台。自定义位置支持：
`bash install.sh --bin-dir "$HOME/bin" --console-dir "$HOME/.bindconsole"`。
更改 console-dir 后，运行工具时也需设置 `BINDCONSOLE_HOME` 为该路径。
SHA-256 检查检测下载损坏，不等同于独立签名；来源信任仍依赖 GitHub HTTPS 和本仓库发布权限。

## 快速开始

先开本机 Web 后台，在页面中设置管理密码并导入连接：

```bash
sshbind --startserver --open    # http://127.0.0.1:8790
dbbind --startserver --open     # http://127.0.0.1:8791
```

两个后台可同时运行，资源分开管理，共用管理密码。任一后台登出会使两边旧会话失效。
Ctrl-C 关闭前台服务；需要后台运行可加 `--daemon`，PID/日志位于 `~/.bindconsole/run/`。

也可以通过 CLI 绑定服务器，密码在终端交互输入：

```bash
sshbind add demo-server --host server.example.com --user deploy
# 已有私钥：只登记与验证，不重新向服务器安装公钥
sshbind adopt existing-server --host server.example.com --user deploy --identity ~/.ssh/id_ed25519
sshbind list --json
sshbind exec --json demo-server 'uname -a'
```

`sshbind exec` 的选项放在别名前；远端退出码原样返回。
Web 粘贴导入的私钥会保留在 `~/.ssh/sshbind/keys/`，不能作为临时文件清理。
更多认证、证书和 FinalShell 迁移说明见 [SSH 使用指南](docs/sshbind.md)。

数据库连接建议编辑 `~/.dbbind/config.json`，使用环境变量引用密码：

```json
{
  "version": 1,
  "defaults": {"read_only": true, "limit": 1000},
  "databases": {
    "demo-mysql": {
      "engine": "mysql", "host": "db.example.com", "port": 3306,
      "user": "app_reader", "password": "$DEMO_MYSQL_PASSWORD", "database": "appdb"
    }
  }
}
```

密码由本人使用安全的终端或密钥管理方式设置，不要粘贴到聊天、命令历史或 Git。
连接 MySQL/PostgreSQL 需有 `mysql`/`psql` 客户端；SQLite 需 `sqlite3`。
客户端环境变量：`DBBIND_MYSQL` / `DBBIND_PSQL` / `DBBIND_SQLITE3`。

```bash
dbbind config validate --json
dbbind list --json
dbbind tables demo-mysql --json
dbbind exec --json demo-mysql 'SELECT 1 AS ok'
dbbind export --json --format csv --out result.csv demo-mysql 'SELECT 1 AS ok'
```

JSON 的 `rows` 是二维数组；超限时 `truncated:true`，应收紧查询或显式调整 `--limit`。
`--out` 默认导出完整结果；`--limit 0` 返回零行用于探测，不表示不限量。
数据库配置优先级与三种通道见 [数据库指南](docs/dbbind.md)。

## 权限与人工审批

数据库默认只读。明确授权的 DML 使用单次 `--write`；DDL/高危操作使用单次 `--unsafe`。
Web 策略进一步限制 sudo、最大 SQL 等级、库/表/schema 白名单和审批要求。

| 退出码 | 含义 | 处理 |
|---|---|---|
| 3（db） | 原只读/DDL 守卫拦截 | 确认操作与用户授权 |
| 5 | `AUTHZ_DENIED` / `SUDO_DENIED` | 停止；由管理员调整策略 |
| 6 | `APPROVAL_REQUIRED` | 打开提示中的地址审批，再原样重试一次 |

DB 审批绑定引擎、实际默认库和 SQL；切换库不能复用原批准。
`export` 与 `exec` 使用相同策略。完整规则见 [安全与策略说明](docs/security-model.md)。

**策略识别是协作守卫，不是隔离沙箱。** 能改本地策略/调用原生客户端的进程仍有操作系统权限；
生产隔离应同时使用独立数据库账号、sudoers 和独立 OS 用户。SQL 识别有保守误报，不能作为完整 SQL 解析器。
CLI 未配置 policy.json 时 SSH 保持兼容行为；需要限制时请先在控制台保存策略。

## 从另一台电脑临时导入

```bash
sshbind --startserver --host 0.0.0.0
dbbind --startserver --host 0.0.0.0
```

终端会打印局域网地址，首次设置需输入终端的一次性 setup token。
LAN 使用 HTTP 明文；在可信网络短时使用，导入后关闭。默认仅监听回环，不支持公网部署或多用户权限隔离。

## 提供给 AI agent

将 [AGENT.md](AGENT.md) 的约定加入你的项目提示词。安装器也会在两个工具目录中创建指引，已有指引不覆盖。

> 使用 sshbind/dbbind 别名和 JSON 输出。只使用 usable:true 的连接。数据库写入先获授权。
> 收到 rc=5 停止报告；rc=6 告知 request_id，等本人批准后原样重试一次。不得自行批准或绕过策略。

## 数据位置与卸载

| 路径 | 内容 |
|---|---|
| `~/.local/bin/sshbind`、`dbbind` | CLI 程序 |
| `~/.bindconsole/lib/`、`web/` | Web 内核与静态资源 |
| `~/.ssh/sshbind/` | 服务器记录、密钥、SSH 策略与审批 |
| `~/.dbbind/` | 数据库配置/状态、策略、审批与指引 |
| `~/.bindconsole/secret.json`、`audit.log` | 管理密码哈希/会话材料与审计 |
| `~/.local/share/bindkit/` | 版本、安装回执、指引和卸载器 |

数据库配置中的明文密码只受本机文件权限保护，建议环境变量引用并限制文件权限。
`secret.json` 保存密码哈希与随机会话签名材料，不保存管理密码明文。

```bash
python3 "$HOME/.local/share/bindkit/uninstall.py"
```

卸载仅移除与安装回执校验值相符的程序文件，保留数据和用户修改过的文件。
不会吊销远端公钥、删除数据库或删除用户凭据；旧程序备份也会保留。

## 开发与验证

```bash
python3 scripts/test.py
python3 scripts/check_release.py
python3 scripts/build_release.py
```

测试使用隔离 HOME、临时 SQLite 和假 SSH 传输，不访问维护者真实设施。
CI 在 Linux/macOS 执行测试；支持范围与版本记录见 [CHANGELOG.md](CHANGELOG.md)。
核心不依赖 pip；FinalShell 密码迁移需要可用 DES 后端（cryptography、pycryptodome 或支持 DES 的 OpenSSL）。
暂不支持原生 Windows。发布包不含个人连接、密钥、数据库文件、截图和运行日志。

## License

[MIT](LICENSE)。安全问题请见 [SECURITY.md](SECURITY.md)。
