# sshbind

`sshbind add NAME --host HOST [--user USER] [--port PORT]` 首次认证后安装专用公钥。
默认交互输入密码；也可用 `--identity PATH` 或 `--agent` 首次认证。
已有私钥的口令可用 `--identity-passphrase-stdin` 从 stdin 读入。

`sshbind adopt NAME --host HOST --identity PATH` 只纳管并验证既有密钥，不向远端推送公钥。
支持 `--certificate PATH`；缺省会查找 `<private-key>-cert.pub`。
CLI adopt 引用原路径，请保留原私钥；Web 粘贴导入会在受管 keys 目录保存一份。

```bash
sshbind list --json
sshbind show demo-server --json
sshbind test demo-server
sshbind doctor
sshbind exec --json demo-server 'uptime'
```

exec 的 JSON 包含 alias/host/user/command/exit_code/stdout/stderr/duration_ms；远端退出码透传。
`--json`、超时等选项放在别名之前。若直接使用 OpenSSH，带 `-o BatchMode=yes` 以免卡在密码提示。

FinalShell 先预览：`sshbind import finalshell`；明确执行密码型连接迁移才加 `--with-passwords`。
软件只从用户本机的 FinalShell 配置读取凭据，用于首次认证；不要把配置提交到仓库。
密钥型连接可使用 adopt，避免重新安装已有公钥。

`sshbind remove NAME` 可能吊销远端公钥，属于有副作用的管理操作；务必确认目标与备用登录方式。
不要由 agent 擅自移除连接或使用破坏性选项。不要手工修改 `~/.ssh/config` 的 sshbind 托管块。

Web 中的 sudo=allow/ask/deny 通过策略守卫作用于 exec；默认无策略时保持原兼容行为。
它不能撤销 root 账号本身的权限，也不能代替 sudoers。

## 无需删除别名的凭据维护

Web 编辑允许更新 host/user/port、登录密码或私钥。登录密码仅用于安装替换公钥，不修改远端密码。
验证成功才保存连接；旧本机和远端密钥保留，不自动吊销。sudo 密码为独立的仅写入字段，保存到运行 BindKit 本机的系统钥匙串。
安装可选依赖：`bash install.sh --with-integrations`。字段留空不修改，显式清除会删除对应钥匙串项。

```bash
sshbind exec --json --as-user app demo-server 'id'
sshbind exec --json --as-user root demo-server 'id'
```

普通身份须位于服务器允许列表并解析出普通 UID，才可免身份审批；root/敏感/未知身份和嵌套命令仍审批。
受管理 sudo 会在实际密码提示时代输；NOPASSWD/认证缓存不发送密码。TTY/MFA 和复杂交互形式不支持自动认证。
`--stdin` 显式启用命令输入；选项仍在别名前。执行状态未知时禁止自动重试。

服务器页「导入连接」先预览 Xshell `.xsh`/普通 ZIP、FinalShell SSH JSON 或 OpenSSH config，选择条目后补充凭据。
不恢复受保护 `.xts` 容器或加密密码，不读取引用密钥文件、不执行代理/本地命令、不覆盖现有别名。
更多步骤见 [管理说明](administration.md)。
