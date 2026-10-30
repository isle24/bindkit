# dbbind

数据库的 SSH/Docker-over-SSH 通道使用原生 OpenSSH，须选择密钥别名。BindKit 密码连接通过 `sshbind exec` 取用钥匙串凭据；这类别名不会被静默当作系统 SSH 别名执行。

引擎：mysql/postgres/sqlite。配置文件支持 JSONC 注释、尾随逗号及环境变量 `$VAR` / `${VAR}`；
`$$` 表示字面 `$`。未知字段会产生 warnings；先运行 `dbbind config validate` 排查拼写。

优先级从低到高：引擎默认值 → `~/.dbbind/config.json` → 当前目录向上找到的首个 `.dbbind.json`
→ `~/.dbbind/databases.json`（CLI/Web 添加）→ `$DBBIND_CONFIG` / `--config PATH`。
以字段为单位合并。示例见 [dbbind.example.json](../examples/dbbind.example.json)。

执行通道：

- local：本机 mysql/psql/sqlite3。
- ssh：`via_ssh` 指定已绑定的 SSH 别名，远端 PATH 需有相应数据库客户端。
- docker：`docker_exec` 格式为容器名或 `SSH别名:容器名`，客户端在容器内运行。

MySQL/PostgreSQL 密码经环境变量（本地）或 stdin（SSH/Docker）传递，不进入客户端 argv。
配置示例只含环境变量引用；不要用明文密码作为 CLI 参数。

```bash
dbbind config path --json
dbbind config validate --json
dbbind list --json
dbbind dbinfo demo-mysql --json
dbbind databases demo-mysql --json
dbbind tables demo-mysql --json
dbbind columns demo-mysql users --json
dbbind schema demo-mysql --json
dbbind exec --json --limit 100 demo-mysql 'SELECT 1 AS ok'
dbbind exec --json --database analytics demo-mysql 'SELECT 1 AS ok'
dbbind export --json --format jsonl --out rows.jsonl demo-mysql 'SELECT 1 AS ok'
```

`list` 的 `config_files` 是路径字符串数组。详细候选文件存在/可读状态看 `config path`。
`usable` 表示配置/客户端具备使用条件，实际连通性仍需 `test` 验证。

`exec --json` 的 `columns` 保持列顺序，`rows` 为二维数组；SQL NULL 保留为 JSON null。
`returned` 是返回行数。截断时 `row_count=limit+1` 是下界，`row_count_exact=false`，不能当总数。
默认 stdout 上限 1000（可配置）；`--out` 不传 limit 则完整导出；`--limit 0` 只探测有无结果。
`--timeout SEC` 限制客户端执行时间。大结果应落盘，批量读应合并 SQL，避免逐条新建连接。

客户端元命令（psql 反斜杠命令、SQLite 点命令）一律禁用；用内置结构命令替代。
默认拒绝 DML/DDL；`--write` 只放 DML，`--unsafe` 才放高危。配置 `read_only:false` 会放松原守卫，
Web 策略仍可限制最大等级及审批。

配置文件来源的连接只能在原文件修改/删除；Web 可以修改其策略。
Web 创建的连接参数可编辑，密码留空表示保留；SQLite file 的修改会实际保存。
