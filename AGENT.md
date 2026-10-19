# BindKit agent instructions

Discover aliases with `sshbind list --json` and `dbbind list --json`; use only `usable:true` entries.
Run remote commands with `sshbind exec --json <alias> '<command>'`; place options before the SSH alias.
Run SQL with `dbbind exec --json <alias> 'SELECT ...'`. Rows are ordered arrays; check `truncated` before interpreting totals.

Never read or print passwords/private keys, connection strings or unmasked configuration.
Let the user import credentials in the web console or edit their configuration directly.
Do not add/remove real connections or revoke keys without explicit user instructions.

Database access is read-only by default. Use `--write` only for explicitly authorized data changes;
DDL requires separate explicit authorization and `--unsafe`. Policy limits still apply.
`export` is also checked; `--database` uses the actual target database. Do not use another alias or client to evade policy.

For rc=5 (`AUTHZ_DENIED` / `SUDO_DENIED`), stop and report the error.
For rc=6 (`APPROVAL_REQUIRED`), give the user the request ID and approval URL, wait for their decision,
then retry the identical command once. Do not approve requests or edit policy/approval files yourself.
DB approvals bind engine, actual default database and SQL.

Start local consoles with `sshbind --startserver` (8790) or `dbbind --startserver` (8791).
Expose LAN only at the user's request, with `--host 0.0.0.0`; close the server after import.
First-time LAN setup requires the terminal's one-time token. Imported keys under `~/.ssh/sshbind/keys/`
are persistent credentials, not disposable temporary files.

For development, run `python3 scripts/test.py`. Tests must use isolated HOME directories and synthetic state.
Do not access a developer's real servers, databases, credentials or approvals during tests.
