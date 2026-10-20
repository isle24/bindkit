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
Managed SSH approvals bind command, connection identity/revision, target user/UID and policy revision.
DB approvals bind engine, actual default database, SQL, connection identity and policy revision.
Credential or connection changes invalidate earlier approvals. Never automatically repeat a command
whose execution state is unknown; report it for human investigation.

For an approved identity switch use `sshbind exec --json --as-user app <alias> 'id'`.
Only positively resolved ordinary users explicitly allowed in that alias's policy can skip identity approval.
UID 0, sensitive/unresolved identities and nested privilege operations still require policy checks.
The operating system must authorize the switch. Configure sudo credentials through the console's
write-only field; credentials are stored in the local OS keychain, separately from the login credential.
Do not pass sudo passwords through command arguments, command stdin, chat or configuration files.

Independent AI review is off by default. The human may configure it in the AI settings page with
explicit SSH/database alias scopes. Auto mode may approve a pending eligible request within the same
CLI invocation; suggest mode always leaves the final decision to the human. It never overrides a deny,
database privilege ceiling, resource whitelist or required --write/--unsafe flags. A provider failure,
timeout or stale context returns to manual approval. The executing agent must not approve its own request,
enable AI review, expand scope or alter protected security configuration to bypass a gate.

SSH credential edits preserve aliases and policy. A login password is used to install/verify a replacement
public key, not to change the remote account password. Old keys remain until an explicit revocation.
Session import requires a preview and explicit selection. Xshell .xsh/ordinary ZIP, FinalShell JSON and
OpenSSH config import connection metadata; vendor-encrypted passwords are not recovered. Never execute
imported ProxyCommand/LocalCommand, read referenced key paths, or overwrite an existing alias implicitly.

Audit responses include server-side page counts and a snapshot token. Keep that token across pages;
HTTP 409 means the log snapshot expired and the user should reload page one. A page is not the full history.

Start local consoles with `sshbind --startserver` (8790) or `dbbind --startserver` (8791).
Expose LAN only at the user's request, with `--host 0.0.0.0`; close the server after import.
First-time LAN setup requires the terminal's one-time token. Imported keys under `~/.ssh/sshbind/keys/`
are persistent credentials, not disposable temporary files.

For development, run `python3 scripts/test.py`. Tests must use isolated HOME directories and synthetic state.
Do not access a developer's real servers, databases, credentials or approvals during tests.
