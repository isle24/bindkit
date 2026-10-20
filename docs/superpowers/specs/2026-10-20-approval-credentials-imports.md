# BindKit approval, credentials and administration extension

User approved the preceding design on 2026-10-20 and selected OS keychain storage for sudo passwords. Additional authorized requirements: paginated audit UI, editing SSH passwords/private keys without deleting aliases, and importing Xshell-like session files.

## Binding requirements

- Keep existing CLI behavior and JSON envelopes when new features are disabled. SSH options precede the alias. All tests use temporary HOME, fake transports and synthetic credentials; never read or modify the maintainer's real credentials or authorization state.
- Store sudo passwords and model API keys in the OS keychain through a mature keyring backend. Configuration stores references only. If unavailable/locked, fail explicitly; no plaintext-file fallback and no secret values in argv, logs, API responses or audit.
- Managed `--as-user USER` requests carry explicit target identity. Allowlisted, positively resolved ordinary users may skip identity approval; UID 0, sensitive/unresolved targets and nested privilege operations remain checked. Actual OS authorization/authentication is always required.
- Sudo approval and authentication are separate phases. A managed SSH runner handles a sudo password prompt before execution, keeps password out of command stdin when authentication is cached/NOPASSWD, emits a trusted execution-start marker, and reports unknown execution states without automatic replay.
- AI approval is off by default, explicitly configured by the human per SSH/database alias. It cannot override hard deny, maximum privilege, resource restrictions or existing DML/DDL flags. It uses an independent model call without execution tools or executor conversation history. Only redacted request data leaves the machine.
- AI decisions are strict approve/reject/human records, one use and a bounded lifetime. Timeout, invalid response, unavailable credentials/provider or changed policy/request context falls back to human review. Human and AI decisions race through the existing atomic approval store; late decisions cannot overwrite completed/denied requests.
- Closing the web page must not disable configured review processing. A private per-user background review worker handles queued requests; CLI may await its decision within a bounded duration and proceed in the same invocation.
- Bind approval to the immutable command/SQL execution plan, connection/target identity and policy revision. Authentication failures known to precede execution must not silently consume an approval; ambiguous remote failures must not trigger automatic retries.
- Audit uses actual requester/decider identities. Add server-side pagination/filtering with stable snapshots and bounded memory; keep legacy `entries`/limit callers compatible.
- Credential editing retains alias and policy. Verify replacement keys/connection before committing local state; keep old keys until explicit revocation. Editing the stored login credential must not change the remote account's password. Sudo password is a separate field.
- Import is preview-first, size-bounded, path-safe and duplicate-aware. Xshell .xsh/ZIP containers, FinalShell JSON and OpenSSH config metadata are supported initially. Do not execute imported commands, read referenced private-key paths, or claim encrypted Xshell passwords were recovered. Unsupported protected containers report an actionable limitation.
- Add usable settings/forms, loading/empty/error states and mobile-safe navigation. Preserve the current framework and visual system. Do not expose stored secrets through edit prefills.
- Package every shipped module in the explicit release allowlist; preserve user state during installation/upgrades. Optional keyring/model SDK runtime must be isolated from system Python. Do not publish runtime databases, keychain data, fixtures or screenshots.

## Component contracts

`bindkit_vault.py`: `Vault.status() -> {available, backend, reason}`, `get(ref)`, `set(ref, value)`, `delete(ref)`, and generated opaque references. Backend injection is available to tests only through constructors.

`bindkit_privilege.py`: `build_plan(command, login_user, as_user=None, allowed_users=(), uid_resolver=None) -> dict`; `execute_plan(ssh_module, server, plan, vault, stdin_data=None, timeout=120) -> dict` with `exit_code/stdout/stderr/started/authenticated/error`. Plan includes `command`, `target_user`, `target_uid`, `managed`, `approval_exempt`, `requires_approval`, and canonical fingerprint context. Simple legacy sudo/su forms may normalize into managed plans; unsupported complex forms never get rewritten silently.

`bindkit_connections.py`: safe public credential status and `update_connection(ssh_module, name, body, vault=None) -> dict`; login password is only used to re-establish key access, private-key replacement is verified before state update, sudo password is keychain-only. No policy editing in this module; root integration owns combined request validation.

`bindkit_ai.py`: public configuration, keychain credential references, model listing/testing, deterministic eligibility and redaction, provider adapter, `review_and_decide(tool, request_id, context, policy_module, timeout=20) -> dict`, background worker start/stop/status. Context includes command/SQL, fingerprint and trusted resource/identity metadata; provider output cannot grant new scope. Background job context is redacted, bounded and expires; no secret values are persisted there. Provider/SDK and vault can be injected for isolated tests. Worker process must use installed/source interpreter/module path, private per-user runtime and a single-instance lock.

`bindkit_catalog.py`: `read_audit_page(path, tool='all', page=1, page_size=50, actor=None, decision=None, alias=None, snapshot=None) -> {entries,total,page,page_size,pages,has_next,has_prev,snapshot}`. A runtime SQLite index may incrementally index complete JSONL lines and handle rotation/truncation. Index permissions are 0600. Snapshot paging remains stable across newly appended records.

`bindkit_imports.py`: `parse_import_files(files, format='auto', reserved_names=()) -> {items,warnings,count}`. Input is a list of `{name,content}` with bytes content. Public items contain `id/name/host/port/user/source/auth_type/requires_credentials/key_hint/warnings`; never raw password/private-key/encrypted-password fields. Imported SSH options such as ProxyCommand/LocalCommand are not executed. Preview itself has zero connection/state side effects.

## Integration ownership

Root owns changes to existing sshbind/dbbind entrypoints, policy module, console routes, frontend, installer/runtime integration, release allowlist, documentation and whole-system tests. Delegated implementers own only their specified new modules and tests. No agent changes the real installation or pushes/releases while implementation is incomplete.
