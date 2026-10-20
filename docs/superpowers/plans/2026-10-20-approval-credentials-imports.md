# BindKit administration extension implementation plan

Goal: implement the approved privilege/authentication/AI workflow and the three additional administration requirements without touching personal runtime state.

Architecture: optional modules own vault/privilege execution, independent AI review, audit indexing and session parsing. Existing entrypoints remain adapters. Root integrates routes and the existing vanilla JS frontend after each module's focused tests pass.

Global constraints: all requirements in `../specs/2026-10-20-approval-credentials-imports.md` are binding. Python 3.9+, macOS/Linux, no real infrastructure or credentials in tests. Secrets use OS keychain only. Disabled features preserve old behavior. All shipped files are explicitly allowlisted.

## Task 1: credential vault, managed identity and key rotation

Write scope: new `bindconsole/bindkit_vault.py`, `bindconsole/bindkit_privilege.py`, `bindconsole/bindkit_connections.py`, and focused `tests/test_vault.py`, `tests/test_privilege.py`, `tests/test_connections.py` only.

- [x] Read the spec and existing SSH helpers; record failing tests before implementation.
- [x] Implement `Vault` with injected test backend, real keyring backend only, opaque references and masked availability. Test missing/locked backend and deletion, never real keychain access.
- [x] Implement `build_plan` for structured as-user and simple sudo/su/runuser forms. Test normal target allowlist, UID 0 aliases, unresolved/dynamic target, nested commands and unsupported interactive switches.
- [x] Implement prompt-aware `execute_plan`, a nonce-bound execution marker and bounded Popen transport. Test prompt-required authentication, NOPASSWD/cache with no password forwarding, stdin preservation, wrong/locked credentials, timeouts and unknown execution state. Password must never appear in command arguments or returned diagnostics.
- [x] Implement transactional key/connection edits with synthetic SSH module/transport. Test preserving old state/key on failed validation, no implicit remote account password changes, separate sudo credential reference, and stable alias/policy.
- [x] Report exact APIs, focused red/green evidence and concerns. Do not edit shared entrypoints or commit unrelated files.

## Task 2: automatic AI review and worker

Write scope: new `bindconsole/bindkit_ai.py`, optional new `bindconsole/bindkit_reviewd.py`, `tests/test_ai.py` only.

- [x] Use the spec's `Vault` contract; dependency-inject a fake vault/provider in tests while Task 1 runs.
- [x] Write failing tests for disabled/suggest/auto modes, alias scopes, hard-deny/unsafe overrides, protected configuration operations, provider outage/malformed output, secret redaction and one-use decisions.
- [x] Implement public configuration and private credential references. Model listing/testing use an optional mature OpenAI-compatible SDK with timeouts/retries bounded and no execution tools.
- [x] Implement `review_and_decide` with policy/context snapshot checks, strict output schema and atomic existing-store decisions. Decisions persist actual `decided_by=ai`; root will correct common audit actor handling.
- [x] Implement private background jobs and single-worker lifecycle independent of a web page. Redacted payloads expire, network calls hold no approval lock, and cancellation/manual decisions win over late model responses.
- [x] Test worker subprocess lifecycle with local synthetic provider, request reuse, duplicate workers and stale context. Do not read real configuration or call an external model.
- [x] Report APIs, test evidence and root integration requirements.

## Task 3: audit pagination and safe session parsing

Write scope: new `bindconsole/bindkit_catalog.py`, `bindconsole/bindkit_imports.py`, `tests/test_audit_paging.py`, `tests/test_imports.py` only.

- [x] Write audit tests for >1000 events, filters, invalid page/page_size, empty data, append-stable snapshots, partial final lines, corrupt lines and log rotation/truncation.
- [x] Implement the specified page response with bounded memory and a 0600 incremental runtime index; no whole-log response disguised as pagination.
- [x] Write synthetic Xshell INI UTF-8/UTF-16, session ZIP, FinalShell JSON and OpenSSH config samples inline in tests. Test protocol rejection, encrypted credential omission, duplicates, archive traversal/links/bombs and hostile SSH commands.
- [x] Implement preview-only parsing and stable safe candidate IDs; unknown protected .xts containers must explain that individual .xsh/ordinary ZIP exports are needed. Do not invent decryption support.
- [x] Report accepted formats, field shapes, exact tests and known vendor-format limits.

## Task 4: integration, UI and packaging (root)

- [x] Validate module APIs against the spec; read diffs and run relevant focused tests before connecting adapters.
- [x] Extend SSH state/public records and policy for sudo credential refs, ordinary-user allowlists, target context and per-operation approval reservation. Add managed execution CLI flags and integrate AI queue/wait with existing return codes.
- [x] Add authenticated/CSRF-checked APIs for AI settings/model test/service status, safe credential edits, user discovery and session preview/commit. Keep public endpoints secret-free and import confirmation explicit.
- [x] Replace audit list limit with actual page/filter/snapshot metadata while retaining `entries` and legacy limit callers.
- [x] Extend the current app with pagination controls, write-only credential fields, preview/selection/import results, and AI configuration/status. Verify loading, errors, secrets clearing and mobile layout in a real browser.
- [x] Add optional isolated keyring/model SDK runtime to installer; core install stays usable without it and missing optional integrations report a clear action. Preserve existing code/state upgrade guarantees.
- [x] Update explicit release files, README/agent/security docs and regression coverage; no personal examples or runtime artifacts may be committed.

## Task 5: acceptance and review

- [x] Run focused tests, the complete portable suite and privacy scans. Run meaningful browser flows against the real kernel and synthetic handlers.
- [x] Request independent whole-branch review; fix material findings and re-run affected checks.
- [x] Keep real zspace sudo acceptance distinct: it requires the human to configure the keychain password through the completed UI. Never obtain it from chat, old sessions or configuration.
- [x] Deliver a concrete testable branch and truthful verification boundaries; do not silently replace the published v1.0.0 assets.

## Local acceptance evidence (2026-10-21)

- Complete portable gate: 158 unittest cases, 196 policy assertions, 20 acceptance regressions, 52 handler assertions, 66 console integration assertions, and 107 backend cases; zero failures/skips in the gate.
- Real browser against the HTTP kernel and synthetic handlers: 1440/768/390 widths, audit snapshot paging/filtering, SSH identity/secret forms, missing-user import rejection, duplicate prevention and retry, AI settings and missing-runtime states.
- Optional runtime actually built in a temporary HOME on Python 3.9.6; fixed SDK imports, both installed CLI launchers and empty alias lists passed. No real vault or model call.
- Built archive installed into a fresh temporary HOME: both CLI/web consoles, version, authentication, paged audit and AI settings passed.
- Independent review findings fixed with failing-then-passing regressions: lost transport marker, stale execution leases, failed approval locks, protected-operation parsing, changed DB/SSH transport context, missing import user and partially failed credential imports.
- Source/filename privacy scan and independent Gitleaks directory/history scans found no leaks.
- Real NAS/PAM/sudoers/keychain acceptance remains separate and requires human configuration through the completed console.
