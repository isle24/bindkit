# Changelog

## v1.3.0 — 2026-10-30

- Make Web password connections authenticate directly with the saved password, without installing public keys or requiring successful key authentication. Key-based connections and explicit CLI key bootstrap remain available.
- Store login passwords only in the OS keychain and transport credentials through a private in-memory askpass broker; helper files, argv, environment and command stdin contain no password.
- Support password connection create/edit/test/exec, deferred activation, identity discovery and managed sudo with the existing policy/approval protections.
- Verify against a real loopback SSH server that accepts passwords and rejects all public keys; no authorized-key installation is performed.
- Force fresh password authentication during connection checks; an existing OpenSSH multiplexed connection cannot bypass verification of a replacement password.
- Keep database SSH and Docker-over-SSH routes restricted to native key aliases; reject password-only and pending managed aliases instead of resolving an unrelated native SSH alias.
- Explicit password bootstrap enables password/keyboard-interactive authentication and overrides inherited BatchMode for that invocation; explicit key-passphrase bootstrap also allows prompting. Normal key execution retains BatchMode=yes.
- Preserve literal special characters without additional escaping; add genuine loopback OpenSSH password, keyboard-interactive, child stdin, edit and pending-activation regression coverage.
- Distinguish password authentication, remote authorized-key installation and subsequent key verification errors in the console and batch imports. Error messages use fixed allowlisted codes and never reflect credential/remote diagnostic text.
- Make hostname/user metadata probes best-effort so minimal Linux images do not turn a successful key login into a failed connection test; explicitly enable public-key authentication for managed-key connections.
- Report observed group/other-writable home directories when key verification fails, without modifying home permissions or disabling server security checks.

## v1.2.0 — 2026-10-28

- Expand session import to multiple files, folders and ordinary ZIP/.xts exports: up to 1024 sessions and 16 MiB, sequential ten-row progress and per-row results.
- Reuse supported Xshell saved passwords with an explicitly supplied master password or original Windows identity, using PyCryptodome and digest verification where available. Public previews never return plaintext or ciphertext passwords.
- Retain imported login credentials and unrecovered encrypted descriptors in the OS keychain; add a write-only unlock action for later recovery.
- Offer explicit deferred registration after a failed attempt. Pending connections stay unusable until a later connection test succeeds; offline registration and cipher unlock do not access remote servers.
- Refresh an already enabled optional runtime when its dependency manifest changes; retain old code/runtime for recovery.
- Add isolated parser, cipher, HTTP, lifecycle and UI regressions. Real user session files and credentials are excluded from tests and release files.

## v1.1.1 — 2026-10-21

- Fix saving local model connections over HTTP to private LAN IPs (RFC1918 and IPv6 ULA), while retaining HTTPS requirements for public/unknown hosts.
- Distinguish invalid model URLs, HTTPS requirements and keychain write failures in the console instead of returning one misleading generic error.
- Add isolated configuration/API regressions and validate a real local OpenAI-compatible provider through model discovery, connection testing and strict approval JSON output. Real credentials and endpoints are excluded from source and fixtures.

## v1.1.0 — 2026-10-21

- Add managed `--as-user` SSH execution and prompt-aware sudo authentication through the local OS keychain.
- Add a verified ordinary-user allowlist; root, sensitive/unresolved identities and nested privilege operations remain checked.
- Bind approvals to connection/identity/policy context, reserve managed execution atomically, release proven pre-start failures and prevent duplicate execution past the authorization TTL.
- Add independent scoped AI suggest/auto review, strict bounded decisions, private background jobs, cancellation and manual fallback. Security configuration operations remain human-reviewed.
- Add server-side audit pagination, exact filters, totals and stable snapshots with a private incremental offset index.
- Edit SSH connection details, login credentials, private keys and separate sudo credentials without deleting aliases; verify replacements and retain old keys.
- Add preview/selection/import for Xshell `.xsh` and ordinary ZIP, FinalShell SSH JSON and OpenSSH config metadata. Protected vendor containers/passwords require manual credentials.
- Add isolated optional keyring/model SDK installation via `--with-integrations`, preserving the dependency-free core and existing user state.
- Refresh unmodified installer-managed agent guides on upgrade while retaining handwritten/edited instructions.
- Extend authenticated APIs, mobile forms, agent instructions, installation and isolated regression coverage.

Validation uses temporary HOME, synthetic SSH/model/keyring transports and local browsers. Real NAS sudoers/PAM/TTY and human keychain configuration require separate acceptance; this release does not claim that verification.

## v1.0.0 — 2026-10-19

First public release of sshbind, dbbind and the local web consoles under the MIT license.

- SSH aliases, password/key/agent bootstrap, existing-key/certificate adoption and FinalShell import.
- MySQL/PostgreSQL/SQLite aliases with layered configuration, JSON queries, schema inspection and export.
- Separate SSH and database web consoles, sudo/SQL policy gates, human approvals and audit.
- Temporary LAN import with first-setup token protection.
- Fixed imported key persistence, policy fields lost during creation, SQLite path editing,
  export/database-override policy checks, cross-database approval reuse, target parsing and common secret redaction.
- Added state-preserving user-level installation, code backups, rollback, checksum validation and safe code-only uninstall.
- Removed environment-specific examples and release data; added portable isolated tests and CI.
- The SSH web console invokes its own CLI executable, including custom installation directories.
- Numeric-IP console binding and local interface discovery do not depend on DNS resolution.

Platforms: macOS/Linux with Python 3.9+ and OpenSSH. Database clients are installed separately.
No native Windows support, public hosting, multi-user isolation or independent release signatures.
