# Changelog

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
