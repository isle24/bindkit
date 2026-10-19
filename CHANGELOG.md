# Changelog

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
