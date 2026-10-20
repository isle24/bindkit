# Security policy

Supported release: 1.1.x. See [security model](docs/security-model.md) before using policy gates.

Report a suspected vulnerability privately through the repository's GitHub **Security → Report a vulnerability**
when available. Do not paste real credentials, private keys, connection state or production logs into issues.
Provide a minimal reproduction using temporary files and synthetic credentials.

This release contains source and generated distribution checksums only, never a maintainer's connection state.
Do not commit `~/.ssh/sshbind`, `~/.dbbind`, `~/.bindconsole`, `.env` files or database dumps.
