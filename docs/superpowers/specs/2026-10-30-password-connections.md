# Genuine password SSH connections

The user explicitly wants the program to connect using the supplied password without requiring server permission changes. Password entry must no longer implicitly install authorized keys and require key authentication.

- Web create/import with password defaults to `auth_type: password`. Verify through password authentication and a harmless marker command, store the password only in OS keychain, and register usable state after verification. Do not create/upload public keys or modify remote permissions/configuration.
- Existing key records remain key records; CLI `sshbind add` retains its explicitly documented key bootstrap behavior. An explicit `auth_type:key` API request may retain that compatibility path, but the ordinary password form never sends it.
- Password records have `key:''`, `login_credential_ref`, `auth_type:password`, installed/verification status indicating connection readiness. Only verified records with an appropriate credential reference are usable. Public output exposes auth_type/has_login_credential, never secrets/references.
- Add, edit, deferred verification, CLI list/show/test/exec and managed sudo must work for password records. Editing an active password connection verifies the replacement before committing; failures preserve previous state. Existing password-less pending records remain pending until credentials and verification are available.
- Password connections use OpenSSH with bounded explicit password/KBI authentication. Login passwords travel through a private memory-backed askpass broker, never plaintext files, argv, logs or command stdin. SSH host-key checking remains accept-new/pinned. Keep command stdin/stdout/stderr/exit-code behavior.
- Replace the legacy SecretHandle plaintext temporary file with the same memory broker. Temporary helper scripts contain only IPC paths/code. The broker must close and delete owned resources deterministically.
- Managed sudo uses its existing approval/nonce handshake; caller supplies transport `(argv, env)` when using password login. Login password and sudo password remain independent. Bind auth_type/credential reference into approval identity context.
- Native `ssh <alias>` cannot retrieve BindKit keychain passwords; password connections use `sshbind exec`. No fake identity file or host policy changes.
- All automated acceptance uses temporary HOME, fake vault and loopback SSH. Critical test: server accepts a special-character password and rejects all public keys; create/test/exec still succeed with zero key-install commands.

Module contracts:

- `bindkit_askpass.MemoryAskpass(secret)` has env(), close(), context protocol, `.dir`; stdlib-only Unix-socket broker.
- `bindkit_password.is_password(server)`: explicit password mode, or keyless record with login/encrypted credential reference. Existing keyed records never auto-convert.
- `bindkit_password.transport(ssh_module, server, vault=None)` yields `(base_ssh_argv_without_command, env)` with an in-memory askpass context.
- `bindkit_password.run(ssh_module, server, command, stdin_data=None, timeout=120, vault=None)` returns `(rc,stdout,stderr)`.
- `bindkit_password.test(ssh_module, server, vault=None)` returns `(bool, details)`; only a harmless success-marker command.
- `bindkit_password.create(ssh_module, body, vault=None)` and `update(ssh_module,name,body,vault=None)` safely commit keychain references and state/policy through existing helpers, no remote key installation.
- `bindkit_privilege.execute_plan(..., transport=None)` accepts optional `(argv,env)`; existing default key transport remains compatible.
