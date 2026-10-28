# Import reliability implementation plan

Goal: complete the user-authorized batch, credential reuse and explicit offline-add workflow described in the companion spec. Use subagent-driven-development for separate components; root reviews contracts and integrates them. Python 3.9+; all test data synthetic, all HOME directories temporary, no real server imports.

- [x] Parser/crypto: add failing tests for encrypted Xshell variants, master/SID batch context, >64 files, .xts ZIP, wrong context/integrity, and secret-free public output. Implement optional mature ARC4 backend, private credential sink and bounded 1024/16MiB parsing. Do not edit admin/SSH/UI.
- [x] SSH pending lifecycle: add failing tests for offline registration without SSH, keychain-only credentials, encrypted-secret preservation, inactive state, duplicate rejection and later activation. Implement create_unverified callback and pending test promotion; preserve existing strict create unless explicitly opting in. Do not edit admin/parser/UI.
- [x] UI: implement folder/multiple files/16MiB selection, batch unlock fields, recovered-password statuses, chunks of ten commits/progress and explicit deferred-add confirmation. Tests must cover failure/cancel/retry and secrets clearing. Do not edit backend.
- [x] Root APIs: authenticated large-preview-only body cap, private preview credential store, server-side credential merge, strict deferred-add flag and per-row results. Add HTTP regressions for secret nonreflection, multi-file size, explicit confirmation and failed-row retries.
- [x] Integration: optional crypto dependency/runtime installation, explicit release files, agent/user docs, full portable gate, independent review and synthetic browser acceptance. Install only code locally; preserve actual records and never import user sessions during automated testing.
- [ ] Release: new version only, privacy/source/history scans, built archive acceptance, exact-commit CI and published installer verification under existing release instructions.

Local acceptance (2026-10-28): all six portable gates passed with optional crypto installed (223 unittest cases, 196 policy assertions, 20 acceptance regressions, 52 handler assertions, 66 console integration assertions and 107 backend cases). Independent review findings fixed: empty-key deletion, false unlock success and pending metadata validation mismatch.

Real browser acceptance used a synthetic .xts with 25 sessions: 23 verified imports, 2 explicit deferred additions, cancellation creates no pending records, wrong-master failure remains visible, later unlock and explicit test activation succeed. No real user session or server was imported. External CI/release results are recorded in release notes.
