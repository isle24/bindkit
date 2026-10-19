# Development and release rules

Read `AGENT.md` for end-user agent behavior. This repository contains program source only.

- Never commit runtime state, personal configuration, databases, credentials, keys, logs or test output.
- Keep all tests in temporary HOME directories. Never connect to real infrastructure in CI.
- Run `python3 scripts/test.py` and `python3 scripts/check_release.py` before release.
- Package only `release-files.txt` entries with `python3 scripts/build_release.py`.
- Installer updates may replace shipped code, but must preserve user configuration and credentials.
- Release notes must state what was actually tested; do not imply native Windows support.
