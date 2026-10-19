# Release procedure

1. Update VERSION, CHANGELOG.md, install.sh's embedded VERSION and component version constants together.
2. Run `python3 scripts/test.py`, `python3 scripts/check_release.py` and an independent secret scanner.
   Tests use isolated state and must not read or import a maintainer's credentials.
3. Review `git diff --check`, tracked filenames and `release-files.txt`. Never stage runtime directories or local reports.
4. Run `python3 scripts/build_release.py`; inspect the archive, MANIFEST.json and SHA256SUMS.
5. Install the built archive in a temporary HOME, test both CLIs and an installed web console, then clean up that temporary HOME.
6. Commit, push main and wait for the Linux/macOS CI matrix to pass for that exact commit.
7. Tag that commit, push the tag, and publish a GitHub release with the matching archive, install.sh and SHA256SUMS.
8. Download the **published** standalone install.sh into a directory without a source checkout; execute it with a temporary HOME.
   Verify the remote checksum path, installed version, empty alias lists and web startup.
9. Compare the remote tag/commit and downloaded asset hashes with the tested local artifacts before announcing success.

Checksums protect against transfer corruption. They are not an independent publisher signature.
Do not silently replace release assets after publication; fix release problems in a new version.
