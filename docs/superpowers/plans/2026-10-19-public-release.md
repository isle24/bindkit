# BindKit v1.0.0 release plan

Approved scope: publish `bindkit` as a public MIT-licensed GitHub repository, including both CLIs, the web console, documentation, and a one-command installer. Never publish personal credentials or runtime data.

1. Import an explicit allowlist of program files into a new repository. Replace personal paths, host examples and aliases with documentation-only examples. Do not import local configuration, databases, reports, screenshots, keys or session history.
2. Write failing installer tests for a clean install, repeat install, upgrade backups, state preservation and failure rollback. Implement a user-level macOS/Linux installer, without sudo or shell-profile edits. Remote bootstrap must verify the release archive checksum and reject unsafe archive members before extraction.
3. Add README, component guides, configuration and policy examples, agent instructions, security boundaries, changelog, MIT license and contributor test commands.
4. Package the distribution from a checked-in allowlist, write a SHA-256 manifest and add tests that inspect both Git-tracked files and the release archive. Exclude runtime data even if it is accidentally present in the checkout.
5. Run isolated CLI, policy, HTTP and installer tests; review the release changes. Inspect tracked files and archives with allowlists and secret scanning without reading personal credentials.
6. Initialize Git, create the approved public repository, push the verified commit and tag, publish v1.0.0 with archive/checksums/installer, then download the published installer and validate the actual one-command installation in a temporary HOME.
7. Verify the remote commit, release assets and GitHub CI result. Deliver the repository, release and exact install command.

The archive and installer are tested locally before publication. Existing personal installations are not replaced as part of release validation.
