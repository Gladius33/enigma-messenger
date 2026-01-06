# Migrations and store versions

Store versioning
- `identity`: latest `2` (v2 bundles). Legacy v1 identities are detected but not auto-upgraded.
- `sessions`: latest `1` (ratchet state seed derivation v1).
- `outbox`: latest `2` (version-tagged queued items).
- Versions are recorded under `store:versions` inside the encrypted store.

Workflow
- Detect: `enigma-cli doctor --config /etc/enigma/daemon.toml --json` reports detected versions and whether a migration is pending.
- Dry run: `enigma-cli migrate --config /etc/enigma/daemon.toml` inspects versions without writing.
- Apply: `enigma-cli migrate --config /etc/enigma/daemon.toml --apply --yes` stamps `store:versions` and upgrades outbox entries to the latest version when possible. Identity/session upgrades are rejected if unsupported.
- All commands support `--json` for machine-readable output; use `ENIGMA_UI_TOKEN` if UI auth is enabled so health checks succeed.

Operator playbook
- Before upgrading binaries, run the dry-run migration and doctor commands.
- After applying migrations, restart services (registry, relay, daemon) and confirm `/api/v1/health`.
- If legacy identities (v1) are present, plan a re-provisioning cutover; the CLI will refuse to auto-upgrade those entries.
