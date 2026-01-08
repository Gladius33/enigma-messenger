# Upgrades and rolling changes

- Review `MIGRATIONS.md`, `COMPATIBILITY.md`, and `RELEASE.md` before touching production systems.
- Verify the release artifacts: `cd dist && sha256sum -c SHA256SUMS`, then inspect `manifest.json` for the expected crate versions and target.
- Compare your configs against `enigma-cli print-default-config` output; new releases may add fields such as `[api]` for the UI bind address. Keep the daemon UI on loopback unless explicitly exposed.
- Stage config changes under `/etc/enigma/`, fix ownership to `root:enigma`, and rerun `enigma-cli doctor --config /etc/enigma/daemon.toml` before restarting services.
- Run `enigma-cli migrate --dry-run --config /etc/enigma/daemon.toml` and apply with `--apply --yes` when required.
- For single-node restarts: `systemctl daemon-reload && systemctl restart enigma-node-registry enigma-relay enigma-daemon`, then run `deployment/smoke.sh`.
- In multi-node setups, upgrade one host at a time: drain clients from the relay, restart the registry and daemon on that host, confirm health, then move to the next node.
