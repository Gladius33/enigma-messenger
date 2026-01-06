# Upgrades and rolling changes

- Verify releases with the published `SHA256SUMS` from `dist/` and prefer the `x86_64-unknown-linux-musl` artifacts. Keep an offline copy of `BUILDINFO.json` for provenance.
- Compare your configs against `enigma-cli print-default-config` output; new releases may add fields such as `[api]` for the UI bind address. Keep the daemon UI on loopback unless explicitly exposed.
- Stage config changes under `/etc/enigma/`, fix ownership to `enigma:enigma`, and rerun `enigma-cli doctor --config /etc/enigma/daemon.toml` before restarting services.
- For single-node restarts: `systemctl daemon-reload && systemctl restart enigma-node-registry enigma-relay enigma-daemon`. Verify `/api/v1/health` and relay/registry liveness before re-opening traffic.
- In multi-node setups, upgrade one host at a time: drain clients from the relay, restart the registry and daemon on that host, confirm health, then move to the next node.
