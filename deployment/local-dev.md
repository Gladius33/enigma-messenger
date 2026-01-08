# Local development

- Canonical production runbook: `deployment/single-node-prod.md`.
- Use the templates under `deployment/etc/enigma/` as a starting point. For local testing, replace `/var/lib/enigma` paths with a writable temp directory.
- Generate the daemon template from the binary when installed: `enigma-cli print-default-config --service daemon`.
- Run the registry and relay from crates.io with the provided `registry.toml` and `relay.toml` templates, keeping the loopback addresses and HTTP mode.
- Start the daemon locally with `cargo run -p enigma-daemon -- --config <path-to-daemon-config>`. The UI API listens on `127.0.0.1:9171` by default and exposes `/api/v1/health`.
- Validate configs and permissions with `enigma-cli doctor --config <path>` and ensure the health check passes before exercising the UI API contract tests.
