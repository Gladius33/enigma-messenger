# Single node production

This is the canonical runbook for a minimal single-host deployment (registry + relay + daemon on one host). The UI API stays on 127.0.0.1 by default and should only be exposed behind a reverse proxy.

## Preparation
- Ensure systemd, curl, and the Enigma binaries are installed on the host.
- Decide whether the registry and relay are co-hosted or remote; update the daemon config accordingly.
- Review `deployment/security.md` for secrets, TLS, logging, and backup guidance.

## User and group
- Create a locked-down service account: `groupadd --system enigma` and `useradd --system --home /var/lib/enigma --shell /usr/sbin/nologin --gid enigma enigma`.
- Keep configs owned by `root:enigma` and data owned by `enigma:enigma`.

## Directory layout
- `/etc/enigma/` for configs and environment files (0750, root:enigma).
- `/var/lib/enigma/daemon` for daemon state (0700, enigma:enigma).
- `/var/lib/enigma/registry` and `/var/lib/enigma/relay` when co-hosted (0700, enigma:enigma).
- `/var/log/enigma/` optional if you enable file logging; journald is preferred.

## Install binaries
- Verify the release artifacts: `cd dist && sha256sum -c SHA256SUMS`.
- Copy binaries into `/usr/local/bin/` and set permissions: `install -m 0755 enigma-daemon /usr/local/bin/enigma-daemon` and `install -m 0755 enigma-cli /usr/local/bin/enigma-cli`.
- If co-hosting registry/relay, install `enigma-node-registry` and `enigma-relay` the same way.
- Confirm versions: `enigma-daemon --version` and `enigma-cli --version`.

## Config
- Copy templates from `deployment/etc/enigma/` to `/etc/enigma/`.
- Update `daemon.toml` `data_dir`, `identity.user_handle`, and `registry/relay` base URLs for your deployment.
- Keep `[api].bind_addr = "127.0.0.1:9171"` unless you front it with a reverse proxy.
- Ensure config files are `0640` and owned by `root:enigma`.

## Secrets
- Replace the placeholder `pepper_hex` and `envelope.keys` values in `registry.toml` with real keys; never ship the template values.
- If you enable TLS for registry/relay, switch `mode = "tls"` and provide all required certificate paths; the daemon refuses TLS configs without them.
- Set UI API auth token in `/etc/enigma/enigma-daemon.env` as `ENIGMA_UI_TOKEN=...` and keep the file `0640 root:enigma`.
- Provide the storage master key via `ENIGMA_MASTER_KEY_HEX` or `ENIGMA_MASTER_KEY_PATH` (32-byte hex) and keep it `0600 root:enigma`.

## Systemd units
- Copy `systemd/enigma-daemon.service`, `systemd/enigma-node-registry.service`, and `systemd/enigma-relay.service` to `/etc/systemd/system/`.
- Create optional environment files: `/etc/enigma/enigma-daemon.env`, `/etc/enigma/enigma-node-registry.env`, `/etc/enigma/enigma-relay.env`.
- Reload and start services: `systemctl daemon-reload` then `systemctl enable --now enigma-node-registry enigma-relay enigma-daemon`.
- If registry/relay are remote, disable their units and set `enabled = false` or remote URLs in `daemon.toml`.
- Validate hardening with `deployment/check_systemd_hardening.md`.

## Firewall
- Allow only registry and relay listener ports (default 9000 and 9100) from trusted peers.
- Keep the UI API on `127.0.0.1:9171`; block it externally.

## Verification
- Check service status and logs: `systemctl status enigma-daemon` and `journalctl -u enigma-daemon -n 200`.
- Run `enigma-cli doctor --config /etc/enigma/daemon.toml` (export `ENIGMA_UI_TOKEN` and `ENIGMA_MASTER_KEY_HEX`/`ENIGMA_MASTER_KEY_PATH` as needed).
- Validate migrations: `enigma-cli migrate --dry-run --config /etc/enigma/daemon.toml`, apply with `--apply --yes` when required.
- Hit the UI health endpoint: `curl -sSf http://127.0.0.1:9171/api/v1/health`.

## Smoke test
- Run `deployment/smoke.sh` after services are up: `ENIGMA_CONFIG=/etc/enigma/daemon.toml deployment/smoke.sh`.
- If UI auth is enabled: `ENIGMA_UI_TOKEN=... ENIGMA_CONFIG=/etc/enigma/daemon.toml deployment/smoke.sh`.

## Upgrades
- Review `MIGRATIONS.md`, `COMPATIBILITY.md`, and `RELEASE.md` before upgrading.
- Verify the new release checksums, back up `/var/lib/enigma`, and run `enigma-cli migrate --dry-run`.
- Stop services, replace binaries/configs, run `systemctl daemon-reload`, then start `enigma-node-registry`, `enigma-relay`, and `enigma-daemon`.
- Re-run `enigma-cli doctor` and `deployment/smoke.sh` after the upgrade.
- Use `deployment/backup.sh` and `deployment/restore.sh` for repeatable backups and restores.
