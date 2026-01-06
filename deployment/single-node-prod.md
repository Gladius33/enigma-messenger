# Single node production

Preparation
- Create a locked-down user for all services: `useradd --system --home /var/lib/enigma --shell /usr/sbin/nologin enigma`.
- Place configs under `/etc/enigma/` using the templates in `deployment/etc/enigma/`. Keep registry/relay bound to loopback or an internal address and switch to `mode = "tls"` only when cert/key paths are populated.
- TLS endpoints must provide `tls.ca_cert`, `tls.client_cert`, and `tls.client_key`; the daemon refuses TLS configs without those paths.
- Ensure `/var/lib/enigma` exists and is owned by `enigma:enigma` with 0750 permissions; the systemd units will create it when absent.
- Prefer journald; `/var/log/enigma/` is created by the units if you need file logs.

Systemd units
- Copy `systemd/enigma-daemon.service`, `systemd/enigma-relay.service`, and `systemd/enigma-node-registry.service` to `/etc/systemd/system/`.
- Enable and start in order: `systemctl daemon-reload`, `systemctl enable --now enigma-node-registry.service enigma-relay.service enigma-daemon.service`.
- Environment overrides can be placed in `/etc/enigma/enigma-*.env`; config paths default to `/etc/enigma/*.toml`.

Firewall
- Allow only the registry and relay listener ports (default 9000 and 9100) from trusted peers. Keep the daemon UI API on `127.0.0.1:9171` and block it externally.
- Example (ufw): `ufw allow 9000/tcp`, `ufw allow 9100/tcp`, deny everything else inbound. The same policy applies with nftables: accept tcp dport {9000,9100} from allowed CIDRs and drop the rest.

Verification
- Run `enigma-cli doctor --config /etc/enigma/daemon.toml` as root or the enigma user to confirm config validity, permissions on `/var/lib/enigma`, and `/api/v1/health` reachability.
- If UI auth is enabled, export `ENIGMA_UI_TOKEN` before running the doctor command so the health check can authenticate.
- Check `systemctl status` for each unit and review journald logs for startup errors (TLS path issues, bind failures, or permission denials).
