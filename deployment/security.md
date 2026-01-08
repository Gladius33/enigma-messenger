# Operational security hardening

## Secrets and key material
- UI API bearer token: set `ENIGMA_UI_TOKEN` via `/etc/enigma/enigma-daemon.env` (0600, root:enigma). Rotate by updating the file and restarting the daemon.
- Master key material: set `ENIGMA_MASTER_KEY_HEX` (32-byte hex) or `ENIGMA_MASTER_KEY_PATH` (file containing 32-byte hex). Keep files `0600` and owned by root. Do not embed keys in configs or scripts.
- Dev vs prod separation: the daemon falls back to a deterministic key only for development and tests. Production deployments must always provide a real master key via `ENIGMA_MASTER_KEY_HEX` or `ENIGMA_MASTER_KEY_PATH`.
- Registry envelope keys and pepper values in `registry.toml` are placeholders in templates; generate real keys for production.

## Network exposure and TLS
- The UI API binds to `127.0.0.1` by default. Keep it on loopback and expose it only behind a reverse proxy.
- Config validation rejects non-loopback UI binds unless `ui-auth` is enabled and `ENIGMA_UI_TOKEN` is set.
- For outbound registry/relay connections, set `mode = "tls"` and use `https://` URLs. Provide `tls.ca_cert`, `tls.client_cert`, and `tls.client_key`; config validation rejects insecure combinations.
- Pin internal CAs by storing a dedicated CA bundle and referencing it via `tls.ca_cert`.

## Reverse proxy (TLS termination)
Nginx (example)
```
location /api/v1/ {
  proxy_pass http://127.0.0.1:9171;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header Authorization $http_authorization;
  proxy_read_timeout 30s;
  proxy_send_timeout 30s;
}
```

Caddy (example)
```
route /api/v1/* {
  reverse_proxy 127.0.0.1:9171 {
    header_up Authorization {>Authorization}
    header_up X-Forwarded-For {>X-Forwarded-For}
    header_up X-Forwarded-Proto {>X-Forwarded-Proto}
  }
}
```

## Abuse resistance and limits
- Policy limits are enforced by enigma-core and configured in `daemon.toml`:
  - `max_message_rate_per_minute`
  - `max_text_bytes`, `max_inline_media_bytes`
  - `max_attachment_chunk_bytes`, `max_attachment_parallel_chunks`
- UI API DTOs are strict and reject unknown fields; errors return the stable JSON envelope defined in `API.md`.

## Logging and auditability
- Configure log level in `[logging].level` and rely on journald for retention.
- Recommended journald retention settings: `SystemMaxUse`, `SystemMaxFileSize`, and `MaxRetentionSec` in `/etc/systemd/journald.conf`.
- Avoid logging secrets or tokens; store any audit exports outside `/var/lib/enigma`.

## Backup and restore
- Stop `enigma-daemon` before backup: `systemctl stop enigma-daemon`.
- Use `deployment/backup.sh` to capture `/var/lib/enigma/daemon` and store the checksum alongside the archive.
- Restore with `deployment/restore.sh`, then run `enigma-cli doctor --config /etc/enigma/daemon.toml` and `enigma-cli migrate --dry-run` before restarting.
