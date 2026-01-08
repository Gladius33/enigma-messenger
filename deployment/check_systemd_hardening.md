# Systemd hardening validation

## Checklist
- Units run as `User=enigma` and `Group=enigma`.
- `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, and `ProtectSystem=strict`.
- `ProtectKernelLogs=yes`, `ProtectKernelModules=yes`, `ProtectKernelTunables=yes`.
- `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
- `SystemCallFilter=@system-service @network-io`.
- `CapabilityBoundingSet=` and `AmbientCapabilities=` are empty.
- `UMask=0077`, `StateDirectory=enigma`, `ConfigurationDirectory=enigma`, and `ReadWritePaths=/var/lib/enigma /var/log/enigma`.

## Validation commands
- `systemd-analyze verify /etc/systemd/system/enigma-daemon.service`
- `systemd-analyze security enigma-daemon.service`
- `systemctl show enigma-daemon -p User -p Group -p ProtectSystem -p NoNewPrivileges`

## Runtime directory checks
- `/etc/enigma` exists and is `root:enigma` with `0750`.
- `/var/lib/enigma` exists and is `enigma:enigma` with `0750`.
- `/var/lib/enigma/daemon` exists and is `enigma:enigma` with `0700`.
- `/var/log/enigma` exists only if file logging is used.
