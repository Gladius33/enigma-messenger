#!/usr/bin/env bash
set -euo pipefail

required_files=(
  deployment/single-node-prod.md
  deployment/local-dev.md
  deployment/upgrade.md
  deployment/smoke.sh
  deployment/check_systemd_hardening.md
  deployment/security.md
  deployment/backup.sh
  deployment/restore.sh
)

for doc in "${required_files[@]}"; do
  if [ ! -f "$doc" ]; then
    echo "Missing $doc"
    exit 1
  fi
done

runbook="deployment/single-node-prod.md"
grep -q "^# Single node production" "$runbook"
grep -q "^## Preparation" "$runbook"
grep -q "^## User and group" "$runbook"
grep -q "^## Directory layout" "$runbook"
grep -q "^## Install binaries" "$runbook"
grep -q "^## Config" "$runbook"
grep -q "^## Secrets" "$runbook"
grep -q "^## Systemd units" "$runbook"
grep -q "^## Firewall" "$runbook"
grep -q "^## Verification" "$runbook"
grep -q "^## Smoke test" "$runbook"
grep -q "^## Upgrades" "$runbook"
grep -q "MIGRATIONS.md" "$runbook"
grep -q "COMPATIBILITY.md" "$runbook"
grep -q "RELEASE.md" "$runbook"
grep -q "deployment/security.md" "$runbook"

security_doc="deployment/security.md"
grep -q "^# Operational security hardening" "$security_doc"
grep -q "^## Secrets and key material" "$security_doc"
grep -q "^## Network exposure and TLS" "$security_doc"
grep -q "^## Reverse proxy" "$security_doc"
grep -q "^## Abuse resistance and limits" "$security_doc"
grep -q "^## Logging and auditability" "$security_doc"
grep -q "^## Backup and restore" "$security_doc"

grep -q "deployment/single-node-prod.md" README.md
grep -q "deployment/security.md" README.md
grep -q "deployment/backup.sh" README.md
grep -q "deployment/restore.sh" README.md
grep -q "deployment/smoke.sh" RELEASE.md
