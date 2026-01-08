#!/usr/bin/env bash
set -euo pipefail

required_files=(
  deployment/single-node-prod.md
  deployment/local-dev.md
  deployment/upgrade.md
  deployment/smoke.sh
  deployment/check_systemd_hardening.md
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

grep -q "deployment/single-node-prod.md" README.md
grep -q "deployment/smoke.sh" RELEASE.md
