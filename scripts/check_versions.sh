#!/usr/bin/env bash
set -euo pipefail

FILES="$(rg --files -g'Cargo.toml')"
if echo "$FILES" | xargs rg 'version\s*=\s*"\^'; then
  echo "Found non-pinned versions"
  exit 1
fi
