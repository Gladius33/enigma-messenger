#!/usr/bin/env bash
set -euo pipefail

for doc in API.md MIGRATIONS.md COMPATIBILITY.md; do
  if [ ! -f "$doc" ]; then
    echo "Missing $doc"
    exit 1
  fi
done

grep -q "API.md" README.md
grep -q "MIGRATIONS" README.md
grep -q "COMPAT" README.md
