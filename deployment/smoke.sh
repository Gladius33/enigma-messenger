#!/bin/sh
set -eu

fail() {
  echo "smoke: $*" >&2
  exit 1
}

DAEMON_BIN="${ENIGMA_DAEMON_BIN:-enigma-daemon}"
CLI_BIN="${ENIGMA_CLI_BIN:-enigma-cli}"
CURL_BIN="${CURL_BIN:-curl}"
CONFIG_PATH="${ENIGMA_CONFIG:-/etc/enigma/daemon.toml}"
HEALTH_URL="${ENIGMA_HEALTH_URL:-http://127.0.0.1:9171/api/v1/health}"

command -v "$DAEMON_BIN" >/dev/null 2>&1 || fail "missing enigma-daemon binary: $DAEMON_BIN"
command -v "$CLI_BIN" >/dev/null 2>&1 || fail "missing enigma-cli binary: $CLI_BIN"
command -v "$CURL_BIN" >/dev/null 2>&1 || fail "missing curl binary: $CURL_BIN"

"$DAEMON_BIN" --version >/dev/null 2>&1 || fail "enigma-daemon --version failed"
"$CLI_BIN" --version >/dev/null 2>&1 || fail "enigma-cli --version failed"

[ -f "$CONFIG_PATH" ] || fail "config not found: $CONFIG_PATH"

status=0

doctor_out="$("$CLI_BIN" doctor --config "$CONFIG_PATH" --json 2>&1)" || {
  echo "smoke: doctor failed: $doctor_out" >&2
  status=1
}

health_ok=0
if [ "${ENIGMA_UI_TOKEN:-}" = "" ]; then
  health_out="$("$CURL_BIN" -sSf "$HEALTH_URL" 2>&1)" && health_ok=1 || {
    echo "smoke: health check failed: $health_out" >&2
    status=1
  }
else
  health_out="$("$CURL_BIN" -sSf -H "Authorization: Bearer $ENIGMA_UI_TOKEN" "$HEALTH_URL" 2>&1)" && health_ok=1 || {
    echo "smoke: health check failed: $health_out" >&2
    status=1
  }
fi

if [ "$health_ok" -eq 1 ]; then
  echo "$health_out" | grep -q "\"status\"" || {
    echo "smoke: health response missing status" >&2
    status=1
  }
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "smoke: ok"
