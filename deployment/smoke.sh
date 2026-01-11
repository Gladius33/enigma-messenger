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
TMP_BODY="$(mktemp)"

cleanup() {
  rm -f "$TMP_BODY"
}

trap cleanup EXIT

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

health_request() {
  token="${1:-}"
  if [ -n "$token" ]; then
    if code="$("$CURL_BIN" -s -o "$TMP_BODY" -w "%{http_code}" -H "Authorization: Bearer $token" "$HEALTH_URL" 2>&1)"; then
      health_code="$code"
      health_body="$(cat "$TMP_BODY")"
      return 0
    fi
  else
    if code="$("$CURL_BIN" -s -o "$TMP_BODY" -w "%{http_code}" "$HEALTH_URL" 2>&1)"; then
      health_code="$code"
      health_body="$(cat "$TMP_BODY")"
      return 0
    fi
  fi
  echo "smoke: health check failed: $code" >&2
  status=1
  return 1
}

health_body=""
health_code=""
if [ "${ENIGMA_UI_TOKEN:-}" = "" ]; then
  if health_request ""; then
    if [ "$health_code" != "200" ]; then
      echo "smoke: health expected 200, got $health_code" >&2
      status=1
    elif ! echo "$health_body" | grep -q "\"status\""; then
      echo "smoke: health response missing status" >&2
      status=1
    fi
  fi
else
  if health_request ""; then
    if [ "$health_code" != "401" ]; then
      echo "smoke: unauth health expected 401, got $health_code" >&2
      status=1
    elif ! echo "$health_body" | grep -q "UNAUTHORIZED"; then
      echo "smoke: unauth health missing UNAUTHORIZED error" >&2
      status=1
    fi
  fi
  if health_request "$ENIGMA_UI_TOKEN"; then
    if [ "$health_code" != "200" ]; then
      echo "smoke: auth health expected 200, got $health_code" >&2
      status=1
    elif ! echo "$health_body" | grep -q "\"status\""; then
      echo "smoke: auth health response missing status" >&2
      status=1
    fi
  fi
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "smoke: ok"
