#!/usr/bin/env bash
#
# End-to-end test for dsh-pairing-gate's standalone front door.
#
# The production dsh at 192.0.2.10:3080 is never touched or restarted. Its
# launch token is printed only at boot; if this host's journal no longer holds
# that line (the case when this test was written), the script starts a
# throwaway dsh web instance with an isolated DSH_HOME and the same TLS
# certificate, then proxies to it. Supply DSH_TOKEN_URL to test a real,
# already-running dsh instead:
#
#   DSH_TOKEN_URL='https://192.0.2.10:3080/?token=...' \
#   E2E_UPSTREAM='https://192.0.2.10:3080' bash tests/e2e-standalone.sh
#
# Requirements: node >= 22, curl, openssl, system TLS cert/key below.
# The gateway listens on 127.0.0.1:3456 only. State lives in ./.test-state and
# is removed at the end (set E2E_KEEP=1 to keep logs, still sanitized on print).

set -Eeuo pipefail
umask 077

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$PWD
STATE="$ROOT/.test-state"
TMP="$ROOT/.test-tmp/e2e"
DSH_HOME="$ROOT/.test-dsh-home"
HOST=127.0.0.1
GATE_PORT=3456
DSH_PORT=3099
BASE="https://$HOST:$GATE_PORT"
# A second, completely fresh gateway instance for the v0.5.0 WebUI setup
# wizard. It uses its own stateDir so the main 18-step scenario above stays
# untouched (and still bootstraps through the adminKey path). Since v0.6.1 it
# listens on this host's LAN address: network settings refuse loopback and the
# setup instance is the one used for the live rebind scenarios.
GATE_PORT_SETUP=3458
# v0.6.0 network settings: temporary port for the live-rebind scenario. The
# same process moves 3458 -> 3459 -> 3458, so no extra gateway is started.
GATE_PORT_SETUP_TMP="${E2E_REBIND_PORT:-3459}"
STATE_SETUP="$ROOT/.test-state-setup"
# v0.6.1: damaged network.json must fall back to the bundle config, not fail
# silently (or refuse to start).
GATE_PORT_FALLBACK="${E2E_FALLBACK_PORT:-3460}"
STATE_FALLBACK="$ROOT/.test-state-fallback"
CERT="${E2E_CERT:-/opt/deepseekharness/config/tls/dsh.crt.pem}"
KEY="${E2E_KEY:-/opt/deepseekharness/config/tls/dsh.key.pem}"
USERNAME=admin
PASSWORD='E2E-Test-Password-2026'
NEW_PASSWORD='E2E-Test-Password-2026-NEW'
WRONG_PASSWORD='Definitely-Wrong-Password-2026'
PAIR_TTL=10
# Session-channel admin requests must look like a real (non-loopback) LAN
# client, otherwise the loopback channel would short-circuit authorization and
# currentPassword/CSRF would never be exercised. Binding the source address of
# this host's NIC while still connecting to 127.0.0.1 achieves that without
# touching firewall rules or binding another port.
SOURCE_IP="${E2E_SOURCE_IP:-}"
SETUP_HOST=''
BASE_SETUP=''
BASE_SETUP_TMP=''

GW_PID=''
GW_SETUP_PID=''
GW_FALLBACK_PID=''
DSH_PID=''
CLEANED=0
KEEP_LOGS="${E2E_KEEP:-0}"

redact() {
  sed -E \
    -e 's/([?&]token=)[A-Za-z0-9_-]+/\1<redacted>/g' \
    -e 's/[0-9a-f]{64}/<hex64-redacted>/g' \
    -e 's/(dsh_gate_(session|device|csrf)=)[^;[:space:]]+/\1<redacted>/g' \
    -e 's/(auth-gate: generated admin key )[0-9a-f]+/\1<redacted>/g'
}

show_logs() {
  if [ -f "$TMP/gateway.log" ]; then
    echo "--- gateway log (sanitized tail) ---" >&2
    tail -n 40 "$TMP/gateway.log" | redact >&2 || true
  fi
  if [ -f "$TMP/gateway-setup.log" ]; then
    echo "--- setup gateway log (sanitized tail) ---" >&2
    tail -n 40 "$TMP/gateway-setup.log" | redact >&2 || true
  fi
  if [ -f "$TMP/gateway-fallback.log" ]; then
    echo "--- fallback gateway log (sanitized tail) ---" >&2
    tail -n 40 "$TMP/gateway-fallback.log" | redact >&2 || true
  fi
  if [ -f "$DSH_HOME/dsh.log" ]; then
    echo "--- temporary dsh log (sanitized tail) ---" >&2
    tail -n 20 "$DSH_HOME/dsh.log" | redact >&2 || true
  fi
}

cleanup() {
  [ "$CLEANED" = 1 ] && return
  CLEANED=1
  set +e
  if [ -n "$GW_PID" ]; then
    kill "$GW_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$GW_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$GW_PID" 2>/dev/null
    wait "$GW_PID" 2>/dev/null
  fi
  if [ -n "$GW_SETUP_PID" ]; then
    kill "$GW_SETUP_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$GW_SETUP_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$GW_SETUP_PID" 2>/dev/null
    wait "$GW_SETUP_PID" 2>/dev/null
  fi
  if [ -n "$GW_FALLBACK_PID" ]; then
    kill "$GW_FALLBACK_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$GW_FALLBACK_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$GW_FALLBACK_PID" 2>/dev/null
    wait "$GW_FALLBACK_PID" 2>/dev/null
  fi
  if [ -n "$DSH_PID" ]; then
    kill "$DSH_PID" 2>/dev/null
    for _ in $(seq 1 40); do kill -0 "$DSH_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$DSH_PID" 2>/dev/null
    wait "$DSH_PID" 2>/dev/null
  fi
  if [ "$KEEP_LOGS" != 1 ]; then
    rm -rf "$STATE" "$STATE_SETUP" "$STATE_FALLBACK" "$TMP" "$DSH_HOME"
  else
    rm -rf "$STATE" "$STATE_SETUP" "$STATE_FALLBACK"
    echo "E2E_KEEP=1: logs kept under $TMP and $DSH_HOME (not part of the package)" >&2
  fi
}

on_exit() {
  local code=$?
  if [ "$code" -ne 0 ]; then
    show_logs
  fi
  cleanup
  exit "$code"
}
trap on_exit EXIT

fail() {
  echo "E2E FAIL: $*" >&2
  exit 1
}

step() {
  printf '\n== %s ==\n' "$*"
}

pass() {
  printf 'PASS: %s\n' "$*"
}

assert_eq() {
  local actual=$1 expected=$2 what=$3
  [ "$actual" = "$expected" ] || fail "$what: expected [$expected], got [$actual]"
}

assert_file_contains() {
  local file=$1 needle=$2 what=$3
  grep -qF -- "$needle" "$file" || fail "$what: $file does not contain the expected text"
}

assert_file_lacks() {
  local file=$1 needle=$2 what=$3
  ! grep -qF -- "$needle" "$file" || fail "$what: $file unexpectedly contains the text"
}

json_get() {
  node tests/e2e-helpers.mjs json "$1" "$2"
}

get_csrf() {
  local jar=$1
  curl -sk --max-time 10 -c "$jar" -b "$jar" "$BASE/__auth/csrf" -o "$TMP/csrf.json" -w '%{http_code}'
}

get_csrf_at() {
  # base jar out; used for the independent setup instance on a different port.
  local base=$1 jar=$2 out=$3
  curl -sk --max-time 10 -c "$jar" -b "$jar" "$base/__auth/csrf" -o "$out" -w '%{http_code}'
}

wait_for_https() {
  # url attempts -> 0 when the endpoint answers HTTP 200
  local url=$1 attempts=${2:-40} code=000
  for _ in $(seq 1 "$attempts"); do
    code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)
    [ "$code" = "200" ] && return 0
    sleep 0.25
  done
  return 1
}

port_is_listening() {
  local port=$1
  command -v ss >/dev/null 2>&1 || return 1
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -q ":$port\$"
}

login_request() {
  # jar csrf password out headers [source-interface]
  # v0.4.0: the device cookie is the second factor; login sends no TOTP.
  local jar=$1 csrf=$2 password=$3 out=$4 headers=$5 iface=${6:-}
  local curl_args=(-sk --max-time 30 -D "$headers" -o "$out" -w '%{http_code}')
  if [ -n "$iface" ]; then curl_args+=(--interface "$iface"); fi
  E2E_USERNAME="$USERNAME" E2E_PASSWORD="$password" \
    node tests/e2e-helpers.mjs login-json "$TMP/login-payload.json"
  curl "${curl_args[@]}" \
    -c "$jar" -b "$jar" -X POST "$BASE/__auth/login" \
    -H 'content-type: application/json' -H "x-auth-gate-csrf: $csrf" \
    --data-binary @"$TMP/login-payload.json"
}

request_qr() {
  local out=$1
  curl -sk --max-time 30 -o "$out" -w '%{http_code}' -X POST "$BASE/__admin/api/qr" \
    -H "x-auth-gate-admin-key: $ADMIN_KEY" -H 'content-type: application/json' --data-binary '{}'
}

redeem_ticket() {
  # ticket jar out [name] [platform]
  local ticket=$1 jar=$2 out=$3 name=${4:-e2e-android} platform=${5:-android}
  E2E_TICKET="$ticket" E2E_DEVICE_NAME="$name" E2E_PLATFORM="$platform" \
    node tests/e2e-helpers.mjs redeem-json "$TMP/redeem-payload.json"
  curl -sk --max-time 30 -o "$out" -w '%{http_code}' -c "$jar" -b "$jar" \
    -X POST "$BASE/__auth/pair/redeem" -H 'content-type: application/json' \
    --data-binary @"$TMP/redeem-payload.json"
}

admin_post_session() {
  # jar csrf path payload out; source address is deliberately non-loopback
  local jar=$1 csrf=$2 path=$3 payload=$4 out=$5
  curl -sk --max-time 30 --interface "$SOURCE_IP" -o "$out" -w '%{http_code}' \
    -c "$jar" -b "$jar" -X POST "$BASE$path" \
    -H 'content-type: application/json' -H "x-auth-gate-csrf: $csrf" \
    --data-binary @"$payload"
}

admin_post_session_at() {
  # base jar csrf path payload out; same non-loopback source as above.
  local base=$1 jar=$2 csrf=$3 path=$4 payload=$5 out=$6
  curl -sk --max-time 30 --interface "$SOURCE_IP" -o "$out" -w '%{http_code}' \
    -c "$jar" -b "$jar" -X POST "$base$path" \
    -H 'content-type: application/json' -H "x-auth-gate-csrf: $csrf" \
    --data-binary @"$payload"
}

secret_in_file() {
  # needle file; exit 0 if found
  E2E_NEEDLE="$1" node tests/e2e-helpers.mjs file-contains "$2"
}

secret_not_in_file() {
  E2E_NEEDLE="$1" node tests/e2e-helpers.mjs file-not-contains "$2"
}

# ---------------------------------------------------------------------------
step "prerequisites"
command -v node >/dev/null || fail "node is required"
command -v curl >/dev/null || fail "curl is required"
command -v openssl >/dev/null || fail "openssl is required"
[ -r "$CERT" ] || fail "missing TLS certificate $CERT"
[ -r "$KEY" ] || fail "missing TLS key $KEY"
if [ -z "$SOURCE_IP" ]; then
  SOURCE_IP=$(hostname -I 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i !~ /^127\./) { print $i; exit }}')
fi
[ -n "$SOURCE_IP" ] || fail "no non-loopback IPv4 address found; set E2E_SOURCE_IP to test the session-backed admin channel"
[[ "$SOURCE_IP" != 127.* ]] || fail "E2E_SOURCE_IP must not be a loopback address (session channel would be masked by loopback admin trust)"
# The network-settings/setup gateway binds the LAN address: v0.6.1 refuses
# loopback listeners for the network API, and hot rebinds stay on this address.
SETUP_HOST="$SOURCE_IP"
BASE_SETUP="https://$SETUP_HOST:$GATE_PORT_SETUP"
BASE_SETUP_TMP="https://$SETUP_HOST:$GATE_PORT_SETUP_TMP"
rm -rf "$STATE" "$TMP" "$DSH_HOME"
mkdir -p "$STATE" "$TMP"
pass "node $(node --version), curl $(curl --version | head -1 | awk '{print $2}'), session source IP $SOURCE_IP"

# ---------------------------------------------------------------------------
step "upstream dsh"
TOKEN_URL="${DSH_TOKEN_URL:-}"
UPSTREAM="${E2E_UPSTREAM:-${AUTH_GATE_UPSTREAM:-}}"
if [ -n "$TOKEN_URL" ]; then
  [ -n "$UPSTREAM" ] || UPSTREAM='https://192.0.2.10:3080'
  pass "using DSH_TOKEN_URL from the environment (upstream $UPSTREAM)"
elif [ "${E2E_USE_JOURNAL:-0}" = "1" ]; then
  TOKEN_URL=$(journalctl -u dsh --no-pager 2>/dev/null | grep 'dsh web: https' | tail -1 | sed -nE 's/^.*(https?:\/\/[^ ]+[?&]token=[A-Za-z0-9_-]+).*$/\1/p' || true)
  [ -n "$TOKEN_URL" ] || fail "journalctl has no dsh launch URL; unset E2E_USE_JOURNAL or pass DSH_TOKEN_URL"
  [ -n "$UPSTREAM" ] || UPSTREAM='https://192.0.2.10:3080'
  pass "using the launch URL from the dsh journal (not printed)"
else
  echo "journal launch URL unavailable; starting a throwaway dsh web instance on $HOST:$DSH_PORT"
  mkdir -p "$DSH_HOME/profiles/e2e" "$DSH_HOME/workspace" "$DSH_HOME/tmp" "$DSH_HOME/home"
  if [ ! -f "$DSH_HOME/profiles/e2e/package.json" ]; then
    cat > "$DSH_HOME/profiles/e2e/package.json" <<'JSON'
{
  "name": "dsh-profile-e2e",
  "private": true,
  "dependencies": {},
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-web-app"
      ]
    }
  }
}
JSON
    printf '[]\n' > "$DSH_HOME/profiles/e2e/cordis.patch.yml"
    printf 'packages:\n  - .\n' > "$DSH_HOME/profiles/e2e/pnpm-workspace.yaml"
  fi
  if command -v ss >/dev/null && ss -lnt 2>/dev/null | awk '{print $4}' | grep -q ":$DSH_PORT\$"; then
    fail "port $DSH_PORT is already in use; stop that process or pass DSH_TOKEN_URL"
  fi
  (
    cd "$DSH_HOME/workspace"
    exec env \
      DSH_HOME="$DSH_HOME" \
      DSH_AGENTS_HOME="$DSH_HOME/agents" \
      TMPDIR="$DSH_HOME/tmp" \
      HOME="$DSH_HOME/home" \
      dsh \
      --profile e2e --no-open --host "$HOST" --port "$DSH_PORT" \
      --public-url "https://$HOST:$DSH_PORT" \
      --tls-cert "$CERT" --tls-key "$KEY"
  ) > "$DSH_HOME/dsh.log" 2>&1 &
  DSH_PID=$!
  DSH_READY=0
  for _ in $(seq 1 120); do
    kill -0 "$DSH_PID" 2>/dev/null || fail "throwaway dsh exited during startup"
    if grep -q 'dsh web:' "$DSH_HOME/dsh.log" 2>/dev/null; then DSH_READY=1; break; fi
    sleep 0.5
  done
  [ "$DSH_READY" = 1 ] || fail "throwaway dsh did not print its URL within 60s"
  DSH_CODE=000
  for _ in $(seq 1 60); do
    DSH_CODE=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' "https://$HOST:$DSH_PORT/" || true)
    [ "$DSH_CODE" = "401" ] && break
    sleep 0.5
  done
  assert_eq "$DSH_CODE" 401 "throwaway dsh must answer unauthenticated requests with 401"
  TOKEN_URL=$(sed -nE 's/^dsh web: (https?:\/\/[^ ]+).*$/\1/p' "$DSH_HOME/dsh.log" | tail -1)
  [ -n "$TOKEN_URL" ] || fail "could not extract the throwaway dsh launch URL"
  UPSTREAM="https://$HOST:$DSH_PORT"
  pass "throwaway dsh is ready at $UPSTREAM (launch URL kept in memory)"
fi

# ---------------------------------------------------------------------------
step "start standalone gateway on $BASE"
AUTH_GATE_LISTEN_HOST="$HOST" \
AUTH_GATE_LISTEN_PORT="$GATE_PORT" \
AUTH_GATE_UPSTREAM="$UPSTREAM" \
AUTH_GATE_UPSTREAM_INSECURE_TLS=true \
AUTH_GATE_PUBLIC_URL="$BASE" \
AUTH_GATE_TLS_CERT="$CERT" \
AUTH_GATE_TLS_KEY="$KEY" \
AUTH_GATE_STATE_DIR="$STATE" \
AUTH_GATE_PAIR_TICKET_TTL_SECONDS="$PAIR_TTL" \
DSH_TOKEN_URL="$TOKEN_URL" \
node lib/standalone.js > "$TMP/gateway.log" 2>&1 &
GW_PID=$!
GW_READY=0
for _ in $(seq 1 80); do
  kill -0 "$GW_PID" 2>/dev/null || fail "standalone gateway exited during startup"
  GW_CODE=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' "$BASE/__auth/csrf" || true)
  if [ "$GW_CODE" = "200" ]; then GW_READY=1; break; fi
  sleep 0.25
done
[ "$GW_READY" = 1 ] || fail "standalone gateway did not become ready"
pass "gateway listening, TLS enabled"

# ---------------------------------------------------------------------------
step "1. unauthenticated navigation is redirected to the login page"
NO_SESSION_HTML_CODE=$(curl -sk --max-time 10 -o "$TMP/no-session.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE/")
NO_SESSION_REDIRECT=$(curl -sk --max-time 10 -o /dev/null -w '%{redirect_url}' -H 'Accept: text/html' "$BASE/")
assert_eq "$NO_SESSION_HTML_CODE" 302 "GET / without a session"
assert_eq "$NO_SESSION_REDIRECT" "$BASE/__auth/login?next=%2F" "login redirect target"
NO_SESSION_API_CODE=$(curl -sk --max-time 10 -o "$TMP/no-session.json" -w '%{http_code}' -H 'Accept: application/json' "$BASE/")
assert_eq "$NO_SESSION_API_CODE" 401 "GET / without a session and without HTML"
assert_eq "$(json_get "$TMP/no-session.json" error)" "authentication_required" "unauthenticated JSON error"
pass "302 + next=%2F for HTML, 401 JSON otherwise"

# ---------------------------------------------------------------------------
step "2. admin key, bootstrap and TOTP"
[ -f "$STATE/admin.key" ] || fail "admin.key was not created"
ADMIN_MODE=$(stat -c '%a' "$STATE/admin.key")
assert_eq "$ADMIN_MODE" 600 "admin.key permissions"
ADMIN_KEY=$(tr -d '\r\n' < "$STATE/admin.key")
[ "${#ADMIN_KEY}" -eq 64 ] || fail "admin key must be 64 hex characters"
# v0.6.1 P0-1: this gateway binds 127.0.0.1, so the automatic loopback admin
# channel is disabled. An unauthenticated loopback request (even with the
# pinned Host and the exact PoC path) must not read state or the admin key.
ADMIN_STATE_CODE=$(curl -sk --max-time 10 -H "Host: 127.0.0.1:$GATE_PORT" -o "$TMP/admin-state-anon.json" -w '%{http_code}' "$BASE/__admin/api/state")
assert_eq "$ADMIN_STATE_CODE" 403 "loopback auto-admin state without a credential"
assert_eq "$(json_get "$TMP/admin-state-anon.json" error)" "forbidden" "loopback auto-admin error"
ADMIN_KEY_LEAK_CODE=$(curl -sk --max-time 10 -H "Host: 127.0.0.1:$GATE_PORT" -o "$TMP/admin-key-leak.json" -w '%{http_code}' "$BASE/__admin/api/admin-key")
assert_eq "$ADMIN_KEY_LEAK_CODE" 403 "P0-1 PoC: loopback must not read /__admin/api/admin-key"
secret_not_in_file "$ADMIN_KEY" "$TMP/admin-key-leak.json" || fail "admin key leaked through the loopback admin channel"
ADMIN_STATE_CODE=$(curl -sk --max-time 10 -H "x-auth-gate-admin-key: $ADMIN_KEY" -o "$TMP/admin-state-before.json" -w '%{http_code}' "$BASE/__admin/api/state")
assert_eq "$ADMIN_STATE_CODE" 200 "adminKey admin state"
assert_eq "$(json_get "$TMP/admin-state-before.json" configured)" "false" "fresh state must not be configured"
ADMIN_BAD_HOST_CODE=$(curl -sk --max-time 10 -H 'Host: evil.example' -o "$TMP/admin-bad-host.json" -w '%{http_code}' "$BASE/__admin/api/state")
assert_eq "$ADMIN_BAD_HOST_CODE" 403 "anonymous admin with a rebinding Host must be refused"
grep -q 'loopback admin channel is DISABLED' "$TMP/gateway.log" || fail "loopback listener must log the disabled admin channel"
E2E_USERNAME="$USERNAME" E2E_PASSWORD="$PASSWORD" \
  node tests/e2e-helpers.mjs bootstrap-json "$TMP/bootstrap-payload.json"
BOOTSTRAP_CODE=$(curl -sk --max-time 30 -o "$TMP/bootstrap.json" -w '%{http_code}' -X POST "$BASE/__admin/api/bootstrap" \
  -H "x-auth-gate-admin-key: $ADMIN_KEY" -H 'content-type: application/json' --data-binary @"$TMP/bootstrap-payload.json")
assert_eq "$BOOTSTRAP_CODE" 200 "admin bootstrap"
TOTP_SECRET=$(json_get "$TMP/bootstrap.json" secretB32)
[ -n "$TOTP_SECRET" ] || fail "bootstrap did not return a TOTP secret"
assert_file_contains "$TMP/bootstrap.json" 'otpauth://totp/DSH:admin' "otpauth URI in bootstrap response"
assert_file_contains "$TMP/bootstrap.json" '<svg' "TOTP QR SVG in bootstrap response"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $ADMIN_KEY" -o "$TMP/admin-state-after.json" "$BASE/__admin/api/state"
assert_eq "$(json_get "$TMP/admin-state-after.json" configured)" "true" "configured after bootstrap"
assert_eq "$(json_get "$TMP/admin-state-after.json" user.username)" "$USERNAME" "admin state username"
pass "user bootstrapped with TOTP (secret kept out of output)"

# ---------------------------------------------------------------------------
step "3. login page, CSRF and security headers"
LOGIN_PAGE_CODE=$(curl -sk --max-time 10 -D "$TMP/login-page-headers" -o "$TMP/login-page.html" -w '%{http_code}' "$BASE/__auth/login")
assert_eq "$LOGIN_PAGE_CODE" 200 "GET /__auth/login"
assert_file_contains "$TMP/login-page.html" 'autocomplete="username"' "login page username autocomplete"
assert_file_contains "$TMP/login-page.html" 'autocomplete="current-password"' "login page password autocomplete"
assert_file_lacks "$TMP/login-page.html" 'one-time-code' "v0.4.0 login page must not ask for TOTP"
assert_file_lacks "$TMP/login-page.html" 'name="totp"' "v0.4.0 login page must not post a TOTP field"
assert_file_contains "$TMP/login-page.html" '配对后的设备登录只需用户名 + 密码' "login page explains the v0.4.0 model"
grep -qi '^x-content-type-options: nosniff' "$TMP/login-page-headers" || fail "missing nosniff"
grep -qi '^strict-transport-security:' "$TMP/login-page-headers" || fail "missing HSTS"
grep -qi '^content-security-policy:.*nonce-' "$TMP/login-page-headers" || fail "missing CSP nonce"
grep -qiE '^cache-control: (private, )?no-store' "$TMP/login-page-headers" || fail "login page must not be cached"
pass "login page is username+password only with CSRF nonce, nosniff, HSTS, no-store"

# ---------------------------------------------------------------------------
step "4. QR ticket and device pairing"
QR_CODE=$(request_qr "$TMP/qr.json")
assert_eq "$QR_CODE" 200 "admin QR"
assert_file_contains "$TMP/qr.json" '<svg' "QR SVG"
PAIR_URL=$(json_get "$TMP/qr.json" url)
case "$PAIR_URL" in
  "$BASE/__auth/pair#v=1&t="*) ;;
  *) fail "unexpected pairing URL shape" ;;
esac
case "$PAIR_URL" in
  *'?'*) fail "pairing URL must not carry a query string (ticket belongs in the fragment)" ;;
esac
FP=$(node tests/e2e-helpers.mjs pair-fp "$TMP/qr.json")
[ "${#FP}" -eq 64 ] || fail "pairing fingerprint must be 64 hex characters"
[[ "$FP" =~ ^[0-9a-f]{64}$ ]] || fail "pairing fingerprint must be lower-case hex"
CERT_FP=$(CERT="$CERT" node --input-type=module -e 'import fs from "node:fs"; import { certificateFingerprint } from "./lib/qr.js"; console.log(certificateFingerprint(fs.readFileSync(process.env.CERT)));')
assert_eq "$FP" "$CERT_FP" "QR fingerprint must match the gateway certificate"
TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr.json")
[ -n "$TICKET" ] || fail "pairing URL has no ticket"
JAR_DEVICE="$TMP/jar-device"
REDEEM_CODE=$(redeem_ticket "$TICKET" "$JAR_DEVICE" "$TMP/redeem.json")
assert_eq "$REDEEM_CODE" 200 "pair/redeem"
DEVICE_TOKEN=$(json_get "$TMP/redeem.json" deviceToken)
DEVICE_ID=$(json_get "$TMP/redeem.json" deviceId)
[ -n "$DEVICE_TOKEN" ] || fail "redeem returned no device token"
[ -n "$DEVICE_ID" ] || fail "redeem returned no device id"
DEVICE_COOKIE=$(node tests/e2e-helpers.mjs cookie "$JAR_DEVICE" dsh_gate_device)
[ -n "$DEVICE_COOKIE" ] || fail "device cookie was not set"
secret_not_in_file "$DEVICE_TOKEN" "$STATE/state.json" || fail "device token was persisted in plaintext"
pass "paired device $DEVICE_ID (fingerprint $FP)"

# ---------------------------------------------------------------------------
step "5. a ticket is single use"
REPLAY_CODE=$(redeem_ticket "$TICKET" "$JAR_DEVICE" "$TMP/redeem-replay.json")
assert_eq "$REPLAY_CODE" 401 "replayed ticket"
assert_eq "$(json_get "$TMP/redeem-replay.json" error)" "invalid_ticket" "replayed ticket error"
pass "replayed ticket rejected with invalid_ticket"

# ---------------------------------------------------------------------------
step "6. login without a paired device is refused"
JAR_NO_DEVICE="$TMP/jar-nodevice"
rm -f "$JAR_NO_DEVICE"
assert_eq "$(get_csrf "$JAR_NO_DEVICE")" 200 "csrf for the unpaired browser"
CSRF_NO_DEVICE=$(json_get "$TMP/csrf.json" csrf)
NO_DEVICE_CODE=$(login_request "$JAR_NO_DEVICE" "$CSRF_NO_DEVICE" "$PASSWORD" "$TMP/login-nodevice.json" "$TMP/login-nodevice-headers")
assert_eq "$NO_DEVICE_CODE" 401 "login without device"
assert_eq "$(json_get "$TMP/login-nodevice.json" error)" "device_required" "unpaired login error"
pass "device_required"

# ---------------------------------------------------------------------------
step "7. login with a paired device + password (no TOTP)"
assert_eq "$(get_csrf "$JAR_DEVICE")" 200 "csrf for the paired browser"
CSRF_DEVICE=$(json_get "$TMP/csrf.json" csrf)
LOGIN_CODE=$(login_request "$JAR_DEVICE" "$CSRF_DEVICE" "$PASSWORD" "$TMP/login-ok.json" "$TMP/login-ok-headers")
assert_eq "$LOGIN_CODE" 200 "login with device + password"
assert_eq "$(json_get "$TMP/login-ok.json" ok)" "true" "login response ok"
assert_file_lacks "$TMP/login-ok.json" '"totp"' "login response must not mention TOTP"
pass "paired device + password login (no TOTP request field)"
grep -qi 'set-cookie:.*dsh_gate_session=.*HttpOnly.*SameSite=Lax.*Secure' "$TMP/login-ok-headers" || fail "session cookie flags are wrong"
! grep -qi 'dsh-auth-' "$TMP/login-ok-headers" || fail "dsh cookie leaked to the browser"
SESSION_COOKIE=$(node tests/e2e-helpers.mjs cookie "$JAR_DEVICE" dsh_gate_session)
[ -n "$SESSION_COOKIE" ] || fail "session cookie not stored"
WHOAMI_CODE=$(curl -sk --max-time 10 -o "$TMP/whoami.json" -w '%{http_code}' -b "$JAR_DEVICE" "$BASE/__auth/whoami")
assert_eq "$WHOAMI_CODE" 200 "whoami"
assert_eq "$(json_get "$TMP/whoami.json" authenticated)" "true" "whoami authenticated"
assert_eq "$(json_get "$TMP/whoami.json" user.username)" "$USERNAME" "whoami username"
pass "session cookie issued with HttpOnly/Secure/SameSite=Lax"

# ---------------------------------------------------------------------------
step "8. renew only accepts a JSON body device token"
JAR_RENEW="$TMP/jar-renew"
EMPTY_RENEW_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-empty.json" -w '%{http_code}' \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary '{}')
assert_eq "$EMPTY_RENEW_CODE" 401 "renew without a device token"
assert_eq "$(json_get "$TMP/renew-empty.json" error)" "device_required" "empty renew error"
COOKIE_RENEW_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-cookie.json" -w '%{http_code}' \
  -b "$JAR_DEVICE" -X POST "$BASE/__auth/renew")
assert_eq "$COOKIE_RENEW_CODE" 401 "renew must not fall back to the device cookie"
assert_eq "$(json_get "$TMP/renew-cookie.json" error)" "device_required" "cookie renew error"
E2E_DEVICE_TOKEN="$DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-payload.json"
RENEW_CODE=$(curl -sk --max-time 20 -D "$TMP/renew-headers" -o "$TMP/renew.json" -w '%{http_code}' -c "$JAR_RENEW" -b "$JAR_RENEW" \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-payload.json")
assert_eq "$RENEW_CODE" 200 "renew"
[ -n "$(node tests/e2e-helpers.mjs cookie "$JAR_RENEW" dsh_gate_session)" ] || fail "renew did not set a session cookie"
# v0.7.0: a successful renewal re-issues the device cookie (sliding lifetime)
# as well as the session cookie; the session Max-Age is the full 48h window.
[ -n "$(node tests/e2e-helpers.mjs cookie "$JAR_RENEW" dsh_gate_device)" ] || fail "renew did not re-issue the device cookie"
grep -qi 'set-cookie:.*dsh_gate_device=.*Max-Age=' "$TMP/renew-headers" || fail "device cookie has no Max-Age on renew"
grep -qi 'set-cookie:.*dsh_gate_session=.*Max-Age=172800' "$TMP/renew-headers" || fail "session cookie Max-Age is not the 48h idle window"
RENEW_DEVICE_EXP_1=$(json_get "$TMP/renew.json" deviceExpiresAt)
[ -n "$RENEW_DEVICE_EXP_1" ] || fail "renew response has no deviceExpiresAt"
# A second renewal a second later must push the sliding device deadline forward.
sleep 1.1
RENEW_CODE_2=$(curl -sk --max-time 20 -o "$TMP/renew-2.json" -w '%{http_code}' -c "$JAR_RENEW" -b "$JAR_RENEW" \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-payload.json")
assert_eq "$RENEW_CODE_2" 200 "second renew"
RENEW_DEVICE_EXP_2=$(json_get "$TMP/renew-2.json" deviceExpiresAt)
[ -n "$RENEW_DEVICE_EXP_2" ] || fail "second renew response has no deviceExpiresAt"
[ "$RENEW_DEVICE_EXP_2" -gt "$RENEW_DEVICE_EXP_1" ] || fail "device expiry did not slide forward: [$RENEW_DEVICE_EXP_1] -> [$RENEW_DEVICE_EXP_2]"
pass "body token renews; device expiry slides forward and both cookies are re-issued; empty body and cookie fallback are refused"

# ---------------------------------------------------------------------------
step "9. reverse proxy serves the real dsh GUI"
PROXY_CODE=$(curl -sk --max-time 60 -D "$TMP/proxy-headers" -o "$TMP/page.html" -w '%{http_code}' -b "$JAR_DEVICE" -H 'Accept: text/html' "$BASE/")
assert_eq "$PROXY_CODE" 200 "proxied GET /"
assert_file_contains "$TMP/page.html" '__DSH_BOOT__' "proxied dsh index must contain __DSH_BOOT__"
grep -qi '^x-content-type-options: nosniff' "$TMP/proxy-headers" || fail "proxied response lost nosniff"
! grep -qi '^set-cookie:' "$TMP/proxy-headers" || fail "upstream Set-Cookie leaked to the browser"
SAME_ORIGIN_CODE=$(curl -sk --max-time 60 -o "$TMP/page-same-origin.html" -w '%{http_code}' -b "$JAR_DEVICE" -H "Origin: $BASE" -H 'Accept: text/html' "$BASE/")
assert_eq "$SAME_ORIGIN_CODE" 200 "same-origin proxied GET /"
CROSS_ORIGIN_CODE=$(curl -sk --max-time 20 -o "$TMP/cross-origin.json" -w '%{http_code}' -b "$JAR_DEVICE" -H 'Origin: https://evil.example' -H 'Accept: application/json' "$BASE/")
assert_eq "$CROSS_ORIGIN_CODE" 403 "cross-origin proxied request"
assert_eq "$(json_get "$TMP/cross-origin.json" error)" "forbidden_origin" "cross-origin error"
pass "GET / is 200 and contains __DSH_BOOT__; Set-Cookie stripped; cross-origin request rejected"

# ---------------------------------------------------------------------------
step "10. WebSocket tunnel to /api/remote.mux"
WS_OK=0
WS_LINE=$(node tests/e2e-helpers.mjs ws "$HOST" "$GATE_PORT" "" "$BASE" 2>/dev/null) || WS_OK=$?
[ "$WS_OK" -ne 0 ] || fail "unauthenticated WebSocket upgrade was accepted"
[[ "$WS_LINE" == *401* ]] || fail "unauthenticated WebSocket did not receive 401 (got: $WS_LINE)"
pass "unauthenticated upgrade rejected with 401"
WS_LINE=$(node tests/e2e-helpers.mjs ws "$HOST" "$GATE_PORT" "$JAR_DEVICE" "$BASE") || fail "authenticated WebSocket upgrade failed: $WS_LINE"
[[ "$WS_LINE" == *101* ]] || fail "authenticated WebSocket did not receive 101 (got: $WS_LINE)"
printf 'WebSocket status: %s\n' "$WS_LINE"
pass "authenticated upgrade through the gateway returned 101"

# ---------------------------------------------------------------------------
step "11. admin WebUI through a logged-in session"
NO_SESSION_ADMIN_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -H 'Accept: text/html' -o /dev/null -w '%{http_code}' "$BASE/__admin")
NO_SESSION_ADMIN_REDIRECT=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -H 'Accept: text/html' -o /dev/null -w '%{redirect_url}' "$BASE/__admin")
assert_eq "$NO_SESSION_ADMIN_CODE" 302 "GET /__admin without a session from a LAN address"
assert_eq "$NO_SESSION_ADMIN_REDIRECT" "$BASE/__auth/login?next=/__admin" "admin login redirect target"
ADMIN_LOGIN_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -o "$TMP/admin-login.html" -w '%{http_code}' "$BASE/__auth/login?next=/__admin")
assert_eq "$ADMIN_LOGIN_CODE" 200 "admin login page for next=/__admin"
assert_file_contains "$TMP/admin-login.html" 'NEXT="/__admin"' "login page keeps the admin return target"
ADMIN_PAGE_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -D "$TMP/admin-page-headers" -o "$TMP/admin-page.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$ADMIN_PAGE_CODE" 200 "GET /__admin with a logged-in session"
assert_file_contains "$TMP/admin-page.html" 'DSH 认证管理' "admin page title"
assert_file_contains "$TMP/admin-page.html" 'id="section-account"' "admin account section"
assert_file_contains "$TMP/admin-page.html" 'id="section-pair"' "admin pairing section"
assert_file_contains "$TMP/admin-page.html" 'id="pair-totp"' "admin pairing TOTP input"
assert_file_contains "$TMP/admin-page.html" '6 位动态验证码（生成配对码必填）' "session channel marks the pairing TOTP as required"
assert_file_contains "$TMP/admin-page.html" 'inputmode="numeric"' "pairing TOTP input is numeric"
assert_file_lacks "$TMP/admin-page.html" 'id="pair-current-password"' "admin pairing must not ask for the current password"
assert_file_contains "$TMP/admin-page.html" 'id="section-devices"' "admin devices section"
assert_file_contains "$TMP/admin-page.html" 'id="section-sessions"' "admin sessions section"
assert_file_contains "$TMP/admin-page.html" 'id="section-audit"' "admin audit section"
assert_file_contains "$TMP/admin-page.html" 'e2e-android' "paired device in admin page"
assert_file_contains "$TMP/admin-page.html" "$DEVICE_ID" "paired device id in admin page"
assert_file_contains "$TMP/admin-page.html" '所有设备需重新扫码' "re-pair warning"
assert_file_contains "$TMP/admin-page.html" '登录会话' "session channel label"
grep -qi '^content-security-policy:.*nonce-' "$TMP/admin-page-headers" || fail "admin page lost its CSP nonce"
grep -qiE '^cache-control: (private, )?no-store' "$TMP/admin-page-headers" || fail "admin page must not be cached"
secret_not_in_file "$PASSWORD" "$TMP/admin-page.html" || fail "password found in admin page"
secret_not_in_file "$TOTP_SECRET" "$TMP/admin-page.html" || fail "TOTP secret found in admin page"
secret_not_in_file "$DEVICE_TOKEN" "$TMP/admin-page.html" || fail "device token found in admin page"
secret_not_in_file "$SESSION_COOKIE" "$TMP/admin-page.html" || fail "session token found in admin page"
ADMIN_STATE_SESSION_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -o "$TMP/admin-state-session.json" -w '%{http_code}' "$BASE/__admin/api/state")
assert_eq "$ADMIN_STATE_SESSION_CODE" 200 "state via session"
assert_eq "$(json_get "$TMP/admin-state-session.json" devices.length)" "1" "device count via session"
assert_eq "$(json_get "$TMP/admin-state-session.json" devices.0.online)" "true" "active device is online"
SESSION_COUNT=$(json_get "$TMP/admin-state-session.json" sessionCount)
[ "$SESSION_COUNT" -ge 1 ] || fail "session count: expected at least 1, got [$SESSION_COUNT]"
assert_file_contains "$TMP/admin-state-session.json" '"current":true' "current session marker"
assert_file_lacks "$TMP/admin-state-session.json" 'passwordHash' "state must not contain passwordHash"
assert_file_lacks "$TMP/admin-state-session.json" 'totpSecretB32' "state must not contain totpSecretB32"
assert_file_lacks "$TMP/admin-state-session.json" 'tokenHash' "state must not contain token hashes"
assert_file_lacks "$TMP/admin-state-session.json" 'deviceToken' "state must not contain device tokens"
secret_not_in_file "$TOTP_SECRET" "$TMP/admin-state-session.json" || fail "TOTP secret found in state"
secret_not_in_file "$DEVICE_TOKEN" "$TMP/admin-state-session.json" || fail "device token found in state"
pass "session channel: /__admin 200 with account/pair/devices/sessions/audit sections + pairing TOTP field; state shows online device + current session"

# ---------------------------------------------------------------------------
step "12. session channel: CSRF, QR generation and device revoke"
NO_CSRF_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -X POST -H 'content-type: application/json' --data-binary '{}' -o "$TMP/admin-no-csrf.json" -w '%{http_code}' "$BASE/__admin/api/qr")
assert_eq "$NO_CSRF_CODE" 403 "session admin POST without CSRF"
assert_eq "$(json_get "$TMP/admin-no-csrf.json" error)" "csrf_invalid" "missing CSRF error"
assert_eq "$(get_csrf "$JAR_DEVICE")" 200 "csrf for session admin"
CSRF_SESSION=$(json_get "$TMP/csrf.json" csrf)
# The session channel must prove a fresh TOTP code before minting a QR.
TOTP=$(E2E_TOTP_SECRET="$TOTP_SECRET" node tests/e2e-helpers.mjs totp-env)
E2E_PLATFORM=web node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-session-no-totp.json"
SESSION_QR_MISSING_CODE=$(admin_post_session "$JAR_DEVICE" "$CSRF_SESSION" "/__admin/api/qr" "$TMP/qr-session-no-totp.json" "$TMP/qr-session-missing.json")
assert_eq "$SESSION_QR_MISSING_CODE" 403 "session QR without a TOTP code"
assert_eq "$(json_get "$TMP/qr-session-missing.json" error)" "totp_required" "missing TOTP QR error"
WRONG_TOTP=000000
[ "$TOTP" = "000000" ] && WRONG_TOTP=000001
E2E_TOTP="$WRONG_TOTP" E2E_PLATFORM=web node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-session-wrong-totp.json"
SESSION_QR_WRONG_CODE=$(admin_post_session "$JAR_DEVICE" "$CSRF_SESSION" "/__admin/api/qr" "$TMP/qr-session-wrong-totp.json" "$TMP/qr-session-wrong.json")
assert_eq "$SESSION_QR_WRONG_CODE" 403 "session QR with a wrong TOTP code"
assert_eq "$(json_get "$TMP/qr-session-wrong.json" error)" "totp_invalid" "wrong TOTP QR error"
E2E_TOTP="$TOTP" E2E_PLATFORM=web node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-session-payload.json"
SESSION_QR_CODE=$(admin_post_session "$JAR_DEVICE" "$CSRF_SESSION" "/__admin/api/qr" "$TMP/qr-session-payload.json" "$TMP/qr-session.json")
assert_eq "$SESSION_QR_CODE" 200 "session-channel QR"
# The verification must not consume the login replay counter: the same 30s
# window can mint another QR code.
E2E_TOTP="$TOTP" E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-session-payload-2.json"
SESSION_QR_CODE_2=$(admin_post_session "$JAR_DEVICE" "$CSRF_SESSION" "/__admin/api/qr" "$TMP/qr-session-payload-2.json" "$TMP/qr-session-2.json")
assert_eq "$SESSION_QR_CODE_2" 200 "the same TOTP window can mint a second QR"
assert_file_contains "$TMP/qr-session-2.json" '<svg' "second session QR SVG"
assert_file_lacks "$TMP/qr-session.json" "$PASSWORD" "currentPassword must not be sent or echoed by the QR response"
assert_file_contains "$TMP/qr-session.json" '<svg' "session QR SVG"
WEB_TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr-session.json")
[ -n "$WEB_TICKET" ] || fail "session QR has no ticket"
JAR_WEB="$TMP/jar-web"
rm -f "$JAR_WEB"
WEB_REDEEM_CODE=$(redeem_ticket "$WEB_TICKET" "$JAR_WEB" "$TMP/redeem-web.json" e2e-browser web)
assert_eq "$WEB_REDEEM_CODE" 200 "browser pairing via session QR link"
WEB_DEVICE_TOKEN=$(json_get "$TMP/redeem-web.json" deviceToken)
WEB_DEVICE_ID=$(json_get "$TMP/redeem-web.json" deviceId)
curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -o "$TMP/admin-state-two.json" "$BASE/__admin/api/state"
assert_eq "$(json_get "$TMP/admin-state-two.json" devices.length)" "2" "devices after browser pairing"
assert_file_contains "$TMP/admin-state-two.json" 'e2e-browser' "browser device name in state"
assert_file_contains "$TMP/admin-state-two.json" '"platform":"web"' "browser platform in state"
ADMIN_PAGE_WEB_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -o "$TMP/admin-page-web.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$ADMIN_PAGE_WEB_CODE" 200 "admin page after browser pairing"
assert_file_contains "$TMP/admin-page-web.html" 'e2e-browser' "browser device in admin page"
assert_file_contains "$TMP/admin-page-web.html" '<span class="badge platform">浏览器</span>' "browser platform label"
SESSION_REVOKE_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -c "$JAR_DEVICE" -X POST "$BASE/__admin/api/devices/revoke" -H 'content-type: application/json' -H "x-auth-gate-csrf: $CSRF_SESSION" --data-binary "{\"deviceId\":\"$WEB_DEVICE_ID\"}" -o "$TMP/revoke-session.json" -w '%{http_code}')
assert_eq "$SESSION_REVOKE_CODE" 200 "session-channel device revoke"
assert_eq "$(json_get "$TMP/revoke-session.json" revoked)" "true" "revoke response"
E2E_DEVICE_TOKEN="$WEB_DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-web-payload.json"
WEB_REVOKED_RENEW_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-web-revoked.json" -w '%{http_code}' \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-web-payload.json")
assert_eq "$WEB_REVOKED_RENEW_CODE" 401 "renew after session-channel revoke"
assert_eq "$(json_get "$TMP/renew-web-revoked.json" error)" "device_required" "revoked browser device error"
curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -o "$TMP/admin-state-revoked-web.json" "$BASE/__admin/api/state"
assert_eq "$(json_get "$TMP/admin-state-revoked-web.json" devices.length)" "1" "devices after browser revoke"
ADMIN_PAGE_AFTER_REVOKE_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_DEVICE" -o "$TMP/admin-page-after-revoke.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$ADMIN_PAGE_AFTER_REVOKE_CODE" 200 "session remains valid after revoking another device"
assert_file_lacks "$TMP/admin-page-after-revoke.html" 'e2e-browser' "revoked browser device disappears from the admin page"
pass "session QR requires TOTP (missing totp_required / wrong totp_invalid 403, correct 200, same window reusable); POST needs CSRF; QR pairing works; browser device revoked and its token renew fails"

# ---------------------------------------------------------------------------
step "13. post-logout and invalid-session behaviour"
LOGOUT_CODE=$(curl -sk --max-time 10 -o "$TMP/logout.json" -w '%{http_code}' -b "$JAR_DEVICE" -c "$JAR_DEVICE" -X POST "$BASE/__auth/logout")
assert_eq "$LOGOUT_CODE" 200 "logout"
curl -sk --max-time 10 -o "$TMP/whoami-after.json" -b "$JAR_DEVICE" "$BASE/__auth/whoami"
assert_eq "$(json_get "$TMP/whoami-after.json" authenticated)" "false" "whoami after logout"
AFTER_LOGOUT_CODE=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' -H 'Accept: text/html' -b "$JAR_DEVICE" "$BASE/")
assert_eq "$AFTER_LOGOUT_CODE" 302 "proxy after logout"
pass "logout invalidates the session server-side"

# ---------------------------------------------------------------------------
step "14. five bad passwords lock the account"
assert_eq "$(get_csrf "$JAR_DEVICE")" 200 "csrf before failed logins"
CSRF_FAIL=$(json_get "$TMP/csrf.json" csrf)
FAIL_CODES=''
for attempt in 1 2 3 4 5; do
  CODE=$(login_request "$JAR_DEVICE" "$CSRF_FAIL" "$WRONG_PASSWORD" "$TMP/login-fail-$attempt.json" "$TMP/login-fail-$attempt-headers")
  FAIL_CODES="$FAIL_CODES $CODE"
  if [ "$attempt" -lt 5 ]; then
    assert_eq "$CODE" 401 "bad password attempt $attempt"
  else
    assert_eq "$CODE" 429 "bad password attempt $attempt must be rate limited"
    assert_eq "$(json_get "$TMP/login-fail-$attempt.json" error)" "rate_limited" "rate limit error code"
  fi
done
LOCKED_CODE=$(login_request "$JAR_DEVICE" "$CSRF_FAIL" "$PASSWORD" "$TMP/login-locked.json" "$TMP/login-locked-headers")
assert_eq "$LOCKED_CODE" 429 "correct password while locked"
pass "statuses:$FAIL_CODES; correct password also 429 while locked"

# ---------------------------------------------------------------------------
step "15. expired ticket is reported as expired_ticket"
EXPIRED_CODE=$(request_qr "$TMP/qr-expired.json")
assert_eq "$EXPIRED_CODE" 200 "admin QR for expiry test"
EXPIRED_TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr-expired.json")
sleep $((PAIR_TTL + 1))
EXPIRED_REDEEM_CODE=$(redeem_ticket "$EXPIRED_TICKET" "$JAR_DEVICE" "$TMP/redeem-expired.json")
assert_eq "$EXPIRED_REDEEM_CODE" 401 "expired ticket"
assert_eq "$(json_get "$TMP/redeem-expired.json" error)" "expired_ticket" "expired ticket error"
pass "expired_ticket after ${PAIR_TTL}s TTL"

# ---------------------------------------------------------------------------
step "16. device revocation (token + all sessions + pending tickets)"
# Keep a session and a pending pairing ticket from *before* the revoke: the
# cascade must invalidate both immediately, not merely the device token.
REVOKE_SESSION_COOKIE=$(node tests/e2e-helpers.mjs cookie "$JAR_RENEW" dsh_gate_session)
[ -n "$REVOKE_SESSION_COOKIE" ] || fail "no session cookie available for the revoke cascade"
STALE_QR_CODE=$(request_qr "$TMP/qr-stale-before-revoke.json")
assert_eq "$STALE_QR_CODE" 200 "QR before revoke"
STALE_TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr-stale-before-revoke.json")
[ -n "$STALE_TICKET" ] || fail "no ticket before revoke"
REVOKE_CODE=$(curl -sk --max-time 10 -o "$TMP/revoke.json" -w '%{http_code}' -X POST "$BASE/__admin/api/devices/revoke" \
  -H "x-auth-gate-admin-key: $ADMIN_KEY" -H 'content-type: application/json' -d "{\"deviceId\":\"$DEVICE_ID\"}")
assert_eq "$REVOKE_CODE" 200 "device revoke"
assert_eq "$(json_get "$TMP/revoke.json" ok)" "true" "revoke response"
assert_eq "$(json_get "$TMP/revoke.json" sessionsRevoked)" "2" "revoke reports the cascaded session count (login + two renews, one logged out)"
SESSION_AFTER_REVOKE=$(curl -sk --max-time 10 -o "$TMP/session-after-revoke.json" -w '%{http_code}' \
  -H "cookie: dsh_gate_session=$REVOKE_SESSION_COOKIE" "$BASE/__admin/api/state")
assert_eq "$SESSION_AFTER_REVOKE" 403 "revoked device's session cookie after cascade"
WHOAMI_AFTER_REVOKE=$(curl -sk --max-time 10 -o "$TMP/whoami-after-revoke.json" -w '%{http_code}' \
  -H "cookie: dsh_gate_session=$REVOKE_SESSION_COOKIE" "$BASE/__auth/whoami")
assert_eq "$WHOAMI_AFTER_REVOKE" 200 "whoami after cascade"
assert_eq "$(json_get "$TMP/whoami-after-revoke.json" authenticated)" "false" "revoked session is unauthenticated"
STALE_REDEEM=$(redeem_ticket "$STALE_TICKET" "$JAR_DEVICE" "$TMP/redeem-stale-after-revoke.json")
assert_eq "$STALE_REDEEM" 401 "ticket minted before revoke"
assert_eq "$(json_get "$TMP/redeem-stale-after-revoke.json" error)" "invalid_ticket" "stale ticket after revoke"
E2E_DEVICE_TOKEN="$DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-revoked-payload.json"
REVOKED_RENEW_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-revoked.json" -w '%{http_code}' \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-revoked-payload.json")
assert_eq "$REVOKED_RENEW_CODE" 401 "renew after device revoke"
assert_eq "$(json_get "$TMP/renew-revoked.json" error)" "device_required" "revoked device error"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $ADMIN_KEY" -o "$TMP/admin-state-revoked.json" "$BASE/__admin/api/state"
assert_eq "$(json_get "$TMP/admin-state-revoked.json" devices.length)" "0" "devices after revoke"
pass "device revoked: its renewal, every session cookie and the pre-revoke ticket are invalidated immediately"

# ---------------------------------------------------------------------------
step "17. audit log, secret hygiene and state permissions"
AUDIT_CODE=$(curl -sk --max-time 10 -o "$TMP/audit.json" -w '%{http_code}' -H "x-auth-gate-admin-key: $ADMIN_KEY" "$BASE/__admin/api/audit")
assert_eq "$AUDIT_CODE" 200 "admin audit"
assert_file_contains "$TMP/audit.json" '"type":"login_ok"' "audit login_ok"
assert_file_contains "$TMP/audit.json" '"type":"login_fail"' "audit login_fail"
assert_file_contains "$TMP/audit.json" '"type":"pair_redeem"' "audit pair_redeem"
assert_file_contains "$TMP/audit.json" '"type":"device_revoke"' "audit device_revoke"
assert_file_contains "$TMP/audit.json" '"type":"admin_change"' "audit admin_change"
assert_file_contains "$TMP/audit.json" 'pair_ticket_issued' "audit pair_ticket_issued"
assert_file_contains "$TMP/audit.json" '"detail":"password"' "audit login_ok detail is password"
secret_not_in_file "$PASSWORD" "$TMP/audit.json" || fail "password found in audit log"
secret_not_in_file "$TOTP_SECRET" "$TMP/audit.json" || fail "TOTP secret found in audit log"
secret_not_in_file "$DEVICE_TOKEN" "$TMP/audit.json" || fail "device token found in audit log"
secret_not_in_file "$TICKET" "$TMP/audit.json" || fail "pairing ticket found in audit log"
assert_eq "$(stat -c '%a' "$STATE/state.json")" 600 "state.json permissions"
secret_not_in_file "$PASSWORD" "$STATE/state.json" || fail "password found in state.json"
secret_not_in_file "$DEVICE_TOKEN" "$STATE/state.json" || fail "device token found in state.json"
secret_not_in_file "$SESSION_COOKIE" "$STATE/state.json" || fail "session token found in state.json"
secret_not_in_file "$TICKET" "$STATE/state.json" || fail "pairing ticket found in state.json"
secret_not_in_file "$ADMIN_KEY" "$STATE/state.json" || fail "admin key found in state.json"
secret_not_in_file "$PASSWORD" "$TMP/gateway.log" || fail "password found in gateway log"
secret_not_in_file "$TOTP_SECRET" "$TMP/gateway.log" || fail "TOTP secret found in gateway log"
secret_not_in_file "$DEVICE_TOKEN" "$TMP/gateway.log" || fail "device token found in gateway log"
secret_not_in_file "$SESSION_COOKIE" "$TMP/gateway.log" || fail "session cookie found in gateway log"
! grep -Eq '[?&]token=[A-Za-z0-9_-]+' "$TMP/gateway.log" || fail "launch token found in gateway log"
ADMIN_KEY_LOG_COUNT=$(grep -c 'generated admin key' "$TMP/gateway.log" || true)
assert_eq "$ADMIN_KEY_LOG_COUNT" 1 "admin key generation must be logged exactly once"
secret_not_in_file "$ADMIN_KEY" "$TMP/gateway.log" || fail "full admin key found in gateway log"
pass "audit has the expected events; no secrets in audit/state/logs; files are 0600"

# ---------------------------------------------------------------------------
step "18. session channel: currentPassword, TOTP reset and password change"
# Pair a fresh device after the earlier revoke; renew (device token -> session)
# avoids a password login while the account is still locked from step 14.
FRESH_QR_CODE=$(request_qr "$TMP/qr-fresh.json")
assert_eq "$FRESH_QR_CODE" 200 "admin QR for password tests"
FRESH_TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr-fresh.json")
JAR_PW="$TMP/jar-password"
rm -f "$JAR_PW"
FRESH_REDEEM_CODE=$(redeem_ticket "$FRESH_TICKET" "$JAR_PW" "$TMP/redeem-fresh.json" e2e-password android)
assert_eq "$FRESH_REDEEM_CODE" 200 "fresh device pairing"
FRESH_DEVICE_TOKEN=$(json_get "$TMP/redeem-fresh.json" deviceToken)
E2E_DEVICE_TOKEN="$FRESH_DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-fresh-payload.json"
FRESH_RENEW_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-fresh.json" -w '%{http_code}' -c "$JAR_PW" -b "$JAR_PW" \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-fresh-payload.json")
assert_eq "$FRESH_RENEW_CODE" 200 "fresh session via device token"
FRESH_PAGE_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_PW" -o "$TMP/admin-page-fresh.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$FRESH_PAGE_CODE" 200 "admin page with the fresh session"
assert_eq "$(get_csrf "$JAR_PW")" 200 "csrf for the fresh session"
CSRF_PW=$(json_get "$TMP/csrf.json" csrf)

E2E_RESET_TOTP=1 node tests/e2e-helpers.mjs admin-user-json "$TMP/user-reset-missing.json"
RESET_MISSING_CODE=$(admin_post_session "$JAR_PW" "$CSRF_PW" "/__admin/api/user" "$TMP/user-reset-missing.json" "$TMP/reset-missing.json")
assert_eq "$RESET_MISSING_CODE" 403 "TOTP reset without currentPassword"
assert_eq "$(json_get "$TMP/reset-missing.json" error)" "invalid_current_password" "missing currentPassword error"
E2E_CURRENT_PASSWORD="$WRONG_PASSWORD" E2E_RESET_TOTP=1 node tests/e2e-helpers.mjs admin-user-json "$TMP/user-reset-wrong.json"
RESET_WRONG_CODE=$(admin_post_session "$JAR_PW" "$CSRF_PW" "/__admin/api/user" "$TMP/user-reset-wrong.json" "$TMP/reset-wrong.json")
assert_eq "$RESET_WRONG_CODE" 403 "TOTP reset with a wrong currentPassword"
assert_eq "$(json_get "$TMP/reset-wrong.json" error)" "invalid_current_password" "wrong currentPassword error"
E2E_CURRENT_PASSWORD="$PASSWORD" E2E_RESET_TOTP=1 node tests/e2e-helpers.mjs admin-user-json "$TMP/user-reset-ok.json"
RESET_CODE=$(admin_post_session "$JAR_PW" "$CSRF_PW" "/__admin/api/user" "$TMP/user-reset-ok.json" "$TMP/reset-ok.json")
assert_eq "$RESET_CODE" 200 "TOTP reset through the session channel"
NEW_TOTP_SECRET=$(json_get "$TMP/reset-ok.json" secretB32)
[ -n "$NEW_TOTP_SECRET" ] || fail "TOTP reset returned no secret"
[ "$NEW_TOTP_SECRET" != "$TOTP_SECRET" ] || fail "TOTP reset did not rotate the secret"
assert_file_contains "$TMP/reset-ok.json" '<svg' "new TOTP QR"
assert_file_contains "$TMP/reset-ok.json" 'otpauth://totp/' "new TOTP otpauth URI"
assert_eq "$(json_get "$TMP/reset-ok.json" devicesRevoked)" "1" "devices revoked by TOTP reset"
assert_eq "$(json_get "$TMP/reset-ok.json" rePairRequired)" "true" "re-pair flag after TOTP reset"
E2E_DEVICE_TOKEN="$FRESH_DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-reset-payload.json"
RENEW_AFTER_RESET_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-after-reset.json" -w '%{http_code}' \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-reset-payload.json")
assert_eq "$RENEW_AFTER_RESET_CODE" 401 "renew after TOTP reset"
assert_eq "$(json_get "$TMP/renew-after-reset.json" error)" "device_required" "revoked device after TOTP reset"
PAGE_AFTER_RESET_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_PW" -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$PAGE_AFTER_RESET_CODE" 302 "old session rejected after TOTP reset"
pass "TOTP reset needs currentPassword; new secret/QR returned; devices and sessions revoked"

# Re-pair for the password rotation test.
PW_QR_CODE=$(request_qr "$TMP/qr-password.json")
assert_eq "$PW_QR_CODE" 200 "admin QR for password change"
PW_TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr-password.json")
JAR_PW2="$TMP/jar-password-2"
rm -f "$JAR_PW2"
PW_REDEEM_CODE=$(redeem_ticket "$PW_TICKET" "$JAR_PW2" "$TMP/redeem-password.json" e2e-password-2 android)
assert_eq "$PW_REDEEM_CODE" 200 "device pairing for the password change"
PW_DEVICE_TOKEN=$(json_get "$TMP/redeem-password.json" deviceToken)
E2E_DEVICE_TOKEN="$PW_DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-password-payload.json"
PW_RENEW_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-password.json" -w '%{http_code}' -c "$JAR_PW2" -b "$JAR_PW2" \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-password-payload.json")
assert_eq "$PW_RENEW_CODE" 200 "session for the password change"
assert_eq "$(get_csrf "$JAR_PW2")" 200 "csrf for the password change"
CSRF_PW2=$(json_get "$TMP/csrf.json" csrf)
E2E_CURRENT_PASSWORD="$WRONG_PASSWORD" E2E_NEW_PASSWORD="$NEW_PASSWORD" node tests/e2e-helpers.mjs admin-user-json "$TMP/user-password-wrong.json"
PW_WRONG_CODE=$(admin_post_session "$JAR_PW2" "$CSRF_PW2" "/__admin/api/user" "$TMP/user-password-wrong.json" "$TMP/password-wrong.json")
assert_eq "$PW_WRONG_CODE" 403 "password change with a wrong currentPassword"
assert_eq "$(json_get "$TMP/password-wrong.json" error)" "invalid_current_password" "wrong currentPassword for password change"
E2E_CURRENT_PASSWORD="$PASSWORD" E2E_NEW_PASSWORD="$NEW_PASSWORD" node tests/e2e-helpers.mjs admin-user-json "$TMP/user-password-ok.json"
PW_CODE=$(admin_post_session "$JAR_PW2" "$CSRF_PW2" "/__admin/api/user" "$TMP/user-password-ok.json" "$TMP/password-ok.json")
assert_eq "$PW_CODE" 200 "password change through the session channel"
assert_eq "$(json_get "$TMP/password-ok.json" devicesRevoked)" "1" "devices revoked by the password change"
assert_eq "$(json_get "$TMP/password-ok.json" rePairRequired)" "true" "re-pair flag after the password change"
E2E_DEVICE_TOKEN="$PW_DEVICE_TOKEN" node tests/e2e-helpers.mjs renew-json "$TMP/renew-after-password-payload.json"
RENEW_AFTER_PASSWORD_CODE=$(curl -sk --max-time 20 -o "$TMP/renew-after-password.json" -w '%{http_code}' \
  -X POST "$BASE/__auth/renew" -H 'content-type: application/json' --data-binary @"$TMP/renew-after-password-payload.json")
assert_eq "$RENEW_AFTER_PASSWORD_CODE" 401 "renew after password change"
PAGE_AFTER_PASSWORD_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_PW2" -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$PAGE_AFTER_PASSWORD_CODE" 302 "old session rejected after password change"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $ADMIN_KEY" -o "$TMP/admin-state-final.json" "$BASE/__admin/api/state"
assert_eq "$(json_get "$TMP/admin-state-final.json" devices.length)" "0" "devices after password change"
assert_eq "$(json_get "$TMP/admin-state-final.json" sessions)" "0" "sessions after password change"

# The new password alone must work; the device cookie is the second factor.
# Log in from $SOURCE_IP: the login limiter's earlier lock belongs to
# 127.0.0.1, so this source is still clean.
NEW_QR_CODE=$(request_qr "$TMP/qr-new-login.json")
assert_eq "$NEW_QR_CODE" 200 "admin QR for the new-credential login"
NEW_TICKET=$(node tests/e2e-helpers.mjs ticket "$TMP/qr-new-login.json")
JAR_NEW="$TMP/jar-new-login"
rm -f "$JAR_NEW"
NEW_REDEEM_CODE=$(redeem_ticket "$NEW_TICKET" "$JAR_NEW" "$TMP/redeem-new-login.json" e2e-new-login android)
assert_eq "$NEW_REDEEM_CODE" 200 "device pairing for the new-credential login"
assert_eq "$(get_csrf "$JAR_NEW")" 200 "csrf for the new-credential login"
CSRF_NEW=$(json_get "$TMP/csrf.json" csrf)
NEW_LOGIN_CODE=$(login_request "$JAR_NEW" "$CSRF_NEW" "$NEW_PASSWORD" "$TMP/login-new.json" "$TMP/login-new-headers" "$SOURCE_IP")
assert_eq "$NEW_LOGIN_CODE" 200 "login with the new password only (no TOTP)"
assert_eq "$(json_get "$TMP/login-new.json" ok)" "true" "new-credential login ok"
NEW_SESSION_ADMIN_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_NEW" -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "$BASE/__admin")
assert_eq "$NEW_SESSION_ADMIN_CODE" 200 "new session can open /__admin"
# A session-channel QR after the password change needs the *new* TOTP secret:
# codes from the old secret are rejected.
assert_eq "$(get_csrf "$JAR_NEW")" 200 "csrf for the new-session QR"
CSRF_NEW_QR=$(json_get "$TMP/csrf.json" csrf)
E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-new-session-no-totp.json"
NEW_SESSION_QR_MISSING_CODE=$(admin_post_session "$JAR_NEW" "$CSRF_NEW_QR" "/__admin/api/qr" "$TMP/qr-new-session-no-totp.json" "$TMP/qr-new-session-missing.json")
assert_eq "$NEW_SESSION_QR_MISSING_CODE" 403 "new-session QR without a TOTP code"
assert_eq "$(json_get "$TMP/qr-new-session-missing.json" error)" "totp_required" "new-session QR missing TOTP error"
OLD_TOTP=$(E2E_TOTP_SECRET="$TOTP_SECRET" node tests/e2e-helpers.mjs totp-env)
E2E_TOTP="$OLD_TOTP" E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-new-session-old-totp.json"
NEW_SESSION_QR_OLD_CODE=$(admin_post_session "$JAR_NEW" "$CSRF_NEW_QR" "/__admin/api/qr" "$TMP/qr-new-session-old-totp.json" "$TMP/qr-new-session-old.json")
assert_eq "$NEW_SESSION_QR_OLD_CODE" 403 "new-session QR with the old TOTP secret after a reset"
assert_eq "$(json_get "$TMP/qr-new-session-old.json" error)" "totp_invalid" "old TOTP secret QR error"
NEW_TOTP=$(E2E_TOTP_SECRET="$NEW_TOTP_SECRET" node tests/e2e-helpers.mjs totp-env)
E2E_TOTP="$NEW_TOTP" E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-new-session-payload.json"
NEW_SESSION_QR_CODE=$(admin_post_session "$JAR_NEW" "$CSRF_NEW_QR" "/__admin/api/qr" "$TMP/qr-new-session-payload.json" "$TMP/qr-new-session.json")
assert_eq "$NEW_SESSION_QR_CODE" 200 "new-session QR with the new TOTP secret"
assert_file_contains "$TMP/qr-new-session.json" '<svg' "new-session QR SVG"
secret_not_in_file "$NEW_PASSWORD" "$TMP/qr-new-session.json" || fail "new password found in the QR response"
pass "new password login works without TOTP; the new session reaches /__admin and mints a QR with the new TOTP secret (old secret and missing code 403)"

curl -sk --max-time 10 -H "x-auth-gate-admin-key: $ADMIN_KEY" -o "$TMP/audit-final.json" "$BASE/__admin/api/audit"
secret_not_in_file "$PASSWORD" "$TMP/audit-final.json" || fail "password found in the final audit"
secret_not_in_file "$NEW_PASSWORD" "$TMP/audit-final.json" || fail "new password found in the final audit"
secret_not_in_file "$NEW_TOTP_SECRET" "$TMP/audit-final.json" || fail "new TOTP secret found in the final audit"
secret_not_in_file "$PW_DEVICE_TOKEN" "$TMP/audit-final.json" || fail "device token found in the final audit"
pass "password change needs currentPassword; every device/session is revoked and old credentials fail"

# ---------------------------------------------------------------------------
step "19. fresh deployment: WebUI setup wizard (separate stateDir on :$GATE_PORT_SETUP)"
rm -rf "$STATE_SETUP"
mkdir -p "$STATE_SETUP"
AUTH_GATE_LISTEN_HOST="$SETUP_HOST" \
AUTH_GATE_LISTEN_PORT="$GATE_PORT_SETUP" \
AUTH_GATE_UPSTREAM="$UPSTREAM" \
AUTH_GATE_UPSTREAM_INSECURE_TLS=true \
AUTH_GATE_PUBLIC_URL="$BASE_SETUP" \
AUTH_GATE_TLS_CERT="$CERT" \
AUTH_GATE_TLS_KEY="$KEY" \
AUTH_GATE_STATE_DIR="$STATE_SETUP" \
DSH_TOKEN_URL="$TOKEN_URL" \
node lib/standalone.js > "$TMP/gateway-setup.log" 2>&1 &
GW_SETUP_PID=$!
SETUP_READY=0
for _ in $(seq 1 80); do
  kill -0 "$GW_SETUP_PID" 2>/dev/null || fail "fresh setup gateway exited during startup"
  SETUP_CODE=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' "$BASE_SETUP/__admin/api/setup/status" || true)
  if [ "$SETUP_CODE" = "200" ]; then SETUP_READY=1; break; fi
  sleep 0.25
done
[ "$SETUP_READY" = 1 ] || fail "fresh setup gateway did not become ready"
pass "fresh standalone gateway listening on $BASE_SETUP with a new stateDir"

# The startup log must carry the one-time setup link (and only there).
grep -q 'auth-gate: setup required' "$TMP/gateway-setup.log" || fail "startup log has no setup-required line"
grep -q "#setup=" "$TMP/gateway-setup.log" || fail "startup log has no setup link"
[ -f "$STATE_SETUP/setup.token" ] || fail "setup.token was not created"
assert_eq "$(stat -c '%a' "$STATE_SETUP/setup.token")" 600 "setup.token permissions"
SETUP_TOKEN_ORIG=$(tr -d '\r\n' < "$STATE_SETUP/setup.token")
[ "${#SETUP_TOKEN_ORIG}" -eq 64 ] || fail "setup token must be 64 hex characters"
[[ "$SETUP_TOKEN_ORIG" =~ ^[0-9a-f]{64}$ ]] || fail "setup token must be lower-case hex"

SETUP_PAGE_CODE=$(curl -sk --max-time 10 -D "$TMP/setup-page-headers" -o "$TMP/setup-page.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP/__admin")
assert_eq "$SETUP_PAGE_CODE" 200 "GET /__admin on an unconfigured gateway"
assert_file_contains "$TMP/setup-page.html" '初始化 DSH 认证网关' "setup wizard title"
assert_file_contains "$TMP/setup-page.html" 'id="setup-form"' "setup wizard step 1 form"
assert_file_contains "$TMP/setup-page.html" 'id="setup-confirm-form"' "setup wizard step 2 form"
assert_file_contains "$TMP/setup-page.html" 'id="setup-totp"' "setup wizard TOTP input"
grep -qi '^x-frame-options: DENY' "$TMP/setup-page-headers" || fail "setup wizard must not be framable"
grep -qiE '^cache-control: (private, )?no-store' "$TMP/setup-page-headers" || fail "setup wizard must not be cached"
grep -qi '^content-security-policy:.*nonce-' "$TMP/setup-page-headers" || fail "setup wizard lost its CSP nonce"
secret_not_in_file "$SETUP_TOKEN_ORIG" "$TMP/setup-page.html" || fail "setup page echoed the token"

SETUP_STATUS_CODE=$(curl -sk --max-time 10 -o "$TMP/setup-status.json" -w '%{http_code}' "$BASE_SETUP/__admin/api/setup/status")
assert_eq "$SETUP_STATUS_CODE" 200 "setup status"
assert_eq "$(json_get "$TMP/setup-status.json" configured)" "false" "setup status configured"
assert_eq "$(json_get "$TMP/setup-status.json" hasToken)" "true" "setup status hasToken"
assert_eq "$(json_get "$TMP/setup-status.json" setupPath)" "/__admin" "setup status path"
secret_not_in_file "$SETUP_TOKEN_ORIG" "$TMP/setup-status.json" || fail "setup status echoed the token"

E2E_SETUP_TOKEN=$(printf '0%.0s' {1..64}) E2E_USERNAME="$USERNAME" E2E_PASSWORD="$PASSWORD" \
  node tests/e2e-helpers.mjs setup-begin-json "$TMP/setup-begin-wrong-token.json"
BEGIN_WRONG_TOKEN_CODE=$(curl -sk --max-time 30 -o "$TMP/setup-begin-wrong-token.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/begin" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-begin-wrong-token.json")
assert_eq "$BEGIN_WRONG_TOKEN_CODE" 403 "setup begin with a wrong token"
assert_eq "$(json_get "$TMP/setup-begin-wrong-token.out.json" error)" "setup_token_invalid" "wrong setup token error"
pass "wizard page 200 (DENY/no-store/nonce), status does not leak the token, wrong token 403"

# Rotate the token through the trusted adminKey channel; the old token and any
# pending draft must die with it.
SETUP_ADMIN_KEY=$(tr -d '\r\n' < "$STATE_SETUP/admin.key")
SETUP_ROTATE_CODE=$(curl -sk --max-time 10 -o "$TMP/setup-rotate.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/token" \
  -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' --data-binary '{}')
assert_eq "$SETUP_ROTATE_CODE" 200 "setup token rotation via adminKey"
ROTATED_SETUP_URL=$(json_get "$TMP/setup-rotate.json" setupUrl)
case "$ROTATED_SETUP_URL" in
  "$BASE_SETUP/__admin#setup="*) ;;
  *) fail "unexpected rotated setup URL shape" ;;
esac
SETUP_TOKEN="${ROTATED_SETUP_URL##*#setup=}"
[ "${#SETUP_TOKEN}" -eq 64 ] || fail "rotated setup token must be 64 hex characters"
[ "$SETUP_TOKEN" != "$SETUP_TOKEN_ORIG" ] || fail "rotation did not change the token"
assert_eq "$(tr -d '\r\n' < "$STATE_SETUP/setup.token")" "$SETUP_TOKEN" "rotated token file"
E2E_SETUP_TOKEN="$SETUP_TOKEN_ORIG" E2E_USERNAME="$USERNAME" E2E_PASSWORD="$PASSWORD" \
  node tests/e2e-helpers.mjs setup-begin-json "$TMP/setup-begin-old-token.json"
BEGIN_OLD_TOKEN_CODE=$(curl -sk --max-time 30 -o "$TMP/setup-begin-old-token.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/begin" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-begin-old-token.json")
assert_eq "$BEGIN_OLD_TOKEN_CODE" 403 "begin with the rotated-away token"
assert_eq "$(json_get "$TMP/setup-begin-old-token.out.json" error)" "setup_token_invalid" "old token error"

E2E_SETUP_TOKEN="$SETUP_TOKEN" E2E_USERNAME="$USERNAME" E2E_PASSWORD="$PASSWORD" \
  node tests/e2e-helpers.mjs setup-begin-json "$TMP/setup-begin.json"
SETUP_BEGIN_CODE=$(curl -sk --max-time 30 -o "$TMP/setup-begin.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/begin" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-begin.json")
assert_eq "$SETUP_BEGIN_CODE" 200 "setup begin"
assert_file_contains "$TMP/setup-begin.out.json" '<svg' "setup begin TOTP QR SVG"
assert_file_contains "$TMP/setup-begin.out.json" 'otpauth://totp/DSH:' "setup begin otpauth URI"
SETUP_SECRET=$(json_get "$TMP/setup-begin.out.json" secretB32)
[ -n "$SETUP_SECRET" ] || fail "setup begin returned no TOTP secret"
[[ "$SETUP_SECRET" =~ ^[A-Z2-7]{16,}$ ]] || fail "setup secret is not base32"
secret_not_in_file "$SETUP_SECRET" "$TMP/gateway-setup.log" || fail "TOTP secret found in the setup gateway log"
secret_not_in_file "$PASSWORD" "$TMP/gateway-setup.log" || fail "password found in the setup gateway log"
[ ! -f "$STATE_SETUP/state.json" ] || secret_not_in_file "$SETUP_SECRET" "$STATE_SETUP/state.json" || fail "pending secret persisted"

SETUP_TOTP=$(E2E_TOTP_SECRET="$SETUP_SECRET" node tests/e2e-helpers.mjs totp-env)
WRONG_SETUP_TOTP=000000
[ "$SETUP_TOTP" = "000000" ] && WRONG_SETUP_TOTP=000001
E2E_SETUP_TOKEN="$SETUP_TOKEN" E2E_TOTP="$WRONG_SETUP_TOTP" \
  node tests/e2e-helpers.mjs setup-confirm-json "$TMP/setup-confirm-wrong.json"
SETUP_CONFIRM_WRONG_CODE=$(curl -sk --max-time 30 -o "$TMP/setup-confirm-wrong.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/confirm" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-confirm-wrong.json")
assert_eq "$SETUP_CONFIRM_WRONG_CODE" 403 "setup confirm with a wrong TOTP"
assert_eq "$(json_get "$TMP/setup-confirm-wrong.out.json" error)" "totp_invalid" "wrong setup TOTP error"
SETUP_CONFIRM_STILL_UNCONFIGURED=$(curl -sk --max-time 10 -o "$TMP/setup-status-2.json" -w '%{http_code}' "$BASE_SETUP/__admin/api/setup/status")
assert_eq "$SETUP_CONFIRM_STILL_UNCONFIGURED" 200 "setup status after a wrong TOTP"
assert_eq "$(json_get "$TMP/setup-status-2.json" configured)" "false" "wrong TOTP must not configure the gateway"
pass "token rotation works; old token 403; begin returns QR/secret; wrong TOTP 403 and leaves the gate unconfigured"

SETUP_TOTP=$(E2E_TOTP_SECRET="$SETUP_SECRET" node tests/e2e-helpers.mjs totp-env)
JAR_SETUP="$TMP/jar-setup"
rm -f "$JAR_SETUP"
E2E_SETUP_TOKEN="$SETUP_TOKEN" E2E_TOTP="$SETUP_TOTP" \
  node tests/e2e-helpers.mjs setup-confirm-json "$TMP/setup-confirm.json"
SETUP_CONFIRM_CODE=$(curl -sk --max-time 30 -c "$JAR_SETUP" -b "$JAR_SETUP" \
  -o "$TMP/setup-confirm.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/confirm" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-confirm.json")
assert_eq "$SETUP_CONFIRM_CODE" 200 "setup confirm with the correct TOTP"
assert_eq "$(json_get "$TMP/setup-confirm.out.json" ok)" "true" "setup confirm response"
SETUP_DEVICE_COOKIE=$(node tests/e2e-helpers.mjs cookie "$JAR_SETUP" dsh_gate_device)
[ -n "$SETUP_DEVICE_COOKIE" ] || fail "setup confirm did not pair the browser (no dsh_gate_device cookie)"
curl -sk --max-time 10 -o "$TMP/setup-status-3.json" "$BASE_SETUP/__admin/api/setup/status"
assert_eq "$(json_get "$TMP/setup-status-3.json" configured)" "true" "configured after setup confirm"
assert_eq "$(json_get "$TMP/setup-status-3.json" hasToken)" "false" "hasToken after setup confirm"
[ ! -f "$STATE_SETUP/setup.token" ] || fail "setup.token still exists after initialization"
assert_eq "$(json_get "$STATE_SETUP/state.json" user.username)" "$USERNAME" "setup username in state"
assert_eq "$(json_get "$STATE_SETUP/state.json" devices.length)" "1" "initial device count"
assert_eq "$(json_get "$STATE_SETUP/state.json" devices.0.name)" "初始化浏览器" "initial device name"
assert_eq "$(json_get "$STATE_SETUP/state.json" devices.0.platform)" "web" "initial device platform"
secret_not_in_file "$PASSWORD" "$STATE_SETUP/state.json" || fail "password found in setup state"
secret_not_in_file "$SETUP_DEVICE_COOKIE" "$STATE_SETUP/state.json" || fail "device token found in setup state"
pass "setup confirm 200 + dsh_gate_device cookie, user/TOTP confirmed, web device paired, setup.token deleted"

# ---------------------------------------------------------------------------
step "20. initialized setup routes are closed; password login and /__admin work"
E2E_SETUP_TOKEN="$SETUP_TOKEN" E2E_USERNAME="$USERNAME" E2E_PASSWORD="$PASSWORD" \
  node tests/e2e-helpers.mjs setup-begin-json "$TMP/setup-begin-after.json"
SETUP_BEGIN_AFTER_CODE=$(curl -sk --max-time 10 -o "$TMP/setup-begin-after.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/begin" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-begin-after.json")
assert_eq "$SETUP_BEGIN_AFTER_CODE" 409 "setup begin after initialization"
assert_eq "$(json_get "$TMP/setup-begin-after.out.json" error)" "already_configured" "begin after setup error"
E2E_SETUP_TOKEN="$SETUP_TOKEN" E2E_TOTP="$SETUP_TOTP" \
  node tests/e2e-helpers.mjs setup-confirm-json "$TMP/setup-confirm-after.json"
SETUP_CONFIRM_AFTER_CODE=$(curl -sk --max-time 10 -o "$TMP/setup-confirm-after.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/confirm" -H 'content-type: application/json' \
  --data-binary @"$TMP/setup-confirm-after.json")
assert_eq "$SETUP_CONFIRM_AFTER_CODE" 409 "setup confirm after initialization"
assert_eq "$(json_get "$TMP/setup-confirm-after.out.json" error)" "already_configured" "confirm after setup error"
SETUP_TOKEN_AFTER_CODE=$(curl -sk --max-time 10 -o "$TMP/setup-rotate-after.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/setup/token" \
  -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' --data-binary '{}')
assert_eq "$SETUP_TOKEN_AFTER_CODE" 409 "setup token rotation after initialization"

SETUP_CSRF_CODE=$(curl -sk --max-time 10 -c "$JAR_SETUP" -b "$JAR_SETUP" -o "$TMP/csrf-setup.json" -w '%{http_code}' "$BASE_SETUP/__auth/csrf")
assert_eq "$SETUP_CSRF_CODE" 200 "csrf for the setup-paired browser"
SETUP_CSRF=$(json_get "$TMP/csrf-setup.json" csrf)
E2E_USERNAME="$USERNAME" E2E_PASSWORD="$PASSWORD" node tests/e2e-helpers.mjs login-json "$TMP/login-setup.json"
SETUP_LOGIN_CODE=$(curl -sk --max-time 30 -c "$JAR_SETUP" -b "$JAR_SETUP" -D "$TMP/login-setup-headers" \
  -o "$TMP/login-setup.out.json" -w '%{http_code}' -X POST "$BASE_SETUP/__auth/login" \
  -H 'content-type: application/json' -H "x-auth-gate-csrf: $SETUP_CSRF" \
  --data-binary @"$TMP/login-setup.json")
assert_eq "$SETUP_LOGIN_CODE" 200 "password login after WebUI setup"
assert_eq "$(json_get "$TMP/login-setup.out.json" ok)" "true" "setup login response"
grep -qi 'set-cookie:.*dsh_gate_session=.*HttpOnly.*SameSite=Lax.*Secure' "$TMP/login-setup-headers" || fail "setup login session cookie flags are wrong"

SETUP_ADMIN_PAGE_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" \
  -o "$TMP/setup-admin-page.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP/__admin")
assert_eq "$SETUP_ADMIN_PAGE_CODE" 200 "GET /__admin after initialization with a session"
assert_file_contains "$TMP/setup-admin-page.html" 'DSH 认证管理' "admin page after WebUI setup"
SETUP_ANON_ADMIN_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP/__admin")
assert_eq "$SETUP_ANON_ADMIN_CODE" 302 "GET /__admin after initialization without a session"
assert_eq "$(curl -sk --max-time 10 --interface "$SOURCE_IP" -o /dev/null -w '%{redirect_url}' -H 'Accept: text/html' "$BASE_SETUP/__admin")" "$BASE_SETUP/__auth/login?next=/__admin" "post-setup admin login redirect"

curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/setup-audit.json" "$BASE_SETUP/__admin/api/audit"
assert_file_contains "$TMP/setup-audit.json" 'setup_begin' "audit setup_begin"
assert_file_contains "$TMP/setup-audit.json" 'setup_confirm' "audit setup_confirm"
assert_file_contains "$TMP/setup-audit.json" 'setup_token_rotated' "audit setup_token_rotated"
secret_not_in_file "$SETUP_TOKEN" "$TMP/setup-audit.json" || fail "setup token found in audit"
secret_not_in_file "$SETUP_TOKEN_ORIG" "$TMP/setup-audit.json" || fail "old setup token found in audit"
secret_not_in_file "$SETUP_SECRET" "$TMP/setup-audit.json" || fail "TOTP secret found in audit"
secret_not_in_file "$PASSWORD" "$TMP/setup-audit.json" || fail "password found in audit"
secret_not_in_file "$SETUP_DEVICE_COOKIE" "$TMP/setup-audit.json" || fail "device token found in audit"
pass "after setup: begin/confirm/token-rotate 409, password login 200, session /__admin 200, anonymous 302, audit has setup events only"

# ---------------------------------------------------------------------------
step "21. network settings via session + TOTP: publicUrl drives the QR origin"
NETWORK_API="$BASE_SETUP/__admin/api/network"
NETWORK_JSON="$STATE_SETUP/network.json"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-initial.json" "$NETWORK_API"
assert_eq "$(json_get "$TMP/network-initial.json" network.listenPort)" "$GATE_PORT_SETUP" "initial network listenPort"
assert_eq "$(json_get "$TMP/network-initial.json" network.publicUrl)" "$BASE_SETUP" "initial network publicUrl"
assert_eq "$(json_get "$TMP/network-initial.json" network.tlsConfigured)" "true" "network TLS flag"
assert_eq "$(json_get "$TMP/network-initial.json" network.source)" "config" "initial network source"
NET_RULES_HOST=$(json_get "$TMP/network-initial.json" rules.listenHost)
[ -n "$NET_RULES_HOST" ] || fail "network API must document the listenHost validation rules"
[ ! -f "$NETWORK_JSON" ] || fail "network.json must not exist before the first network change"

# The server-rendered admin page exposes the same section/fields (embed=1 too).
SETUP_ADMIN_PAGE_NET_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" \
  -o "$TMP/setup-admin-page-network.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP/__admin")
assert_eq "$SETUP_ADMIN_PAGE_NET_CODE" 200 "admin page with network section"
assert_file_contains "$TMP/setup-admin-page-network.html" 'id="section-network"' "admin network section"
assert_file_contains "$TMP/setup-admin-page-network.html" 'id="network-listen-host"' "admin network listen host input"
assert_file_contains "$TMP/setup-admin-page-network.html" 'id="network-listen-port"' "admin network listen port input"
assert_file_contains "$TMP/setup-admin-page-network.html" 'id="network-public-url"' "admin network publicUrl input"
assert_file_contains "$TMP/setup-admin-page-network.html" 'id="network-totp"' "admin network TOTP input"
SETUP_EMBED_NET_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" \
  -o "$TMP/setup-admin-embed-network.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP/__admin?embed=1")
assert_eq "$SETUP_EMBED_NET_CODE" 200 "embedded admin page with network section"
assert_file_contains "$TMP/setup-admin-embed-network.html" 'id="section-network"' "embedded admin network section"
assert_file_contains "$TMP/setup-admin-embed-network.html" 'class="embed"' "embedded admin page marker"

assert_eq "$(get_csrf_at "$BASE_SETUP" "$JAR_SETUP" "$TMP/csrf-network.json")" 200 "csrf for network settings"
CSRF_NETWORK=$(json_get "$TMP/csrf-network.json" csrf)
NET_TOTP=$(E2E_TOTP_SECRET="$SETUP_SECRET" node tests/e2e-helpers.mjs totp-env)
NET_WRONG=000000
[ "$NET_TOTP" = "000000" ] && NET_WRONG=000001
NET_PUBLIC_URL='https://relay.example:8443'

E2E_PUBLIC_URL="$NET_PUBLIC_URL" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-no-totp.json"
NET_MISSING_CODE=$(admin_post_session_at "$BASE_SETUP" "$JAR_SETUP" "$CSRF_NETWORK" "/__admin/api/network" "$TMP/network-no-totp.json" "$TMP/network-missing.json")
assert_eq "$NET_MISSING_CODE" 403 "session network update without TOTP"
assert_eq "$(json_get "$TMP/network-missing.json" error)" "totp_required" "missing network TOTP error"

E2E_PUBLIC_URL="$NET_PUBLIC_URL" E2E_TOTP="$NET_WRONG" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-wrong-totp.json"
NET_WRONG_CODE=$(admin_post_session_at "$BASE_SETUP" "$JAR_SETUP" "$CSRF_NETWORK" "/__admin/api/network" "$TMP/network-wrong-totp.json" "$TMP/network-wrong.json")
assert_eq "$NET_WRONG_CODE" 403 "session network update with a wrong TOTP"
assert_eq "$(json_get "$TMP/network-wrong.json" error)" "totp_invalid" "wrong network TOTP error"

E2E_PUBLIC_URL="$NET_PUBLIC_URL/path" E2E_TOTP="$NET_TOTP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-bad-url.json"
NET_BAD_URL_CODE=$(admin_post_session_at "$BASE_SETUP" "$JAR_SETUP" "$CSRF_NETWORK" "/__admin/api/network" "$TMP/network-bad-url.json" "$TMP/network-bad-url.out.json")
assert_eq "$NET_BAD_URL_CODE" 400 "network update with a publicUrl path"
assert_eq "$(json_get "$TMP/network-bad-url.out.json" error)" "invalid_public_url" "invalid publicUrl error"
[ ! -f "$NETWORK_JSON" ] || fail "an invalid network update must not persist network.json"

E2E_PUBLIC_URL="$NET_PUBLIC_URL" E2E_TOTP="$NET_TOTP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-ok.json"
NET_OK_CODE=$(admin_post_session_at "$BASE_SETUP" "$JAR_SETUP" "$CSRF_NETWORK" "/__admin/api/network" "$TMP/network-ok.json" "$TMP/network-ok.out.json")
assert_eq "$NET_OK_CODE" 200 "session network update with the correct TOTP"
assert_eq "$(json_get "$TMP/network-ok.out.json" ok)" "true" "network update response"
assert_eq "$(json_get "$TMP/network-ok.out.json" rebound)" "false" "publicUrl-only update must not rebind"
assert_eq "$(json_get "$TMP/network-ok.out.json" network.publicUrl)" "$NET_PUBLIC_URL" "effective publicUrl"
assert_eq "$(json_get "$TMP/network-ok.out.json" network.source)" "override" "source after override"
assert_file_contains "$NETWORK_JSON" "\"publicUrl\": \"$NET_PUBLIC_URL\"" "network.json publicUrl"
assert_eq "$(stat -c '%a' "$NETWORK_JSON")" 600 "network.json permissions"
secret_not_in_file "$SETUP_SECRET" "$NETWORK_JSON" || fail "TOTP secret found in network.json"

# Pairing QR (session channel also needs TOTP) now points at the frp relay.
E2E_TOTP="$NET_TOTP" E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-network.json"
NET_QR_CODE=$(admin_post_session_at "$BASE_SETUP" "$JAR_SETUP" "$CSRF_NETWORK" "/__admin/api/qr" "$TMP/qr-network.json" "$TMP/qr-network.out.json")
assert_eq "$NET_QR_CODE" 200 "QR after publicUrl override"
NET_QR_URL=$(json_get "$TMP/qr-network.out.json" url)
case "$NET_QR_URL" in
  "$NET_PUBLIC_URL/__auth/pair#v=1&t="*) ;;
  *) fail "QR URL must use the new publicUrl host (got ${NET_QR_URL%%#*})" ;;
esac
assert_file_contains "$TMP/qr-network.out.json" '<svg' "QR after publicUrl override has an SVG"
assert_file_lacks "$TMP/network-ok.out.json" "$NET_TOTP" "network response must not echo the TOTP code"

# Restore the setup instance's original publicUrl through the adminKey channel
# (no TOTP) so later steps keep the documented origin.
E2E_PUBLIC_URL="$BASE_SETUP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-restore.json"
NET_RESTORE_CODE=$(curl -sk --max-time 10 -o "$TMP/network-restore.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-restore.json")
assert_eq "$NET_RESTORE_CODE" 200 "restore publicUrl via adminKey"
assert_eq "$(json_get "$TMP/network-restore.out.json" network.publicUrl)" "$BASE_SETUP" "restored publicUrl"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-after-restore.json" "$NETWORK_API"
assert_eq "$(json_get "$TMP/network-after-restore.json" network.source)" "override" "network.json stays the effective source"
pass "session+TOTP updates publicUrl; missing/wrong TOTP and invalid origin are refused; QR uses the relay origin; adminKey restores it"

# ---------------------------------------------------------------------------
step "22. live listen-port rebind: $GATE_PORT_SETUP -> $GATE_PORT_SETUP_TMP -> $GATE_PORT_SETUP"
port_is_listening "$GATE_PORT_SETUP_TMP" && fail "port $GATE_PORT_SETUP_TMP is already in use; set E2E_REBIND_PORT"
E2E_LISTEN_PORT="$GATE_PORT_SETUP_TMP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-rebind.json"
REBIND_CODE=$(curl -sk --max-time 10 -o "$TMP/network-rebind.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-rebind.json")
assert_eq "$REBIND_CODE" 200 "live listen-port rebind"
assert_eq "$(json_get "$TMP/network-rebind.out.json" rebound)" "true" "rebind response flag"
assert_eq "$(json_get "$TMP/network-rebind.out.json" network.listenPort)" "$GATE_PORT_SETUP_TMP" "new effective port"
printf 'Waiting for the rebound listener on port %s...\n' "$GATE_PORT_SETUP_TMP"
wait_for_https "$BASE_SETUP_TMP/__auth/login" || fail "rebound listener did not answer on $GATE_PORT_SETUP_TMP"
if curl -sk --max-time 3 -o /dev/null "$BASE_SETUP/__auth/login" 2>/dev/null; then
  fail "the old listener on $GATE_PORT_SETUP still accepts connections after the rebind"
fi
REBOUND_NETWORK_CODE=$(curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-rebound.json" -w '%{http_code}' "$BASE_SETUP_TMP/__admin/api/network")
assert_eq "$REBOUND_NETWORK_CODE" 200 "network API on the rebound port"
assert_eq "$(json_get "$TMP/network-rebound.json" network.listenPort)" "$GATE_PORT_SETUP_TMP" "network API reports the new port"
REBOUND_ADMIN_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" -o "$TMP/rebound-admin.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP_TMP/__admin")
assert_eq "$REBOUND_ADMIN_CODE" 200 "session admin page on the rebound port"
assert_file_contains "$TMP/rebound-admin.html" 'id="section-network"' "session admin page keeps the network section after rebind"
assert_file_contains "$NETWORK_JSON" "\"listenPort\": $GATE_PORT_SETUP_TMP" "network.json new port"

# Change it back; the gateway is now reachable on the temporary base only.
E2E_LISTEN_PORT="$GATE_PORT_SETUP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-rebind-back.json"
REBIND_BACK_CODE=$(curl -sk --max-time 10 -o "$TMP/network-rebind-back.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP_TMP/__admin/api/network" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-rebind-back.json")
assert_eq "$REBIND_BACK_CODE" 200 "rebind back to $GATE_PORT_SETUP"
assert_eq "$(json_get "$TMP/network-rebind-back.out.json" rebound)" "true" "rebind-back response flag"
wait_for_https "$BASE_SETUP/__auth/login" || fail "listener did not return to $GATE_PORT_SETUP"
if curl -sk --max-time 3 -o /dev/null "$BASE_SETUP_TMP/__auth/login" 2>/dev/null; then
  fail "the temporary listener on $GATE_PORT_SETUP_TMP still accepts connections"
fi
assert_file_contains "$NETWORK_JSON" "\"listenPort\": $GATE_PORT_SETUP" "network.json restored port"
pass "hot rebind 3458 -> 3459 -> 3458: old port closed, new port 200, network.json persisted each step, no process restart"

# ---------------------------------------------------------------------------
step "23. invalid network values: 400 + no persistence/rebind + audit"
E2E_LISTEN_HOST='0.0.0.0' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-bad-host.json"
BAD_HOST_CODE=$(curl -sk --max-time 10 -o "$TMP/network-bad-host.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-bad-host.json")
assert_eq "$BAD_HOST_CODE" 400 "wildcard listenHost"
assert_eq "$(json_get "$TMP/network-bad-host.out.json" error)" "invalid_listen_host" "wildcard listenHost error"
E2E_LISTEN_PORT="$DSH_PORT" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-upstream-port.json"
UPSTREAM_PORT_CODE=$(curl -sk --max-time 10 -o "$TMP/network-upstream-port.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-upstream-port.json")
assert_eq "$UPSTREAM_PORT_CODE" 400 "listenPort equal to the upstream port"
assert_eq "$(json_get "$TMP/network-upstream-port.out.json" error)" "invalid_listen_port" "upstream-port error"
E2E_PUBLIC_URL='http://relay.example:8443' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-bad-protocol.json"
BAD_PROTOCOL_CODE=$(curl -sk --max-time 10 -o "$TMP/network-bad-protocol.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-bad-protocol.json")
assert_eq "$BAD_PROTOCOL_CODE" 400 "http publicUrl while TLS is configured"
assert_eq "$(json_get "$TMP/network-bad-protocol.out.json" error)" "invalid_public_url" "protocol mismatch error"
assert_file_contains "$NETWORK_JSON" "\"listenPort\": $GATE_PORT_SETUP" "invalid updates must not change the persisted port"
assert_file_contains "$NETWORK_JSON" "\"publicUrl\": \"$BASE_SETUP\"" "invalid updates must not change the persisted publicUrl"
assert_eq "$(json_get "$NETWORK_JSON" publicUrl)" "$BASE_SETUP" "network.json publicUrl after invalid updates"
NETWORK_FINAL_CODE=$(curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-final.json" -w '%{http_code}' "$NETWORK_API")
assert_eq "$NETWORK_FINAL_CODE" 200 "network API after invalid updates"
assert_eq "$(json_get "$TMP/network-final.json" network.listenPort)" "$GATE_PORT_SETUP" "effective port after invalid updates"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-audit.json" "$BASE_SETUP/__admin/api/audit"
assert_file_contains "$TMP/network-audit.json" 'network_update' "audit network_update"
assert_file_contains "$TMP/network-audit.json" 'network_invalid_public_url' "audit rejected publicUrl"
assert_file_contains "$TMP/network-audit.json" 'network_invalid_listen_host' "audit rejected host"
secret_not_in_file "$SETUP_SECRET" "$TMP/network-audit.json" || fail "TOTP secret found in the network audit"
# v0.6.1: loopback is refused with a dedicated error code, and every IPv6
# wildcard spelling is normalized/rejected before it can bind 0.0.0.0.
E2E_LISTEN_HOST='127.0.0.1' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-loopback-host.json"
LOOPBACK_HOST_CODE=$(curl -sk --max-time 10 -o "$TMP/network-loopback-host.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-loopback-host.json")
assert_eq "$LOOPBACK_HOST_CODE" 400 "loopback listenHost"
assert_eq "$(json_get "$TMP/network-loopback-host.out.json" error)" "listen_host_loopback_not_allowed" "loopback listenHost error code"
assert_eq "$(json_get "$TMP/network-loopback-host.out.json" field)" "listenHost" "loopback listenHost field"
# The same rule applies when the operator asks for an IPv6 loopback spelling.
E2E_LISTEN_HOST='::1' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-loopback-v6.json"
LOOPBACK_V6_CODE=$(curl -sk --max-time 10 -o "$TMP/network-loopback-v6.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-loopback-v6.json")
assert_eq "$LOOPBACK_V6_CODE" 400 "IPv6 loopback listenHost"
assert_eq "$(json_get "$TMP/network-loopback-v6.out.json" error)" "listen_host_loopback_not_allowed" "IPv6 loopback error code"

for V6_WILDCARD in '::0' '0::0' '00::' '::ffff:0.0.0.0'; do
  E2E_LISTEN_HOST="$V6_WILDCARD" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-v6-wildcard.json"
  V6_WILDCARD_CODE=$(curl -sk --max-time 10 -o "$TMP/network-v6-wildcard.out.json" -w '%{http_code}' \
    -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
    --data-binary @"$TMP/network-v6-wildcard.json")
  assert_eq "$V6_WILDCARD_CODE" 400 "IPv6 wildcard spelling $V6_WILDCARD"
  assert_eq "$(json_get "$TMP/network-v6-wildcard.out.json" error)" "invalid_listen_host" "IPv6 wildcard error $V6_WILDCARD"
done

# v0.6.1 P1-2: if persistence fails, the new listener (already bound) is
# retired and the old listener keeps serving. Make network.json a directory so
# the atomic rename fails; then verify both ports.
mv "$NETWORK_JSON" "$NETWORK_JSON.e2e-bak"
mkdir "$NETWORK_JSON"
E2E_LISTEN_PORT="$GATE_PORT_SETUP_TMP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-persist-fail.json"
PERSIST_FAIL_CODE=$(curl -sk --max-time 10 -o "$TMP/network-persist-fail.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-persist-fail.json")
assert_eq "$PERSIST_FAIL_CODE" 400 "persistence failure after a successful bind"
assert_eq "$(json_get "$TMP/network-persist-fail.out.json" error)" "rebind_failed" "persistence failure error"
assert_eq "$(json_get "$TMP/network-persist-fail.out.json" reason)" "persist_failed" "persistence failure reason"
assert_eq "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$BASE_SETUP/__auth/login")" 200 "old listener still serves after persist failure"
if port_is_listening "$GATE_PORT_SETUP_TMP"; then fail "the newly bound listener leaked on port $GATE_PORT_SETUP_TMP after a persistence failure"; fi
NETWORK_FINAL_PORT=$(curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" "$NETWORK_API" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).network.listenPort)}catch{console.log("parse-error")}})')
assert_eq "$NETWORK_FINAL_PORT" "$GATE_PORT_SETUP" "effective port after persist-failure rollback"
rmdir "$NETWORK_JSON"
mv "$NETWORK_JSON.e2e-bak" "$NETWORK_JSON"

NET_FINAL_ADMIN_CODE=$(curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" -o "$TMP/network-final-admin.html" -w '%{http_code}' -H 'Accept: text/html' "$BASE_SETUP/__admin")
assert_eq "$NET_FINAL_ADMIN_CODE" 200 "admin page after the network scenario"
assert_file_contains "$TMP/network-final-admin.html" 'id="section-network"' "network section still rendered"
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-audit-v061.json" "$BASE_SETUP/__admin/api/audit"
assert_file_contains "$TMP/network-audit-v061.json" 'network_update_failed' "audit persistence failure"
assert_file_contains "$TMP/network-audit-v061.json" 'listen_host_loopback_not_allowed' "audit loopback rejection"
pass "loopback/IPv6-wildcard 400s, bind-first + persist-failure rollback keeps the old listener, no leaked new listener"

# ---------------------------------------------------------------------------
step "24. damaged network.json falls back to the bundle config at startup"
port_is_listening "$GATE_PORT_FALLBACK" && fail "port $GATE_PORT_FALLBACK is already in use; set E2E_FALLBACK_PORT"
rm -rf "$STATE_FALLBACK"
mkdir -p "$STATE_FALLBACK"
printf '{this is not json\n' > "$STATE_FALLBACK/network.json"
AUTH_GATE_LISTEN_HOST="$HOST" \
AUTH_GATE_LISTEN_PORT="$GATE_PORT_FALLBACK" \
AUTH_GATE_UPSTREAM="http://127.0.0.1:9" \
AUTH_GATE_PUBLIC_URL="http://$HOST:$GATE_PORT_FALLBACK" \
AUTH_GATE_STATE_DIR="$STATE_FALLBACK" \
DSH_TOKEN_URL="http://127.0.0.1:9/?token=unused" \
node lib/standalone.js > "$TMP/gateway-fallback.log" 2>&1 &
GW_FALLBACK_PID=$!
FALLBACK_READY=0
for _ in $(seq 1 80); do
  kill -0 "$GW_FALLBACK_PID" 2>/dev/null || fail "gateway exited instead of falling back on a damaged network.json"
  FALLBACK_CODE=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://$HOST:$GATE_PORT_FALLBACK/__auth/csrf" || true)
  if [ "$FALLBACK_CODE" = "200" ]; then FALLBACK_READY=1; break; fi
  sleep 0.25
done
[ "$FALLBACK_READY" = 1 ] || fail "gateway did not start on the bundle config after a damaged network.json"
grep -q 'network override' "$TMP/gateway-fallback.log" || fail "fallback log must name the damaged network override"
grep -q 'IGNORED' "$TMP/gateway-fallback.log" || fail "fallback log must say the override was ignored"
grep -q 'rm -f' "$TMP/gateway-fallback.log" || fail "fallback log must carry the recovery command"
FALLBACK_ADMIN_KEY=$(tr -d '\r\n' < "$STATE_FALLBACK/admin.key")
FALLBACK_NETWORK=$(curl -s --max-time 10 -H "x-auth-gate-admin-key: $FALLBACK_ADMIN_KEY" "http://$HOST:$GATE_PORT_FALLBACK/__admin/api/network")
assert_eq "$(printf '%s' "$FALLBACK_NETWORK" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).network.source)}catch{console.log("parse-error")}})')" "config" "fallback source"
assert_eq "$(printf '%s' "$FALLBACK_NETWORK" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).network.listenPort)}catch{console.log("parse-error")}})')" "$GATE_PORT_FALLBACK" "fallback listens on the bundle port"
grep -q 'not valid JSON' "$TMP/gateway-fallback.log" || fail "fallback log must name the invalid JSON"
kill "$GW_FALLBACK_PID" 2>/dev/null || true
wait "$GW_FALLBACK_PID" 2>/dev/null || true
GW_FALLBACK_PID=''
pass "damaged network.json is reported with recovery guidance and the gateway starts on the bundle config"

# ---------------------------------------------------------------------------
step "25. external certificate fingerprint: fixed/empty QR fp + auto-detect over TLS"
# Behind frp + Caddy the App sees the proxy certificate, so the QR fp must be
# overridable. Fixed values are validated/normalized, an empty value falls back
# to the gateway certificate, and "auto" reads the certificate of the saved
# publicUrl over a TLS handshake (no HTTP request is sent).
GATEWAY_FP=$(node tests/e2e-helpers.mjs cert-fingerprint "$CERT")
[[ "$GATEWAY_FP" =~ ^[0-9a-f]{64}$ ]] || fail "certificate fingerprint helper returned an invalid value"
FIXED_PUBLIC_FP=$(printf 'ab%.0s' {1..32})
assert_eq "${#FIXED_PUBLIC_FP}" 64 "fixed test fingerprint length"
[ "$FIXED_PUBLIC_FP" != "$GATEWAY_FP" ] || fail "fixed test fingerprint must differ from the gateway certificate"
NET_FP_INITIAL_CODE=$(curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-fp-initial.json" -w '%{http_code}' "$NETWORK_API")
assert_eq "$NET_FP_INITIAL_CODE" 200 "network API with publicFingerprint"
assert_eq "$(json_get "$TMP/network-fp-initial.json" network.publicFingerprint)" "" "initial publicFingerprint is empty"
assert_eq "$(json_get "$TMP/network-fp-initial.json" network.effectiveFingerprint)" "$GATEWAY_FP" "empty override falls back to the gateway certificate"
[ -n "$(json_get "$TMP/network-fp-initial.json" rules.publicFingerprint)" ] || fail "network API must document the publicFingerprint rules"

# Both server-rendered settings surfaces expose the field and the auto button.
curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" -o "$TMP/setup-admin-page-fp.html" -H 'Accept: text/html' "$BASE_SETUP/__admin"
assert_file_contains "$TMP/setup-admin-page-fp.html" 'id="network-public-fingerprint"' "admin page public fingerprint input"
assert_file_contains "$TMP/setup-admin-page-fp.html" 'id="network-fingerprint-auto"' "admin page fingerprint auto button"
assert_file_contains "$TMP/setup-admin-page-fp.html" '从对外地址自动读取' "admin page fingerprint auto label"
curl -sk --max-time 10 --interface "$SOURCE_IP" -b "$JAR_SETUP" -o "$TMP/setup-admin-embed-fp.html" -H 'Accept: text/html' "$BASE_SETUP/__admin?embed=1"
assert_file_contains "$TMP/setup-admin-embed-fp.html" 'id="network-public-fingerprint"' "embedded admin page public fingerprint input"
secret_not_in_file "$SETUP_SECRET" "$TMP/setup-admin-page-fp.html" || fail "TOTP secret found in the admin page"

# Invalid values: 400 with a field, and network.json is unchanged.
E2E_PUBLIC_FP='not-a-fingerprint' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-fp-bad.json"
NET_FP_BAD_CODE=$(curl -sk --max-time 10 -o "$TMP/network-fp-bad.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-fp-bad.json")
assert_eq "$NET_FP_BAD_CODE" 400 "invalid publicFingerprint"
assert_eq "$(json_get "$TMP/network-fp-bad.out.json" error)" "invalid_public_fingerprint" "invalid publicFingerprint error"
assert_eq "$(json_get "$TMP/network-fp-bad.out.json" field)" "publicFingerprint" "invalid publicFingerprint field"

# The session channel still needs TOTP for fingerprint writes too.
E2E_PUBLIC_FP="$FIXED_PUBLIC_FP" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-fp-no-totp.json"
NET_FP_NO_TOTP_CODE=$(admin_post_session_at "$BASE_SETUP" "$JAR_SETUP" "$CSRF_NETWORK" "/__admin/api/network" "$TMP/network-fp-no-totp.json" "$TMP/network-fp-no-totp.out.json")
assert_eq "$NET_FP_NO_TOTP_CODE" 403 "session publicFingerprint update without TOTP"
assert_eq "$(json_get "$TMP/network-fp-no-totp.out.json" error)" "totp_required" "missing fingerprint TOTP error"

# Fixed fingerprint (upper-case input is normalized) drives the QR fp=.
E2E_PUBLIC_FP="$(printf 'AB%.0s' {1..32})" node tests/e2e-helpers.mjs admin-network-json "$TMP/network-fp-fixed.json"
NET_FP_FIXED_CODE=$(curl -sk --max-time 10 -o "$TMP/network-fp-fixed.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-fp-fixed.json")
assert_eq "$NET_FP_FIXED_CODE" 200 "fixed publicFingerprint via adminKey"
assert_eq "$(json_get "$TMP/network-fp-fixed.out.json" network.publicFingerprint)" "$FIXED_PUBLIC_FP" "normalized fixed fingerprint"
assert_eq "$(json_get "$TMP/network-fp-fixed.out.json" network.effectiveFingerprint)" "$FIXED_PUBLIC_FP" "fixed effective fingerprint"
assert_file_contains "$NETWORK_JSON" "\"publicFingerprint\": \"$FIXED_PUBLIC_FP\"" "network.json publicFingerprint"
assert_eq "$(stat -c '%a' "$NETWORK_JSON")" 600 "network.json permissions with fingerprint"
E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-fp-fixed.json"
QR_FP_FIXED_CODE=$(curl -sk --max-time 10 -o "$TMP/qr-fp-fixed.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/qr" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/qr-fp-fixed.json")
assert_eq "$QR_FP_FIXED_CODE" 200 "QR with a fixed publicFingerprint"
assert_eq "$(node tests/e2e-helpers.mjs pair-fp "$TMP/qr-fp-fixed.out.json")" "$FIXED_PUBLIC_FP" "QR fp uses the fixed publicFingerprint"

# "auto": the saved publicUrl is this throwaway setup instance itself, so the
# probe reads the same test certificate over a TLS handshake. This is a test
# gateway, never the production one; no HTTP request is sent.
E2E_PUBLIC_FP='auto' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-fp-auto.json"
NET_FP_AUTO_CODE=$(curl -sk --max-time 20 -o "$TMP/network-fp-auto.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-fp-auto.json")
assert_eq "$NET_FP_AUTO_CODE" 200 "auto publicFingerprint over TLS"
assert_eq "$(json_get "$TMP/network-fp-auto.out.json" network.publicFingerprint)" "$GATEWAY_FP" "auto-detected fingerprint"
assert_eq "$(json_get "$TMP/network-fp-auto.out.json" network.effectiveFingerprint)" "$GATEWAY_FP" "auto effective fingerprint"
assert_file_contains "$NETWORK_JSON" "\"publicFingerprint\": \"$GATEWAY_FP\"" "network.json auto fingerprint"
E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-fp-auto.json"
QR_FP_AUTO_CODE=$(curl -sk --max-time 10 -o "$TMP/qr-fp-auto.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/qr" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/qr-fp-auto.json")
assert_eq "$QR_FP_AUTO_CODE" 200 "QR after auto fingerprint"
assert_eq "$(node tests/e2e-helpers.mjs pair-fp "$TMP/qr-fp-auto.out.json")" "$GATEWAY_FP" "QR fp uses the auto-detected fingerprint"

# A failed probe (the step-24 fallback port is closed again) is a 400 and
# persists neither the submitted publicUrl nor a fingerprint change.
E2E_PUBLIC_URL="https://$SETUP_HOST:$GATE_PORT_FALLBACK" E2E_PUBLIC_FP='auto' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-fp-fail.json"
NET_FP_FAIL_CODE=$(curl -sk --max-time 20 -o "$TMP/network-fp-fail.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-fp-fail.json")
assert_eq "$NET_FP_FAIL_CODE" 400 "failed auto fingerprint probe"
assert_eq "$(json_get "$TMP/network-fp-fail.out.json" error)" "fingerprint_fetch_failed" "probe failure error"
[ -n "$(json_get "$TMP/network-fp-fail.out.json" reason)" ] || fail "probe failure must carry a coarse reason"
assert_file_contains "$NETWORK_JSON" "\"publicUrl\": \"$BASE_SETUP\"" "probe failure keeps the saved publicUrl"
assert_file_contains "$NETWORK_JSON" "\"publicFingerprint\": \"$GATEWAY_FP\"" "probe failure keeps the saved fingerprint"
NET_FP_STILL=$(curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" "$NETWORK_API")
assert_eq "$(printf '%s' "$NET_FP_STILL" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).network.publicUrl)}catch{console.log("parse-error")}})')" "$BASE_SETUP" "failed probe does not move publicUrl"

# Clearing the field returns to the gateway certificate and drops the key from
# network.json (absent == empty == use the gateway certificate).
E2E_PUBLIC_FP='' node tests/e2e-helpers.mjs admin-network-json "$TMP/network-fp-clear.json"
NET_FP_CLEAR_CODE=$(curl -sk --max-time 10 -o "$TMP/network-fp-clear.out.json" -w '%{http_code}' \
  -X POST "$NETWORK_API" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/network-fp-clear.json")
assert_eq "$NET_FP_CLEAR_CODE" 200 "clear publicFingerprint"
assert_eq "$(json_get "$TMP/network-fp-clear.out.json" network.publicFingerprint)" "" "cleared publicFingerprint"
assert_eq "$(json_get "$TMP/network-fp-clear.out.json" network.effectiveFingerprint)" "$GATEWAY_FP" "cleared effective fingerprint"
assert_file_lacks "$NETWORK_JSON" '"publicFingerprint"' "empty publicFingerprint omitted from network.json"
E2E_PLATFORM=android node tests/e2e-helpers.mjs admin-qr-json "$TMP/qr-fp-clear.json"
QR_FP_CLEAR_CODE=$(curl -sk --max-time 10 -o "$TMP/qr-fp-clear.out.json" -w '%{http_code}' \
  -X POST "$BASE_SETUP/__admin/api/qr" -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -H 'content-type: application/json' \
  --data-binary @"$TMP/qr-fp-clear.json")
assert_eq "$QR_FP_CLEAR_CODE" 200 "QR after clearing the fingerprint"
assert_eq "$(node tests/e2e-helpers.mjs pair-fp "$TMP/qr-fp-clear.out.json")" "$GATEWAY_FP" "QR fp falls back to the gateway certificate"

# Audit keeps a short prefix only (the fingerprint is public, but the log stays
# concise) and records the failure without the TOTP secret.
curl -sk --max-time 10 -H "x-auth-gate-admin-key: $SETUP_ADMIN_KEY" -o "$TMP/network-audit-fp.json" "$BASE_SETUP/__admin/api/audit"
assert_file_contains "$TMP/network-audit-fp.json" "public_fp=${FIXED_PUBLIC_FP:0:8}" "audit fixed fingerprint prefix"
assert_file_contains "$TMP/network-audit-fp.json" 'fingerprint_fetch_failed' "audit failed probe"
assert_file_lacks "$TMP/network-audit-fp.json" "$FIXED_PUBLIC_FP" "audit must not carry the full fingerprint"
secret_not_in_file "$SETUP_SECRET" "$NETWORK_JSON" || fail "TOTP secret found in network.json"
secret_not_in_file "$SETUP_SECRET" "$TMP/network-audit-fp.json" || fail "TOTP secret found in the fingerprint audit"
pass "fixed/normalized and auto-detected publicFingerprint drive the QR fp; empty falls back to the gateway certificate; failed probes are 400 with no persistence; session writes still need TOTP"

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
step "26. sliding session / device lifetimes with an injectable clock"
# The main gateway runs on the real clock, so the 1h refresh interval and the
# 30-day absolute ceiling cannot be observed in a few seconds. This in-process
# harness drives the *same* gateway code over real HTTP with an injected clock
# (10 scenarios: device renew cap, login slide, renew cookies, session slide +
# cookie Max-Age, absolute ceiling, idle expiry, revoke cascade, prune cascade,
# v0.7.1 P2-1 cookie-cache/asset no-refresh, v0.7.1 P2-3 over-age device reads).
if ! node --test tests/sliding.test.js > "$TMP/sliding.log" 2>&1; then
  tail -n 80 "$TMP/sliding.log" >&2
  fail "sliding lifetime scenario failed"
fi
grep -q '^# fail 0$' "$TMP/sliding.log" || fail "sliding lifetime scenario reported failures"
grep -q '^ok .*P2-1: cookie responses' "$TMP/sliding.log" || fail "P2-1 cookie/asset scenario did not run"
grep -q '^ok .*P2-3: over-age devices' "$TMP/sliding.log" || fail "P2-3 absolute read-path scenario did not run"
pass "device/session sliding, absolute ceilings and revoke/prune cascade pass over real HTTP"

# ---------------------------------------------------------------------------
step "27. v0.7.1 P2-1: cookie responses private/no-store + Vary: cookie, assets set none"
# Every response that attaches a gateway cookie (CSRF, login, renew, session
# refresh) must be uncacheable by a shared cache. login-new-headers and
# renew-headers were captured earlier from real Set-Cookie responses.
grep -qi '^cache-control: private, no-store' "$TMP/login-page-headers" || fail "CSRF-bearing login page is not private/no-store"
grep -qi '^vary: cookie' "$TMP/login-page-headers" || fail "CSRF-bearing login page is missing Vary: cookie"
grep -qi '^cache-control: private, no-store' "$TMP/login-new-headers" || fail "login response is not private/no-store"
grep -qi '^vary: cookie' "$TMP/login-new-headers" || fail "login response is missing Vary: cookie"
grep -qi '^cache-control: private, no-store' "$TMP/renew-headers" || fail "renew response is not private/no-store"
grep -qi '^vary: cookie' "$TMP/renew-headers" || fail "renew response is missing Vary: cookie"
# A public dist asset fetched with a valid session cookie must not require
# auth, must not re-issue cookies and must therefore stay cacheable as-is.
ASSET_CODE=$(curl -sk --max-time 20 -D "$TMP/asset-headers" -o "$TMP/asset-body" -w '%{http_code}' \
  -b "$JAR_NEW" -H 'Accept: */*' "$BASE/assets/v0.7.1-cookie-cache-probe.js")
case "$ASSET_CODE" in
  401|302) fail "public asset with a session cookie must stay public (got $ASSET_CODE)" ;;
esac
! grep -qi '^set-cookie:' "$TMP/asset-headers" || fail "public asset response must not set cookies"
pass "cookie responses carry private/no-store + Vary: cookie; assets stay cookie-less and public"

# ---------------------------------------------------------------------------
step "result"
printf 'E2E PASSED\n'
