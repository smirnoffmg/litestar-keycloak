#!/usr/bin/env bash
# Smoke tests for the example app.
# Prerequisites: Keycloak and the example app are running (e.g. docker compose up, or keycloak + app locally).
#
# Usage (from repo root):
#   ./examples/test.sh
# Or with custom URLs:
#   KEYCLOAK_URL=http://localhost:8080 APP_URL=http://localhost:8000 ./examples/test.sh

set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
APP_URL="${APP_URL:-http://localhost:8000}"
REALM="${REALM:-test-realm}"
CLIENT_ID="${CLIENT_ID:-test-app}"
CLIENT_SECRET="${CLIENT_SECRET:-test-secret}"
SERVICE_CLIENT_ID="${SERVICE_CLIENT_ID:-test-service}"
SERVICE_CLIENT_SECRET="${SERVICE_CLIENT_SECRET:-service-secret}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail() { echo -e "${RED}FAIL${NC}: $*"; return 1; }
pass() { echo -e "${GREEN}PASS${NC}: $*"; return 0; }

# --- Token helpers ---
token_url="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

json_access_token() {
  python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true
}

get_user_token() {
  curl -sf -X POST "$token_url" \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=testuser" \
    -d "password=testpass" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    | json_access_token
}

get_admin_token() {
  curl -sf -X POST "$token_url" \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=testadmin" \
    -d "password=testpass" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    | json_access_token
}

get_service_token() {
  curl -sf -X POST "$token_url" \
    -d "grant_type=client_credentials" \
    -d "client_id=$SERVICE_CLIENT_ID" \
    -d "client_secret=$SERVICE_CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    | json_access_token
}

# --- Tests ---
run_tests() {
  local err=0

  # Public
  if curl -sf -o /dev/null -w "%{http_code}" "$APP_URL/" | grep -q 200; then
    pass "GET / returns 200"
  else
    fail "GET / returns 200"; err=1
  fi

  if curl -sf -o /dev/null -w "%{http_code}" "$APP_URL/health" | grep -q 200; then
    pass "GET /health returns 200"
  else
    fail "GET /health returns 200"; err=1
  fi

  # Unauthenticated /me
  code=$(curl -s -o /dev/null -w "%{http_code}" "$APP_URL/me" || true)
  if [ "$code" = "401" ]; then
    pass "GET /me without token returns 401"
  else
    fail "GET /me without token returns 401 (got $code)"; err=1
  fi

  # User token
  user_token=$(get_user_token)
  if [ -z "$user_token" ]; then
    fail "Obtain user token (testuser)"; err=1
  else
    pass "Obtain user token (testuser)"
  fi

  if [ -n "$user_token" ]; then
    code=$(curl -sf -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $user_token" "$APP_URL/me" || true)
    if [ "$code" = "200" ]; then
      pass "GET /me with user token returns 200"
    else
      fail "GET /me with user token returns 200 (got $code)"; err=1
    fi

    body=$(curl -sf -H "Authorization: Bearer $user_token" "$APP_URL/me" || true)
    if echo "$body" | grep -q '"preferred_username":"testuser"'; then
      pass "GET /me contains testuser"
    else
      fail "GET /me contains testuser"; err=1
    fi

    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $user_token" "$APP_URL/admin" || true)
    if [ "$code" = "403" ]; then
      pass "GET /admin with user token returns 403"
    else
      fail "GET /admin with user token returns 403 (got $code)"; err=1
    fi
  fi

  # Admin token
  admin_token=$(get_admin_token)
  if [ -z "$admin_token" ]; then
    fail "Obtain admin token (testadmin)"; err=1
  else
    pass "Obtain admin token (testadmin)"
  fi

  if [ -n "$admin_token" ]; then
    code=$(curl -sf -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $admin_token" "$APP_URL/admin" || true)
    if [ "$code" = "200" ]; then
      pass "GET /admin with admin token returns 200"
    else
      fail "GET /admin with admin token returns 200 (got $code)"; err=1
    fi
  fi

  # Service-to-service: client_credentials
  service_token=$(get_service_token)
  if [ -z "$service_token" ]; then
    fail "Obtain service token (client_credentials)"; err=1
  else
    pass "Obtain service token (client_credentials)"
  fi

  if [ -n "$service_token" ]; then
    code=$(curl -sf -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $service_token" "$APP_URL/internal/backend" || true)
    if [ "$code" = "200" ]; then
      pass "GET /internal/backend with service token returns 200"
    else
      fail "GET /internal/backend with service token returns 200 (got $code)"; err=1
    fi
  fi

  # Service-to-service: app calls backend with service token
  code=$(curl -sf -o /dev/null -w "%{http_code}" "$APP_URL/service/call-backend" || true)
  if [ "$code" = "200" ]; then
    pass "GET /service/call-backend returns 200"
  else
    fail "GET /service/call-backend returns 200 (got $code)"; err=1
  fi

  # User token forward (requires valid user token)
  if [ -n "$user_token" ]; then
    code=$(curl -sf -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $user_token" "$APP_URL/user/forward" || true)
    if [ "$code" = "200" ]; then
      pass "GET /user/forward with user token returns 200"
    else
      fail "GET /user/forward with user token returns 200 (got $code)"; err=1
    fi
  fi

  return $err
}

echo "Keycloak: $KEYCLOAK_URL  App: $APP_URL"
if ! curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "$APP_URL/health" | grep -q 200; then
  echo "Error: App not reachable at $APP_URL (start Keycloak and the example app first)"
  exit 1
fi
if ! curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "$KEYCLOAK_URL/realms/$REALM/.well-known/openid-configuration" | grep -q 200; then
  echo "Error: Keycloak not reachable at $KEYCLOAK_URL"
  exit 1
fi
echo "---"
run_tests
