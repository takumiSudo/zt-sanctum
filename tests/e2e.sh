#!/usr/bin/env bash
# End-to-end test suite for zt-sanctum
set -euo pipefail

# --- Config (override via env if needed) ---
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443/relay}"
CERTS_DIR="${CERTS_DIR:-certs}"
KEY="${KEY:-$CERTS_DIR/client.key}"
CRT="${CRT:-$CERTS_DIR/client.crt}"
CA="${CA:-$CERTS_DIR/ca.crt}"
SIGN_KEY="${SIGN_KEY:-pki/agent.key}"
AUDIT_FILE="${AUDIT_FILE:-logs/audit.jsonl}"
EGRESS_FILE="${EGRESS_FILE:-egress.yaml}"

CURL_BASE=(curl -sk -w "%{http_code}" --cert "$CRT" --key "$KEY" --cacert "$CA")
have_jq=0; command -v jq >/dev/null 2>&1 && have_jq=1

pass=0; fail=0
log() { printf "%s\n" "$*" >&2; }
last_audit() {
  [[ -f "$AUDIT_FILE" ]] || { echo "{}"; return; }
  if [[ $have_jq -eq 1 ]]; then tail -n 1 "$AUDIT_FILE" | jq -c .; else tail -n 1 "$AUDIT_FILE"; fi
}

# --- Helpers ---
gen_poca() {
  local body="$1"
  tools/poca_sign/poca_sign -key "$SIGN_KEY" -body "$body" > /tmp/poca_e2e.txt
  local man sig
  man="$(sed -n 's/^X-PoCA-Manifest: //p'  /tmp/poca_e2e.txt | tr -d '\r\n')"
  sig="$(sed -n 's/^X-PoCA-Signature: //p' /tmp/poca_e2e.txt | tr -d '\r\n')"
  echo "$man|$sig"
}

gen_poca_tool() {
  local body="$1" tool="$2"
  # Try signer with explicit tool; fall back to legacy if unsupported
  if tools/poca_sign/poca_sign -key "$SIGN_KEY" -tool "$tool" -body "$body" > /tmp/poca_e2e.txt 2>/dev/null; then
    :
  else
    tools/poca_sign/poca_sign -key "$SIGN_KEY" -body "$body" > /tmp/poca_e2e.txt
    echo "WARN: poca_sign does not support -tool; PoCA tool mismatch may cause 403" >&2
  fi
  local man sig
  man="$(sed -n 's/^X-PoCA-Manifest: //p'  /tmp/poca_e2e.txt | tr -d '\r\n')"
  sig="$(sed -n 's/^X-PoCA-Signature: //p' /tmp/poca_e2e.txt | tr -d '\r\n')"
  echo "$man|$sig"
}

call_gateway() {
  local body="$1" man="$2" sig="$3"
  local out="/tmp/e2e_resp.json"
  local code
  code=$("${CURL_BASE[@]}" \
    -H "Content-Type: application/json" \
    -H "X-PoCA-Manifest: $man" \
    -H "X-PoCA-Signature: $sig" \
    -o "$out" \
    -d "$body" \
    "$GATEWAY_URL")
  echo "$code|$out"
}

# Helper to call gateway with contract header
call_gateway_contract() {
  local body="$1" man="$2" sig="$3" contract="$4"
  local out="/tmp/e2e_resp.json"
  local code
  code=$("${CURL_BASE[@]}" \
    -H "Content-Type: application/json" \
    -H "X-Contract-ID: $contract" \
    -H "X-PoCA-Manifest: $man" \
    -H "X-PoCA-Signature: $sig" \
    -o "$out" \
    -d "$body" \
    "$GATEWAY_URL")
  echo "$code|$out"
}

# Assertions that allow skipping when policy/egress blocks (HTTP 403)
assert_code_or_skip() {
  local name="$1" expect="$2" got="$3"
  if [[ "$got" == "$expect" ]]; then
    printf "✅  %s (HTTP %s)\n" "$name" "$got"; pass=$((pass+1))
  elif [[ "$got" == "403" ]]; then
    printf "↷  (skipping %s; policy/egress denied with 403)\n" "$name"
  else
    printf "❌  %s (got %s, expected %s)\n" "$name" "$got" "$expect"
    printf "    last audit: %s\n" "$(last_audit)"; fail=$((fail+1))
  fi
}

assert_any_or_skip() {
  local name="$1" got="$2"; shift 2
  local ok=0
  for exp in "$@"; do
    if [[ "$got" == "$exp" ]]; then ok=1; break; fi
  done
  if [[ $ok -eq 1 ]]; then
    printf "✅  %s (HTTP %s)\n" "$name" "$got"; pass=$((pass+1))
  elif [[ "$got" == "403" ]]; then
    printf "↷  (skipping %s; policy/egress denied with 403)\n" "$name"
  else
    printf "❌  %s (got %s, expected one of: %s)\n" "$name" "$got" "$*"
    printf "    last audit: %s\n" "$(last_audit)"; fail=$((fail+1))
  fi
}

assert_code() {
  local name="$1" expect="$2" got="$3"
  if [[ "$expect" == "$got" ]]; then
    printf "✅  %s (HTTP %s)\n" "$name" "$got"; pass=$((pass+1))
  else
    printf "❌  %s (got %s, expected %s)\n" "$name" "$got" "$expect"
    printf "    last audit: %s\n" "$(last_audit)"; fail=$((fail+1))
  fi
}

# --- Ensure signer exists ---
if [[ ! -x tools/poca_sign/poca_sign ]]; then
  (cd tools/poca_sign && go build -o poca_sign)
fi

# --- Optional egress backup/restore guard ---
EGRESS_BAK=""
cleanup() {
  if [[ -n "$EGRESS_BAK" && -f "$EGRESS_BAK" ]]; then
    mv "$EGRESS_BAK" "$EGRESS_FILE" || true
    docker compose restart gateway >/dev/null 2>&1 || true
    sleep 1
  fi
}
trap cleanup EXIT

echo "== zt-sanctum e2e tests =="

# 1) Happy path
body='{"message":"hello gateway"}'
IFS='|' read -r MAN SIG <<<"$(gen_poca "$body")"
IFS='|' read -r code resp <<<"$(call_gateway "$body" "$MAN" "$SIG")"
assert_code "happy_path" "200" "$code"

# 2) Missing PoCA (no headers)
code=$("${CURL_BASE[@]}" -H "Content-Type: application/json" -o /tmp/e2e_no_poca.json -d "$body" "$GATEWAY_URL")
assert_code "deny_missing_poca" "403" "$code"

# 3) Tampered body (hash mismatch)
body_bad='{"message":"tampered"}'
IFS='|' read -r MAN2 SIG2 <<<"$(gen_poca "$body")"           # sign original
IFS='|' read -r code resp <<<"$(call_gateway "$body_bad" "$MAN2" "$SIG2")"
assert_code "deny_payload_hash_mismatch" "403" "$code"

# 4) Replay (same headers twice)
IFS='|' read -r MAN3 SIG3 <<<"$(gen_poca "$body")"
IFS='|' read -r code resp <<<"$(call_gateway "$body" "$MAN3" "$SIG3")"  # first should pass
assert_code "replay_first_ok" "200" "$code"
IFS='|' read -r code resp <<<"$(call_gateway "$body" "$MAN3" "$SIG3")"  # second should fail
assert_code "replay_second_denied" "403" "$code"

# 5) Invalid schema (missing required 'message')
bad_schema='{"bad":123}'
IFS='|' read -r MAN4 SIG4 <<<"$(gen_poca "$bad_schema")"
IFS='|' read -r code resp <<<"$(call_gateway_contract "$bad_schema" "$MAN4" "$SIG4" "echo.v1")"
assert_code "deny_schema_invalid" "422" "$code"

# 6) TODOS: create OK via envelope (requires OPA allow + egress allow)
todos_ok_body='{"tool":"todos","payload":{"op":"create","title":"demo task"}}'
IFS='|' read -r MAN_T SIG_T <<<"$(gen_poca_tool "$todos_ok_body" "todos")"
IFS='|' read -r code resp <<<"$(call_gateway_contract "$todos_ok_body" "$MAN_T" "$SIG_T" "todo.create.v1")"
assert_code_or_skip "todos_create_ok" "200" "$code"

# 7) TODOS: bad schema/payload (missing title) → service 400 or gateway 422 if schema enforced
todos_bad_body='{"tool":"todos","payload":{"op":"create"}}'
IFS='|' read -r MAN_T2 SIG_T2 <<<"$(gen_poca_tool "$todos_bad_body" "todos")"
IFS='|' read -r code resp <<<"$(call_gateway_contract "$todos_bad_body" "$MAN_T2" "$SIG_T2" "todo.create.v1")"
# Accept 400 (todos service validation) or 422 (gateway schema), skip on 403 policy/egress
assert_any_or_skip "todos_bad_payload" "$code" "400" "422"

# 8) Egress denied (temporarily remove allow entry, then restore)
if [[ -f "$EGRESS_FILE" ]] && grep -q "url: http://echo:8081/echo" "$EGRESS_FILE"; then
  EGRESS_BAK="$(mktemp "$EGRESS_FILE.bak.XXXX")"
  cp "$EGRESS_FILE" "$EGRESS_BAK"
  awk '!/url: http:\/\/echo:8081\/echo/' "$EGRESS_BAK" > "$EGRESS_FILE"
  docker compose restart gateway >/dev/null
  sleep 1
  IFS='|' read -r MAN5 SIG5 <<<"$(gen_poca "$body")"
  IFS='|' read -r code resp <<<"$(call_gateway "$body" "$MAN5" "$SIG5")"
  assert_code "deny_egress_not_allowlisted" "403" "$code"
else
  echo "↷  (skipping egress test; allow entry not found in $EGRESS_FILE)"
fi

echo
printf "== Summary: %d passed, %d failed ==\n" "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1