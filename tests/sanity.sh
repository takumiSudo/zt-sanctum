#!/usr/bin/env bash
set -euo pipefail

# Always (re)build the PoCA signer if missing
if [[ ! -x "tools/poca_sign/poca_sign" ]]; then
  (cd tools/poca_sign && go build -o poca_sign)
fi

# 1) Generate fresh PoCA headers + body every run (prevents replay/expiry)
tools/poca_sign/poca_sign -key pki/agent.key > /tmp/poca.txt

# 2) Extract + export env vars for this shell and children
export MAN="$(sed -n 's/^X-PoCA-Manifest: //p'  /tmp/poca.txt | tr -d '\r\n')"
export SIG="$(sed -n 's/^X-PoCA-Signature: //p' /tmp/poca.txt | tr -d '\r\n')"
export BODY="$(sed -n 's/^Body: //p'            /tmp/poca.txt)"

# 3) Sanity: print lengths (manifest/signature/body)
echo "${#MAN} ${#SIG} ${#BODY}"

# 4) Optional: show decoded manifest if python is available (silently ignore errors)
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY' >/dev/null || true
import base64, json, os
m = os.environ["MAN"]
pad = '=' * (-len(m) % 4)
raw = base64.urlsafe_b64decode(m + pad)
_ = json.loads(raw.decode())
PY
fi

# 5) Call the gateway
curl -k https://localhost:8443/relay \
  --cert certs/client.crt \
  --key  certs/client.key \
  --cacert certs/ca.crt \
  -H "Content-Type: application/json" \
  -H "X-PoCA-Manifest: $MAN" \
  -H "X-PoCA-Signature: $SIG" \
  -d "$BODY"

# 6) If denied, show the last audit line for quick diagnosis
if [[ "${PIPESTATUS[0]}" -ne 0 ]]; then
  echo
  echo "--- last audit line ---"
  if command -v jq >/dev/null 2>&1; then
    tail -n 1 logs/audit.jsonl | jq .
  else
    tail -n 1 logs/audit.jsonl
  fi
fi