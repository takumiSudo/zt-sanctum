# zt-sanctum — E2E Test Suite

This is a black-box end-to-end test runner for the current MVP. It hits the live gateway and verifies both allow and deny paths.

## What it verifies
- ✅ Happy path (valid PoCA + valid JSON) → **200**
- ❌ Missing PoCA → **403**
- ❌ Tampered body (hash mismatch) → **403**
- ❌ Replay (same PoCA twice) → first **200**, second **403**
- ❌ Invalid schema (fails JSON-Schema) → **422**
- ❌ Egress denied (temporarily removes allow entry) → **403**

## Prereqs
- `docker compose up -d` has started `gateway`, `opa`, `echo`
- Dev certs in `./certs`
- PoCA signer exists (runner builds `tools/poca_sign/poca_sign` if missing)
- `jq` optional (prettier audit on failure)

## Run
```bash
./tests/e2e.sh
```