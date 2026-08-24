#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VP="${VP:-.venv/bin/vulnproof}"
OUTPUT="${OUTPUT:-/tmp/vulnproof-demo}"
mkdir -p "$OUTPUT"

LAB_MODE=vulnerable PORT=18080 python3 lab/app.py >"$OUTPUT/vulnerable.log" 2>&1 &
VULNERABLE_PID=$!
LAB_MODE=patched PORT=18081 python3 lab/app.py >"$OUTPUT/patched.log" 2>&1 &
PATCHED_PID=$!
trap 'kill "$VULNERABLE_PID" "$PATCHED_PID" 2>/dev/null || true' EXIT

python3 - <<'PY'
import time
from urllib.request import urlopen

for port in (18080, 18081):
    for _ in range(30):
        try:
            urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2)
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit(f"fixture on port {port} did not start")
PY

"$VP" ingest fixtures/trivy-demo.json \
  --asset config/assets/demo-api.yaml \
  --output "$OUTPUT/scan.json"

"$VP" retest "$OUTPUT/scan.json" \
  --finding VP-LAB-0001 \
  --playbook playbooks/VP-LAB-0001.yaml \
  --asset config/assets/demo-api.yaml \
  --before-target http://127.0.0.1:18080 \
  --after-target http://127.0.0.1:18081 \
  --approve \
  --output "$OUTPUT/retest.json"

python3 - "$OUTPUT/retest.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["before"]["status"] == "confirmed"
assert report["after"]["status"] == "not_confirmed"
assert report["remediation_verified"] is True
print(f"end-to-end demo passed -> {sys.argv[1]}")
PY
