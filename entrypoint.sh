#!/bin/bash
set -euo pipefail
echo "[entrypoint] aarloven sealed room v4: runs each case's agreed tests"
export LD_LIBRARY_PATH=/usr/lib64:${LD_LIBRARY_PATH:-}
"$NODE_BIN" --version
exec python3 /app/enclave_loop.py
