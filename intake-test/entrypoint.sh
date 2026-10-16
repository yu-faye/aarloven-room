#!/bin/bash
set -euo pipefail
echo "[entrypoint] aarloven intake TEST room (not Room v6)"
export LD_LIBRARY_PATH=/usr/lib64:${LD_LIBRARY_PATH:-}
exec python3 /app/intake_loop.py
