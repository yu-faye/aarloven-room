#!/bin/bash
set -euo pipefail
echo "[entrypoint] aarloven closed-loop enclave (in-enclave JEV) starting"
export LD_LIBRARY_PATH=/usr/lib64:${LD_LIBRARY_PATH:-}
test -x /app/llama-completion
test -f /app/models/qwen2.5-0.5b-instruct-q4_k_m.gguf
test -f /app/models/model_meta.json
echo "[entrypoint] model=$(jq -r .model_name /app/models/model_meta.json) hash=$(jq -r .model_hash /app/models/model_meta.json | cut -c1-16)…"
exec python3 /app/enclave_loop.py
