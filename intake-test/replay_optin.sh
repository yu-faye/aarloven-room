#!/bin/sh
# One command, offline (docker needed, no network, no AWS):  intake-test/replay_optin.sh
# 1. loads the public sample dumps from /workspace/cache/legacy-dumps into docker containers r6-optin-* (MySQL 5.7, MySQL 8.4, SQL Server 2022; one at a time,
#    ports 58610-58612, removed at the end) and lets the fourdb connector seal canon-2 intakes with the opt-in policies (CANON.md s10);
# 2. replays each through intake_loop.py's handler with a fake kmstool and a STUB NSM, compares the room's fingerprint with the connector's, runs tamper cases.
# Needs: the li4db checkout (read-only), docker with the mysql:5.7, mysql:8.4 and mssql 2022 images, a Python with pymysql/pymssql/cryptography for step 1.
# Override: FOURDB_DIR, FOURDB_PY (step 1), PYTHON (step 2), LEGACY_DUMPS_CACHE, OPTIN_REPLAY_OUT (results JSON; default intake-test/evidence/2026-10-17-optin-replay-results.json).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
FPY=${FOURDB_PY:-/workspace/flywheel/overnight-2026-10-16/venv/bin/python}
PY=${PYTHON:-python3}
OUT=${OPTIN_REPLAY_OUT:-$HERE/evidence/2026-10-17-optin-replay-results.json}
export PYTHONDONTWRITEBYTECODE=1
WORK=$(mktemp -d)
cleanup() {
    for n in r6-optin-my57 r6-optin-my84 r6-optin-ms22; do docker rm -f "$n" >/dev/null 2>&1 || true; done   # only our own containers
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
echo "[1/2] sealed canon-2 intakes with opt-in policies (docker, one container at a time)"
"$FPY" "$HERE/optin_make_intakes.py" "$WORK"
echo "[2/2] replay through intake_loop (fake kmstool, STUB NSM)"
"$PY" "$HERE/replay_optin.py" "$WORK" --save "$OUT"
