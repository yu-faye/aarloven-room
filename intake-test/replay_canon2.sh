#!/bin/sh
# One command, offline, no docker, no AWS:  intake-test/replay_canon2.sh
# 1. builds the lerobot/pusht SQLite source (from /workspace/intake/raw, via the li4db loaders) and lets the fourdb connector seal it
#    (canon-2, --mode sealed, local test KEK) twice: all three tables, and the pusht-only subset (no operators);
# 2. replays both through intake_loop.py's handler with a fake kmstool and a STUB NSM, verifies the receipt/2, compares fingerprints,
#    runs the tamper cases.
# Needs: the li4db checkout (read-only; nothing is written there), and a Python with pyarrow for step 1.
# Override: FOURDB_DIR, FOURDB_PY (step 1), PYTHON (step 2), CANON2_REPLAY_OUT (keep the stub replies there).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
FOURDB=${FOURDB_DIR:-/workspace/li4db/tools/legacy-intake/fourdb}
FPY=${FOURDB_PY:-/workspace/flywheel/overnight-2026-10-16/venv/bin/python}
PY=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "[1/2] pusht SQLite source + connector --mode sealed (fourdb canon-2)"
"$FPY" -c "
import sys; sys.path.insert(0, '$FOURDB')
import loaders
loaders.load('sqlite', '$WORK/pusht.sqlite').close()"
"$FPY" "$FOURDB/connector.py" --engine sqlite --dsn "sqlite:///$WORK/pusht.sqlite" --out "$WORK/full" --mode sealed --kek-file "$WORK/kek" >/dev/null
"$FPY" "$FOURDB/connector.py" --engine sqlite --dsn "sqlite:///$WORK/pusht.sqlite" --out "$WORK/subset" --mode sealed --kek-file "$WORK/kek" \
    --tables episodes:episode_index,frames:idx >/dev/null
echo "[2/2] replay through intake_loop (fake kmstool, STUB NSM)"
"$PY" "$HERE/replay_canon2.py" --full "$WORK/full" --subset "$WORK/subset" --kek "$WORK/kek" ${CANON2_REPLAY_OUT:+--save "$CANON2_REPLAY_OUT"}
