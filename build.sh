#!/bin/bash
# Build the sealed room's enclave image and print its measurements.
#   ./build.sh [TAG] [EIF]     on an x86_64 host with Docker (BuildKit) and nitro-cli 1.5.0
# Two runs from fresh copies of this folder must print the same PCR0: that is the reproducibility check.
# kmstool_enclave_cli and libnsm.so are published next to this file and checked against inputs.sha256.
set -euo pipefail
cd "$(dirname "$0")"
TAG=${1:-aarloven-room:local}
EIF=${2:-$PWD/aarloven-room.eif}
sha256sum -c inputs.sha256
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg SOURCE_DATE_EPOCH=0 -t "$TAG" .
nitro-cli build-enclave --docker-uri "$TAG" --output-file "$EIF" > /dev/null
nitro-cli describe-eif --eif-path "$EIF" | python3 -c "import json,sys; m=json.load(sys.stdin)['Measurements']; [print(k, m[k]) for k in ('PCR0', 'PCR1', 'PCR2')]"
