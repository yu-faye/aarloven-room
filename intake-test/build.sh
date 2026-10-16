#!/bin/bash
# Build the intake TEST room's enclave image and print its measurements.
#   intake-test/build.sh [TAG] [EIF]     on an x86_64 host with Docker (BuildKit) and nitro-cli 1.5.0
# The build context is the repo root. The KMS key is not a build input: each request carries it, so PCR0 does not depend on it.
set -euo pipefail
cd "$(dirname "$0")/.."
TAG=${1:-aarloven-intake-test:local}
EIF=${2:-$PWD/aarloven-intake-test.eif}
sha256sum -c inputs.sha256
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg SOURCE_DATE_EPOCH=0 -f intake-test/Dockerfile -t "$TAG" .
nitro-cli build-enclave --docker-uri "$TAG" --output-file "$EIF" > /dev/null
nitro-cli describe-eif --eif-path "$EIF" | python3 -c "import json,sys; m=json.load(sys.stdin)['Measurements']; [print(k, m[k]) for k in ('PCR0', 'PCR1', 'PCR2')]"
