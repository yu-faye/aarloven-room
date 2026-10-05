# Aarloven sealed room: the enclave image, built so that anyone can rebuild it and get the same PCR0.
# Room v4 runs each case's agreed tests with Node and decides from their results. There is no language model in it.
#
# Every input is pinned:
# - the base image by digest. dnf then reads the versioned repository of that exact Amazon Linux
#   release, and the packages are named by version as well;
# - the Python wheels by SHA-256 (requirements.txt), installed without byte-code;
# - kmstool_enclave_cli and libnsm.so by SHA-256 (inputs.sha256, checked during the build).
# What changes from one build to the next (package databases, logs, caches, the time on every file, and the
# permissions a checkout happens to give the copied files) is removed or set in stages 1 to 3.
# Build and measure with ./build.sh.

ARG BASE=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
ARG RELEASE=2023.12.20260930

# 1. the room: Python, Node, AWS's two Nitro helpers and the room's code
FROM ${BASE} AS room
ARG RELEASE
RUN dnf install -y --releasever=${RELEASE} --setopt=install_weak_deps=False \
      python3-3.9.25-1.amzn2023.0.9 python3-pip-21.3.1-2.amzn2023.0.21 nodejs24-24.21.0-1.amzn2023.0.1 \
    && dnf clean all
COPY requirements.txt /tmp/requirements.txt
RUN PYTHONDONTWRITEBYTECODE=1 pip3 install --no-cache-dir --no-compile --no-deps --require-hashes -r /tmp/requirements.txt
WORKDIR /app
COPY inputs.sha256 kmstool_enclave_cli libnsm.so enclave_loop.py entrypoint.sh /app/
RUN sha256sum -c inputs.sha256 \
    && mv libnsm.so /usr/lib64/libnsm.so \
    && chmod 0755 kmstool_enclave_cli entrypoint.sh /usr/lib64/libnsm.so \
    && chmod 0644 enclave_loop.py inputs.sha256 \
    && ldconfig \
    && node-24 --version \
    && PYTHONDONTWRITEBYTECODE=1 python3 -c "import cryptography; print('cryptography', cryptography.__version__)"

# 2. remove what differs between builds (package databases, logs, caches), then date every file 1970-01-01
FROM ${BASE} AS flat
ARG RELEASE
RUN dnf install -y --releasever=${RELEASE} --setopt=install_weak_deps=False findutils && dnf clean all
COPY --from=room / /out/
RUN cd /out \
    && rm -rf var/lib/rpm var/lib/dnf var/log/* var/cache/* tmp/* root/.cache \
    && find /out -exec touch -h -d @0 {} +

# 3. the image: one layer, and the settings the room starts with
FROM scratch
COPY --from=flat /out/ /
ENV REGION=eu-north-1
ENV KMS_PROXY_PORT=8000
ENV AARLOVEN_VSOCK_PORT=5005
ENV KMSTOOL_CLI=/app/kmstool_enclave_cli
ENV NODE_BIN=/usr/bin/node-24
ENV LD_LIBRARY_PATH=/usr/lib64
WORKDIR /app
CMD ["/app/entrypoint.sh"]
