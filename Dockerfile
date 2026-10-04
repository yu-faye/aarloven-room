# Aarloven sealed room: the enclave image, built so that anyone can rebuild it and get the same PCR0.
#
# Every input is pinned:
# - the base image by digest. dnf then reads the versioned repository of that exact Amazon Linux
#   release, and the packages are named by version as well;
# - the Python wheels by SHA-256 (requirements.txt), installed without byte-code;
# - llama.cpp by commit;
# - kmstool_enclave_cli, libnsm.so and the model by SHA-256 (inputs.sha256, checked during the build).
# What changes from one build to the next (package databases, logs, caches, and the time on every
# file) is removed or set to zero in stages 3 and 4. Build and measure with ./build.sh.
# Dockerfile.v2 is the earlier, unpinned recipe that built Room v1 and Room v2.

ARG BASE=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
ARG RELEASE=2023.12.20260930
ARG LLAMA_COMMIT=d775ebf363f777bc862a8659b6c55eec9419cf35

# 1. llama.cpp, CPU only, at a fixed commit
FROM ${BASE} AS llama-build
ARG RELEASE
ARG LLAMA_COMMIT
RUN dnf install -y --releasever=${RELEASE} --setopt=install_weak_deps=False \
      gcc-11.5.0-5.amzn2023.0.5 gcc-c++-11.5.0-5.amzn2023.0.5 cmake-3.22.2-1.amzn2023.0.6 \
      make-4.3-5.amzn2023.0.2 git-2.50.1-1.amzn2023.0.1 \
    && dnf clean all
WORKDIR /src
RUN git init -q . \
    && git fetch -q --depth 1 https://github.com/ggml-org/llama.cpp.git ${LLAMA_COMMIT} \
    && git checkout -q FETCH_HEAD
RUN cmake -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DGGML_NATIVE=OFF \
      -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON \
      -DGGML_CUDA=OFF \
      -DLLAMA_BUILD_TESTS=OFF \
      -DLLAMA_BUILD_EXAMPLES=OFF \
      -DLLAMA_BUILD_SERVER=OFF \
      -DLLAMA_BUILD_TOOLS=ON \
      -DLLAMA_BUILD_APP=OFF \
    && cmake --build build --config Release -j"$(nproc)" --target llama-completion \
    && mkdir -p /opt/llama/bin /opt/llama/lib \
    && BIN=$(find build -type f -name llama-completion | head -1) \
    && test -n "$BIN" && test -x "$BIN" \
    && cp -a "$BIN" /opt/llama/bin/llama-completion \
    && find build -name 'libllama*.so*' -exec cp -a {} /opt/llama/lib/ \; \
    && find build -name 'libggml*.so*' -exec cp -a {} /opt/llama/lib/ \; \
    && LD_LIBRARY_PATH=/opt/llama/lib /opt/llama/bin/llama-completion --version

# 2. the room: Python, the tools, llama.cpp, the model and the room's code
FROM ${BASE} AS room
ARG RELEASE
RUN dnf install -y --releasever=${RELEASE} --setopt=install_weak_deps=False \
      python3-3.9.25-1.amzn2023.0.9 python3-pip-21.3.1-2.amzn2023.0.21 \
      socat-1.7.4.2-1.amzn2023.0.3 jq-1.8.1-60.amzn2023 libgomp-14.2.1-7.amzn2023.0.2 \
    && dnf clean all
COPY requirements.txt /tmp/requirements.txt
RUN PYTHONDONTWRITEBYTECODE=1 pip3 install --no-cache-dir --no-compile --no-deps --require-hashes -r /tmp/requirements.txt
WORKDIR /app
COPY inputs.sha256 kmstool_enclave_cli libnsm.so enclave_loop.py entrypoint.sh yn.gbnf /app/
COPY models/ /app/models/
COPY --from=llama-build /opt/llama/bin/llama-completion /app/llama-completion
COPY --from=llama-build /opt/llama/lib/ /usr/lib64/
RUN sha256sum -c inputs.sha256 \
    && mv libnsm.so /usr/lib64/libnsm.so \
    && chmod 0755 kmstool_enclave_cli llama-completion entrypoint.sh \
    && ldconfig \
    && ./llama-completion --version \
    && PYTHONDONTWRITEBYTECODE=1 python3 -c "import cryptography; print('cryptography', cryptography.__version__)"

# 3. remove what differs between builds (package databases, logs, caches), then date every file 1970-01-01
FROM ${BASE} AS flat
ARG RELEASE
RUN dnf install -y --releasever=${RELEASE} --setopt=install_weak_deps=False findutils && dnf clean all
COPY --from=room / /out/
RUN cd /out \
    && rm -rf var/lib/rpm var/lib/dnf var/log/* var/cache/* tmp/* root/.cache \
    && find /out -exec touch -h -d @0 {} +

# 4. the image: one layer, and the settings the room starts with
FROM scratch
COPY --from=flat /out/ /
ENV REGION=eu-north-1
ENV KMS_PROXY_PORT=8000
ENV AARLOVEN_VSOCK_PORT=5005
ENV KMSTOOL_CLI=/app/kmstool_enclave_cli
ENV LLAMA_CLI=/app/llama-completion
ENV MODEL_PATH=/app/models/qwen2.5-0.5b-instruct-q4_k_m.gguf
ENV MODEL_NAME=Qwen2.5-0.5B-Instruct-Q4_K_M
ENV MODEL_META=/app/models/model_meta.json
ENV GRAMMAR_PATH=/app/yn.gbnf
ENV LD_LIBRARY_PATH=/usr/lib64
WORKDIR /app
CMD ["/app/entrypoint.sh"]
