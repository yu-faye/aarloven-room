# Rebuild the room and check its PCR0

Anyone can rebuild Room v6 from this repository and get the PCR0 that the KMS key policy requires and that AWS's hardware reports on every receipt. No AWS account is needed.

**Expected PCR0 (Room v6, commit `40952883`):**

    3ea0a6f506beac36cb81e6a469df53072f0c38d3599183b15960246c2f89108cf276430233f7f16ac00de1162f5ac343

## Required inputs

- x86_64 Linux with a Docker host that can run a privileged container.
- **Docker 25.0.16** as the engine that builds the image. This is a required input, not a detail: the same Dockerfile built with Docker 26.1.5 gives a different (but also self-consistent) PCR0, `610c6b75…`.
- `nitro-cli` 1.5.0.
- Everything else is pinned by the Dockerfile (base image digest, package versions, wheel hashes, `inputs.sha256`).

The simplest way to get exactly these versions is an Amazon Linux 2023 container, used as the build host:

```Dockerfile
# host.Dockerfile
FROM public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
RUN dnf install -y --releasever=2023.12.20260930 docker-25.0.16-1.amzn2023.0.4 \
      aws-nitro-enclaves-cli-1.5.0-0.amzn2023 aws-nitro-enclaves-cli-devel-1.5.0-0.amzn2023 \
      git findutils python3 iptables-nft && dnf clean all
```

## Steps

```sh
docker build -t room-build-host -f host.Dockerfile .
mkdir -p out dockerdata            # dockerdata must be on a normal filesystem (ext4/xfs), not overlay
docker run --rm --privileged -v "$PWD/dockerdata:/var/lib/docker" -v "$PWD/out:/out" room-build-host bash -c '
  (dockerd >/out/dockerd.log 2>&1 &); for t in $(seq 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
  git clone -q https://github.com/yu-faye/aarloven-room /w && cd /w && git checkout -q 40952883
  export NITRO_CLI_ARTIFACTS=/tmp/art; mkdir -p $NITRO_CLI_ARTIFACTS
  ./build.sh aarloven-room:local /out/room.eif'
```

The last lines print PCR0, PCR1 and PCR2. Compare **PCR0** with the value above, with `pcr0` in [aarloven.com/releases.json](https://aarloven.com/releases.json), and with the PCR0 in the AWS document attached to any receipt.

Compare PCR0, not the `.eif` file's hash: the EIF embeds build metadata, so its sha384 differs on every build even when PCR0 is identical.

## Checked

On 15–16 Oct 2026 (Europe/Oslo), three rounds of two builds each, every build in its own fresh dockerd with no cache, the second from a checkout with different file times and permissions. With Docker 25.0.16 all four builds gave the PCR0 above; with Docker 26.1.5 both builds gave `610c6b75…`.
