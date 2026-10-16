# Build host from REBUILD.md: Amazon Linux 2023 with Docker 25.0.16 and nitro-cli 1.5.0, all pinned.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
RUN dnf install -y --releasever=2023.12.20260930 docker-25.0.16-1.amzn2023.0.4 \
      aws-nitro-enclaves-cli-1.5.0-0.amzn2023 aws-nitro-enclaves-cli-devel-1.5.0-0.amzn2023 \
      findutils python3 iptables-nft && dnf clean all
