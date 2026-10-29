# k3sec + mlab-agent, one per node (deploy/kubernetes/k3sec.yaml).
# The agent starts `k3sec serve` as its tool; k3sec never talks to mlab.
#
#   docker build -f deploy/Dockerfile -t k3sec:dev .                     # k3sec from source
#   docker build -f deploy/Dockerfile --build-arg K3SEC_FROM=dist .      # release binaries:
#       dist/k3sec-linux-<amd64|arm64> (with the eBPF probe, built by the release workflow)
#   docker build -f deploy/Dockerfile --build-arg MLAB_AGENT_FROM=local .  # deploy/mlab-agent
#
# FEATURES (source builds): cargo features; `ebpf` needs a nightly BPF
# toolchain, which the release workflow sets up, not this file.
ARG K3SEC_FROM=source
ARG MLAB_AGENT_FROM=apt

FROM rust:1-bookworm AS k3sec-source
ARG FEATURES=rpm
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p k3sec --features "${FEATURES}" \
 && strip target/release/k3sec && cp target/release/k3sec /usr/bin/k3sec

FROM scratch AS k3sec-dist
ARG TARGETARCH
# --chmod: release binaries come through workflow artifacts, which drop the
# executable bit.
COPY --chmod=0755 dist/k3sec-linux-${TARGETARCH} /usr/bin/k3sec

FROM k3sec-${K3SEC_FROM} AS k3sec

# mlab-agent from the shared repository (apt.mlab.sh), signed by mlab.
FROM debian:bookworm-slim AS agent-apt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gpg \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://apt.mlab.sh/mlab.asc -o /etc/apt/keyrings/mlab.asc \
 && printf 'Types: deb\nURIs: https://apt.mlab.sh\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/mlab.asc\n' \
      > /etc/apt/sources.list.d/mlab.sources \
 && apt-get update && apt-get install -y --no-install-recommends mlab-agent

# A locally built mlab-agent (glibc <= 2.36), for testing agent changes.
FROM scratch AS agent-local
COPY deploy/mlab-agent /usr/bin/mlab-agent

FROM agent-${MLAB_AGENT_FROM} AS agent

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/mlab-sh/k3sec" \
      org.opencontainers.image.description="k3sec with mlab-agent, one pod per Kubernetes node" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=agent /usr/bin/mlab-agent /usr/bin/mlab-agent
COPY --from=k3sec /usr/bin/k3sec /usr/bin/k3sec
COPY rules/ /usr/share/k3sec/rules/
COPY deploy/entrypoint.sh /usr/bin/k3sec-node
ENTRYPOINT ["/usr/bin/k3sec-node"]
