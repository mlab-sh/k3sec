# k3sec

Runtime security CLI for **Kubernetes** clusters, built for **k3s** and tested
on k0s, vanilla Kubernetes and Talos. Written in Rust.

![](./.github/banner.png)

![status: beta](https://img.shields.io/badge/status-beta-orange)
![development: active](https://img.shields.io/badge/development-active-brightgreen)

> **Beta, under active development.** k3sec is not production-ready yet. Flags,
> the `SecEvent` schema, and internals may change between releases without
> notice. Use it for testing and evaluation.

k3sec gives you a single real-time stream of what's happening in your cluster,
normalized into one event schema, and tells you which vulnerabilities touch
code that is **actually running**:

- **Kubernetes events** and **pod logs**, live (watch API, no polling)
- **Kernel runtime activity** via an **eBPF** probe: exec, outbound connects,
  writes to sensitive paths, enriched with the pod they came from
- **YARA detections** on exec'd binaries and dropped files, inline in the stream
- **Runtime-aware vulnerabilities**: every running container's packages
  matched against CVEs via [vuln.mlab.sh](https://vuln.mlab.sh), each tagged
  **loaded** or **dormant** depending on whether its code is in memory

```text
$ sudo k3sec vulns
11507 vulns, 335 loaded (1 KEV loaded) across 7 images

docker.io/library/nginx:1.25.3 (sha256:c7a6ad68be85)  Debian GNU/Linux 12 (bookworm)
  829 vulns, 104 loaded
  LOADED   KEV  HIGH  7.5  CVE-2023-44487     nginx 1.25.3-1~bookworm
  LOADED        CRIT  9.8  CVE-2023-45853     zlib1g 1:1.2.13.dfsg-1
  LOADED        CRIT  9.1  CVE-2024-5535      libssl3 3.0.11-1~deb12u2  → 3.0.15-1~deb12u1
```

## Cluster compatibility

Nothing in k3sec is k3s-only: it reads containers through the node's `/proc`
and cgroups and talks to the standard Kubernetes API.

| Distribution | Status |
|---|---|
| k3s | Tested, the reference lab |
| k0s | Tested: `inventory`, `vulns`, `watch` |
| Vanilla Kubernetes (kubeadm, kind) | Tested: `inventory`, `vulns`, `watch` |
| Talos | Tested: `inventory`, `vulns`, DaemonSet |
| EKS, GKE, AKS | Expected to work, not tested (not on Fargate / Autopilot: no `hostPID`) |
| CRI-O / cri-dockerd nodes | Containers and events work; the runtime itself isn't version-matched |

Details on the [wiki home](https://github.com/mlab-sh/k3sec/wiki#cluster-compatibility).

## Documentation

Everything is in the **[wiki](https://github.com/mlab-sh/k3sec/wiki)** (sources
in [`wiki/`](wiki/)), with real outputs from a test cluster:

| | |
|---|---|
| Commands | [watch](https://github.com/mlab-sh/k3sec/wiki/Watch) · [inventory](https://github.com/mlab-sh/k3sec/wiki/Inventory) · [vulns](https://github.com/mlab-sh/k3sec/wiki/Vulns) |
| Live stream | [eBPF probe](https://github.com/mlab-sh/k3sec/wiki/eBPF-Probe) · [YARA](https://github.com/mlab-sh/k3sec/wiki/YARA-Detection) · [watch --vulns](https://github.com/mlab-sh/k3sec/wiki/Watch-Vulns) · [SecEvent schema](https://github.com/mlab-sh/k3sec/wiki/SecEvent-Schema) |
| Vulnerabilities | [Reachability](https://github.com/mlab-sh/k3sec/wiki/Reachability) · [Package sources](https://github.com/mlab-sh/k3sec/wiki/Package-Sources) · [Matching](https://github.com/mlab-sh/k3sec/wiki/Vuln-Matching) · [Node stack](https://github.com/mlab-sh/k3sec/wiki/Node-Stack) |
| Operations | [Deployment](https://github.com/mlab-sh/k3sec/wiki/Deployment) · [Troubleshooting](https://github.com/mlab-sh/k3sec/wiki/Troubleshooting) · [Known limits](https://github.com/mlab-sh/k3sec/wiki/Known-Limits) |
| Internals | [Architecture](https://github.com/mlab-sh/k3sec/wiki/Architecture) · [Development](https://github.com/mlab-sh/k3sec/wiki/Development) |

Release notes: [CHANGELOG.md](CHANGELOG.md).

## Install

Release builds include the eBPF probe and RPM support, for x86_64 Linux
(glibc 2.35+: Debian 12, Ubuntu 22.04, RHEL 9 and later).

**apt** (Debian / Ubuntu)

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://apt.mlab.sh/mlab.asc -o /etc/apt/keyrings/mlab.asc
sudo tee /etc/apt/sources.list.d/mlab.sources >/dev/null <<'EOF'
Types: deb
URIs: https://apt.mlab.sh
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/mlab.asc
EOF
sudo apt update && sudo apt install k3sec
```

**dnf / zypper** (Fedora, RHEL, Rocky, Alma, openSUSE)

```bash
sudo curl -fsSL https://pkg.mlab.sh/rpm/mlab.repo -o /etc/yum.repos.d/mlab.repo
sudo dnf install k3sec
```

The signing key is the one every mlab package uses: fingerprint
`717894BC C0E057E4 F9BBF3CA C0E287DD 9609A065`.

The packages install `/usr/bin/k3sec`, the YARA rules in
`/usr/share/k3sec/rules`, and a `k3sec.service` unit (disabled) that runs
`watch --ebpf --rules` on the host.

**Prebuilt binary**: tarballs on the
[releases page](https://github.com/mlab-sh/k3sec/releases), with a
`SHA256SUMS` signed keyless by the release workflow:

```bash
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/mlab-sh/k3sec/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

**From source** (stable Rust 1.85+):

```bash
cargo build --release                   # binary at ./target/release/k3sec
cargo build --release --features rpm    # + RPM-based images (bundles SQLite)
cargo build --release --features ebpf   # + the eBPF probe (Linux, nightly + bpf-linker)
```

See the [eBPF probe](https://github.com/mlab-sh/k3sec/wiki/eBPF-Probe#build)
page for the BPF toolchain setup.

## In a cluster, with mlab

With an [mlab](https://mlab.sh) workspace, k3sec runs on every node next to
**mlab-agent**, one pod per node: the agent owns the workspace identity and
the only outbound connection, and starts `k3sec serve` as its tool. k3sec has
no mlab key and talks to nothing but the Kubernetes API. Events, inventories
and vulnerabilities show up in the workspace's **Cluster** tab.

```bash
kubectl create namespace k3sec
kubectl -n k3sec create secret generic k3sec-enroll --from-literal=code=<cluster enrolment code>
curl -fsSLO https://raw.githubusercontent.com/mlab-sh/k3sec/main/deploy/kubernetes/k3sec.yaml
# edit the k3sec-policy ConfigMap: upload host, what mlab may turn on
kubectl apply -f k3sec.yaml
```

The image is `ghcr.io/mlab-sh/k3sec` (k3sec, mlab-agent and the rules; amd64
for now). Read-only RBAC, no privileged mode: `hostPID` plus
`BPF`, `PERFMON`, `SYS_RESOURCE`, `SYS_PTRACE` and `DAC_READ_SEARCH`, which is
why the `k3sec` namespace is labelled Pod Security `privileged` (clusters
enforcing `baseline`, like Talos, refuse the pod otherwise). The
[Deployment](https://github.com/mlab-sh/k3sec/wiki/Deployment) page has the
details; [Tool API](https://github.com/mlab-sh/k3sec/wiki/Tool-API) has the
contract between k3sec and the agent.

## Quick start

k3sec uses your kubeconfig (`$KUBECONFIG`, `~/.kube/config`, or `--kubeconfig`).

```bash
k3sec watch                              # live k8s events, all namespaces
k3sec watch -n demo --logs               # + pod logs of one namespace
k3sec watch --rollback -o json           # replay the backlog first, as NDJSON
sudo k3sec watch --ebpf --rules ./rules/ # + kernel events + YARA detections
sudo k3sec inventory --sbom ./sboms/     # what runs on this node, what's loaded
sudo k3sec vulns --only-loaded           # CVEs in code that is in memory
sudo k3sec watch --vulns                 # vulnerability events for new pods
```

Diagnostics go to **stderr** (`RUST_LOG=k3sec=debug`), output to **stdout**,
so JSON piping stays clean. **Ctrl+C** shuts down gracefully.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo test -p k3sec-inventory --features rpm
```

CI runs the same. The [Development](https://github.com/mlab-sh/k3sec/wiki/Development)
page covers the test fixtures and a reproducible test lab (k3s in Docker; the
same steps work with k0s, kind or Talos).
