# k3sec

Runtime security CLI for **k3s** clusters, written in Rust.

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

Requires a recent stable Rust toolchain (1.85+).

```bash
git clone https://github.com/mlab-sh/k3sec
cd k3sec
cargo build --release                   # binary at ./target/release/k3sec
cargo build --release --features rpm    # + RPM-based images (bundles SQLite)
cargo build --release --features ebpf   # + the eBPF probe (Linux, nightly + bpf-linker)
```

See the [eBPF probe](https://github.com/mlab-sh/k3sec/wiki/eBPF-Probe#build)
page for the BPF toolchain setup.

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
page covers the test fixtures and a reproducible k3s test lab.
