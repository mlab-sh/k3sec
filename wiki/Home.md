# k3sec

**Runtime security for Kubernetes clusters, k3s first, in one Rust binary.**

k3sec gives you one real-time stream of what happens in your cluster, normalized
into a single event schema ([`SecEvent`](SecEvent-Schema)), and tells you which
vulnerabilities touch code that is **actually running** on the node.

- **Kubernetes events** and **pod logs**, live (watch API, no polling).
- **Kernel runtime activity** from an **eBPF** probe: exec, outbound connects,
  writes to sensitive paths, each tagged with its pod.
- **YARA detections** on exec'd binaries and dropped files, inline in the stream.
- **Runtime-aware vulnerabilities**: every running container's packages matched
  against CVEs via [vuln.mlab.sh](https://vuln.mlab.sh), each tagged
  **loaded** / **dormant** / **unknown**. Trivy or Grype list 800 CVEs for an
  nginx image; k3sec puts the one that matters on the first line:

```text
docker.io/library/nginx:1.25.3 (sha256:c7a6ad68be85)  Debian GNU/Linux 12 (bookworm)
  pods: demo/nginx-57fcccff77-4hhkt/nginx, demo/nginx-57fcccff77-l8lzs/nginx
  829 vulns, 104 loaded
  LOADED   KEV  HIGH  7.5  CVE-2023-44487     nginx 1.25.3-1~bookworm
  LOADED        CRIT  9.8  CVE-2023-45853     zlib1g 1:1.2.13.dfsg-1
  LOADED        CRIT  9.1  CVE-2024-5535      libssl3 3.0.11-1~deb12u2  → 3.0.15-1~deb12u1
```

> **Beta.** Flags, the `SecEvent` schema and internals may change between
> milestones. Every output in this wiki was captured on a throwaway single-node
> k3s (v1.33.5+k3s1) built as described in [Development](Development#test-lab).

## Cluster compatibility

k3sec is built for k3s but nothing in it is k3s-only: it reads containers
through the node's `/proc` and cgroups (containerd, CRI-O and Docker cgroup
names, cgroupfs or systemd driver) and talks to the standard Kubernetes API.

| Distribution | Status |
| --- | --- |
| **k3s** | Tested (v1.33.5+k3s1), the reference lab. |
| **k0s** | Tested (v1.33.4+k0s): `inventory`, `vulns`, `watch`. Kubelet matched as upstream `k8s.io/kubernetes`. |
| **Vanilla Kubernetes** (kubeadm, kind) | Tested on kind (v1.33.1): `inventory`, `vulns`, `watch`. |
| **Talos** | Tested (Talos v1.10.6, Kubernetes v1.33.3): `inventory`, `vulns`, DaemonSet admitted. Talos enforces Pod Security `baseline`: the manifest labels its namespace `privileged`. |
| **EKS, GKE, AKS** | Expected to work, not tested. Vendor version tags (`-eks-…`, `-gke.…`) are stripped before matching. |
| **CRI-O / cri-dockerd nodes** | Containers and events work; the runtime itself is not in the [node stack](Node-Stack) (only containerd is matched). |

The eBPF probe needs a kernel with BTF and tracefs, whatever the distribution;
see [Known limits](Known-Limits) for nodes running inside containers.

---

## The commands

| Command | What it does |
| --- | --- |
| [`watch`](Watch) | Live stream: k8s events, `--logs`, `--ebpf` kernel events, `--rules` YARA detections, `--vulns` vulnerability events. |
| [`inventory`](Inventory) | One-shot: packages of every running container on the node, loaded / dormant, `--sbom` CycloneDX per digest. |
| [`vulns`](Vulns) | One-shot: inventory + CVE matching, loaded + KEV first, filters for triage. |

## Key concepts

- **[Reachability](Reachability)**: how a package is tagged loaded, dormant or
  unknown, from `/proc/<pid>/maps` and eBPF exec events.
- **[Package sources](Package-Sources)**: dpkg, apk, rpm, lockfiles, Go build
  info; distros and ecosystems covered.
- **[Vulnerability matching](Vuln-Matching)**: the vuln.mlab.sh API, KEV, the
  cache, retries and what happens when the API is down.
- **[Node stack](Node-Stack)**: k3s, containerd and kernel versions matched too.
- **[Watch --vulns](Watch-Vulns)**: vulnerability events in the live stream.
- **[eBPF probe](eBPF-Probe)** and **[YARA detection](YARA-Detection)**.
- **[SecEvent schema](SecEvent-Schema)**: the JSON contract shared by every source.
- **[Deployment](Deployment)**: privileges, RBAC, running per node.
- **[Known limits](Known-Limits)** and **[Troubleshooting](Troubleshooting)**.
- **[Architecture](Architecture)** and **[Development](Development)**.

---

## Install

From source (stable Rust, 1.85+):

```bash
git clone https://github.com/mlab-sh/k3sec
cd k3sec
cargo build --release                   # ./target/release/k3sec
cargo build --release --features rpm    # + RPM-based images (bundles SQLite)
cargo build --release --features ebpf   # + the eBPF probe (nightly + bpf-linker, see eBPF probe)
```

## Quick start

```bash
k3sec watch                             # live k8s events, all namespaces
k3sec watch -n demo --logs              # + pod logs of one namespace
sudo k3sec watch --ebpf --rules ./rules # + kernel events + YARA
sudo k3sec inventory                    # what runs on this node, what's loaded
sudo k3sec vulns --only-loaded          # CVEs in code that is in memory
sudo k3sec watch --vulns                # vuln events for every new pod
```

k3sec uses your kubeconfig (`$KUBECONFIG`, `~/.kube/config`, or `--kubeconfig`).
Diagnostics go to **stderr** (`RUST_LOG=k3sec=debug`), output to **stdout**, so
`-o json | jq` stays clean.

> This wiki is generated from the [`wiki/`](https://github.com/mlab-sh/k3sec/tree/main/wiki)
> folder in the repo and synced automatically - edit the markdown there, not here.
