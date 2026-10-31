# Node stack: k3s, containerd, kernel

`k3sec vulns` also matches the node's own software, from
`node.status.nodeInfo` (needs `get` / `list` on nodes). It shows up as a pseudo
image `node/<name>`, every component `loaded` (it's running).

| Component | From | Matched as |
|-----------|------|------------|
| k3s | `kubeletVersion` `v1.33.5+k3s1` | Go `github.com/k3s-io/k3s@v1.33.5+k3s1` (`k8s.io/kubernetes` on non-k3s nodes) |
| k0s, EKS, GKE, … | `kubeletVersion` `v1.33.4+k0s`, `v1.30.4-eks-a737599` | Go `k8s.io/kubernetes@v1.33.4` (upstream kubelet: the vendor tag after `+` / `-` stripped) |
| containerd | `containerRuntimeVersion` `containerd://2.1.4-k3s1` | Go `github.com/containerd/containerd/v2@v2.1.4` (the `-k3sN` suffix stripped; `…/containerd` for 1.x) |
| kernel | `kernelVersion` `7.0.0-38-generic` | only with `--match-kernel`: CPE `cpe:2.3:o:linux:linux_kernel:7.0.0:…` against NVD |

Real output, `sudo k3sec vulns`, node section:

```text
node/k3sec-m4-node  K3s v1.33.5+k3s1
  12 vulns, 12 loaded
  LOADED        CRIT  9.9  CVE-2026-50195     containerd 2.1.4-k3s1  → 2.1.9
  LOADED        CRIT  9.6  CVE-2026-53492     containerd 2.1.4-k3s1  → 2.1.9
  LOADED        HIGH  8.8  CVE-2026-53488     containerd 2.1.4-k3s1  → 2.1.9
  LOADED        HIGH  7.8  CVE-2024-25621     containerd 2.1.4-k3s1  → 2.1.5
  LOADED        HIGH  7.8  CVE-2026-46680     containerd 2.1.4-k3s1  → 2.2.4
  LOADED        HIGH  7.8  CVE-2026-95837     containerd 2.1.4-k3s1  → 2.2.7
  LOADED        MED   6.9  CVE-2026-53493     containerd 2.1.4-k3s1  → 2.2.9
  LOADED        MED   6.8  CVE-2025-46599     k3s v1.33.5+k3s1
  LOADED        MED   6.5  CVE-2026-53489     containerd 2.1.4-k3s1  → 2.1.9
  LOADED        MED   5.8  CVE-2026-54250     k3s v1.33.5+k3s1  → 1.33.10
  LOADED        MED   5.5  CVE-2025-64329     containerd 2.1.4-k3s1  → 2.1.5
  LOADED        MED   5.5  CVE-2026-47262     containerd 2.1.4-k3s1  → 2.1.9
```

The fixed versions are upstream containerd ones: k3s ships containerd inside its
own releases, so the fix is the k3s release that bundles it.

## Why the kernel is opt-in

Measured on the API: the CPE `linux_kernel:6.8.0` matches **9826** CVEs. NVD's
CPE data knows the upstream version only; distro kernels backport fixes without
changing it. By default that would drown the report. Combined with filters it
becomes useful, `--match-kernel --only-loaded --kev-only` on the lab:

```text
node/k3sec-m4-node  K3s v1.33.5+k3s1
  4 vulns, 4 loaded
  LOADED   KEV  HIGH  8.8  CVE-2026-53266     linux 7.0.0-38-generic
  LOADED   KEV  HIGH  7.8  CVE-2026-31431     linux 7.0.0-38-generic
  LOADED   KEV  HIGH  7.8  CVE-2026-46300     linux 7.0.0-38-generic
  LOADED   KEV  HIGH  7.8  CVE-2026-53362     linux 7.0.0-38-generic
```

Check each against your distro's kernel changelog: it may already be patched.
Kernel matches are not enriched one by one (KEV comes from the bulk catalogue).

`watch --vulns` doesn't report the node stack: it reports pods.
