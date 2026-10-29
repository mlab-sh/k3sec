# Architecture

A Cargo workspace of focused crates. The output pipeline is source-agnostic:
every collector implements `EventSource` and feeds one printer; the engines
(YARA, vulnerabilities) only depend on `k3sec-core`.

```text
crates/
  k3sec-core/        SecEvent, EventSource, Printer (pretty / NDJSON), cgroup → container id,
                     ContainerResolver, ScanRequest, PodContainer, NodeVersions
  k3sec-k8s/         K8sEventSource, K8sLogSource, NodePodResolver (pod watch,
                     new-container notifications), list_node_containers, node_versions
  k3sec-probe/       EbpfSource (aya loader, ring buffer, pod enrichment; feature "ebpf")
  k3sec-probe-common/ the kernel ↔ userspace event struct
  k3sec-probe-ebpf/  the BPF programs (built for the BPF target by k3sec-probe's build.rs)
  k3sec-engine/      YARA (yara-x) detection engine
  k3sec-inventory/   container inventory, SBOM, reachability, VulnSource + vuln.mlab.sh
                     client, cache, VulnWatcher (feature "rpm")
  k3sec/             the CLI (clap), wiring sources into the pipeline
```

Dependency rule: `k3sec-engine` and `k3sec-inventory` depend only on
`k3sec-core` (plus third-party crates). Pods come into the inventory as core
`PodContainer`s listed by `k3sec-k8s`; the CLI connects the two.

## `watch`

```text
K8sEventSource ─┐
K8sLogSource ───┤
EbpfSource ─────┼──▶ EventSink (bounded mpsc, 1024) ──▶ printer task ──▶ stdout
DetectionEngine ┤          ▲                                │
VulnWatcher ────┘          │                                └─ exec events ──▶ VulnWatcher
                           │
EbpfSource ──ScanRequest──▶ DetectionEngine (worker threads)
NodePodResolver ──PodContainer──▶ VulnWatcher (background scan tasks, ≤ 2)
```

- One printer owns stdout: concurrent sources never interleave a line.
- Producers never block on slow consumers: scan requests, new-container
  notifications and exec observations use `try_send` and drop when full.
- Ctrl+C cancels a shared token; sources stop, then the engines drain, then the
  printer (5 s cap).

## `inventory` / `vulns`

```text
k8s API: list pods (node) ──▶ PodContainer[] ─┐
/proc/*/cgroup ──▶ container id → PIDs ───────┼─▶ group by digest ─▶ per image:
                                              │     rootfs = /proc/<pid>/root (in-root resolver)
                                              │     os-release, dpkg | apk | rpm, lockfiles, Go build info
                                              │     /proc/<pid>/maps ─▶ FileIndex ─▶ loaded / dormant
k8s API: node info ──▶ NodeVersions ──────────┘
                                   ─▶ match_images(VulnSource, Cache) ─▶ findings ─▶ render (pretty | json)
```

`VulnSource` is the seam for tests (mock) and on-prem backends:

```rust
#[async_trait]
pub trait VulnSource: Send + Sync {
    fn id(&self) -> &str;                                              // cache key (base URL)
    async fn scan(&self, coords: &[Coordinate]) -> Result<Vec<Option<Vec<Advisory>>>>;
    async fn cve(&self, id: &str) -> Result<Option<CveInfo>>;
    async fn known_exploited(&self) -> Result<Option<HashMap<String, CveInfo>>> { Ok(None) }
}
```

`None` in `scan`'s answer means "not scanned", never "clean".
