# k3sec

Runtime security CLI for **k3s** clusters, written in Rust.

![](./.github/banner.png)

![status: beta](https://img.shields.io/badge/status-beta-orange)
![development: active](https://img.shields.io/badge/development-active-brightgreen)

> **Beta, under active development.** k3sec is not production-ready yet. Flags,
> the `SecEvent` schema, and internals may change between milestones without
> notice. Use it for testing and evaluation.

k3sec gives you a single real-time stream of what's happening in your cluster,
normalized into one event schema:

- **Kubernetes events** (watch API, no polling)
- **Pod logs** (`--logs`, multi-pod, follow)
- **Kernel runtime activity** via an **eBPF** probe (`--ebpf`): exec, outbound
  connects, and writes to sensitive paths, enriched with the pod/namespace they
  came from
- **YARA detections** (`--rules`): the scan engine flags malicious binaries and
  dropped files, inline in the same stream
- **Runtime-aware vulnerabilities** (`k3sec vulns`, `watch --vulns`): every
  running container's packages matched against CVEs via
  [vuln.mlab.sh](https://vuln.mlab.sh), each tagged **loaded** or **dormant**
  depending on whether its code is actually in memory

Everything flows through the generic [`SecEvent`] envelope, so every source and
any downstream consumer speak the same format.

> **Realtime by default.** k3sec is a detection tool, not a history viewer. It
> shows what happens *after* you start watching. Use `--rollback` to replay the
> existing backlog first.

## Status

- **M1:** live k8s events & pod logs, pretty/JSON output. ✅
- **M2:** eBPF runtime probe (`exec` / `connect` / `file_write`), pod-enriched,
  via a ring buffer with in-kernel filtering. ✅ (build with `--features ebpf`).
- **M3:** YARA (yara-x) detection engine that scans exec'd binaries and files
  written to sensitive paths, off the probe's hot path, and emits detection
  events. ✅
- **M4:** runtime-aware vulnerability detection: per-node container inventory
  (dpkg / apk / rpm + lockfiles + Go build info), CycloneDX SBOM per digest,
  loaded / dormant / unknown reachability from `/proc/<pid>/maps` (+ eBPF
  exec), matching via vuln.mlab.sh with CVSS + KEV, `watch --vulns`. ✅

## Install

Requires a recent stable Rust toolchain (2021 edition).

```bash
git clone https://github.com/mlab-sh/k3sec
cd k3sec
cargo build --release
# binary at ./target/release/k3sec
```

The eBPF probe is Linux-only and behind a feature flag. Building it needs a
nightly toolchain (to cross-compile the kernel program) and `bpf-linker`:

```bash
# One-time toolchain setup on the node (Linux, kernel 6.x, BTF enabled):
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker        # needs LLVM (apt install llvm clang)

# Build with the probe compiled in:
cargo build --release --features ebpf
```

The kernel program lives in `crates/k3sec-probe-ebpf` (its own standalone
workspace); `k3sec-probe`'s build script compiles it via `aya-build`. A normal
host build (no `--features ebpf`) never touches any of this.

## Usage

k3sec uses your current kubeconfig (`$KUBECONFIG`, then `~/.kube/config`), or an
explicit `--kubeconfig <path>`.

```bash
# Live events from all namespaces (realtime, pretty)
k3sec watch

# Replay existing events (sorted by time), then go live
k3sec watch --rollback

# One namespace only
k3sec watch --namespace default

# Also follow pod logs
k3sec watch --logs

# Kernel runtime events via eBPF (needs root or CAP_BPF+CAP_PERFMON)
sudo k3sec watch --ebpf

# Only exec + connect from the probe, as NDJSON
sudo k3sec watch --ebpf --kind exec,connect --output json

# Capture + YARA scanning + alerting, all in one command
sudo k3sec watch --ebpf --rules ./rules/
```

### Detection (YARA / yara-x)

With `--rules <file|dir>`, k3sec scans the artifacts the probe surfaces:

- **exec:** the executed binary (`/proc/<pid>/exe`), even if it's deleted right
  after. This is the priority case.
- **file_write:** the file dropped under a sensitive path (debounced, scanned
  once it settles).

Scanning runs on a bounded worker pool, off the probe's critical path, so a big
binary or a slow rule never blocks event capture. A match becomes a
`source: "yara"`, `kind: "detection"` event (critical severity, red in pretty)
carrying the pod/namespace, the matched rule name(s), tags, and the artifact
path. Rules are compiled once at startup; an invalid ruleset refuses to start
with a readable error. A starter `rules/` directory is included.

```bash
sudo k3sec watch --ebpf --rules ./rules/ --max-scan-size 33554432 --scan-workers 4
```

Flags (`k3sec watch --help`):

| Flag | Description | Default |
|------|-------------|---------|
| `-n, --namespace <NS>` | Restrict to one namespace | all namespaces |
| `--logs` | Follow pod container logs | off |
| `--ebpf` | Enable the eBPF runtime probe | off |
| `--kind <exec,connect,file_write>` | Restrict eBPF events to these kinds | all |
| `--rules <PATH>` | YARA rules file/dir; enables scanning (needs `--ebpf`) | off |
| `--max-scan-size <BYTES>` | Skip artifacts larger than this | 32 MiB |
| `--scan-workers <N>` | YARA worker threads | CPU count |
| `--vulns` | Inventory + vuln-match new pod images (needs root) | off |
| `--rollback` | Replay backlog before going live (and, with `--vulns`, inventory existing pods) | off (realtime) |
| `-o, --output <pretty\|json>` | Output format | `pretty` |
| `--kubeconfig <PATH>` | Kubeconfig file | `$KUBECONFIG` / `~/.kube/config` |

Internal diagnostics go to **stderr** (`RUST_LOG`, e.g. `RUST_LOG=k3sec=debug`);
event output goes to **stdout**, so JSON piping stays clean. **Ctrl+C** shuts
down gracefully.

### JSON output (NDJSON)

One `SecEvent` per line: a source-agnostic envelope shared by every source
(k8s events, logs, the eBPF probe, and YARA detections).

```jsonc
{
  "source": "ebpf",                    // k8s-event | k8s-log | ebpf | yara | vuln
  "timestamp": "2026-08-11T18:30:05Z",
  "kind": "exec",                      // event reason | "log" | exec|connect|file_write | "detection" | "vulnerability" | "vuln_summary"
  "severity": "warning",
  "namespace": "default",
  "object": "pod/academy-...",
  "message": "...",
  "metadata": { /* flat string fields: pod, container, pid, ... */ },
  "payload": { /* raw source-specific detail */ }
}
```

### Vulnerabilities (runtime-aware)

Trivy or Grype list every CVE of every package in an image: hundreds per
image, most in code that never runs. k3sec looks at the **running**
containers on the node and tells you which vulnerable code is actually loaded.

```bash
# Packages of every running container on this node, with reachability
sudo k3sec inventory
sudo k3sec inventory --output json --sbom ./sboms/   # + one CycloneDX per digest

# Inventory + CVE matching, loaded + KEV first
sudo k3sec vulns
sudo k3sec vulns --only-loaded --min-severity high
sudo k3sec vulns --kev-only --output json | jq '.images[].findings[]'

# In the live stream: new pods are inventoried + matched in the background
sudo k3sec watch --vulns            # add --ebpf to also learn from exec events
```

Both commands need root (they read containers' filesystems through
`/proc/<pid>/root`), or a privileged DaemonSet with `hostPID: true`. Run them
on each node: only containers with a process on the host are inventoried
(`--node` / `$NODE_NAME` scopes the pod listing).

**How it works**

1. **Discovery:** pods on the node from the k8s API (image, digest,
   container id); container → PIDs by matching `/proc/*/cgroup`. Images are
   deduplicated by digest: 10 pods of one image = one inventory.
2. **Packages**, from the live filesystem (no registry pull, no containerd
   snapshot access): dpkg (`status` + `info/*.list`, distroless `status.d`),
   apk (`lib/apk/db/installed`), rpm (`rpmdb.sqlite`, build with
   `--features rpm`). Distro from `/etc/os-release`. Language deps from a
   bounded walk of the usual app dirs (`/app`, `/srv`, `/opt`, `/home`, ...) for
   `package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`,
   `requirements.txt`, `poetry.lock`, `composer.lock`, `Gemfile.lock`, plus Go
   build info of running and found binaries (modules + Go `stdlib`).
3. **Reachability:** a snapshot of `/proc/<pid>/maps` of every process of the
   container gives the binaries and `.so` files actually mapped; each is mapped
   back to its package through the file lists (paths resolved inside the
   container root: usrmerge `/lib → /usr/lib`, absolute symlinks, `(deleted)`
   files of upgraded libraries).
4. **Matching:** `POST /api/v2/scan` on vuln.mlab.sh (distro packages by source
   package, as distro advisories are filed), CVSS and KEV (CISA + EU) from
   `/api/v1/cve/{id}` and the KEV catalogue (`/api/v1/cve?kevOnly=1`, cached).
   Node versions (k3s, containerd) are matched too.

| Tag | Meaning |
|-----|---------|
| `loaded` | At least one file of the package is mapped by a container process (or was exec'd, with `--ebpf`) |
| `dormant` | OS package, none of its files mapped or executed: present on disk, not running |
| `unknown` | Language dependency: not determinable from maps (an interpreter loads it from source / bytecode) |

Pretty output is grouped by image, sorted loaded+KEV, loaded, KEV, then
severity (real output from a test k3s node, trimmed):

```text
1793 vulns, 209 loaded (1 KEV loaded) across 6 images
node k3sec-m4-node  v1.33.5+k3s1 · containerd://2.1.4-k3s1 · kernel 7.0.0-38-generic

docker.io/library/nginx:1.25.3 (sha256:c7a6ad68be85)  Debian GNU/Linux 12 (bookworm)
  pods: demo/nginx-75b7c5fd7b-dhmqv/nginx, demo/nginx-75b7c5fd7b-qsx24/nginx
  829 vulns, 104 loaded
  LOADED   KEV  HIGH  7.5  CVE-2023-44487     nginx 1.25.3-1~bookworm
  LOADED        CRIT  9.8  CVE-2023-45853     zlib1g 1:1.2.13.dfsg-1
  LOADED        CRIT  9.1  CVE-2024-5535      libssl3 3.0.11-1~deb12u2  → 3.0.15-1~deb12u1
  ...
  dormant  KEV  CRIT  9.8  CVE-2026-111497    libbrotli1 1.0.9-2+b6  → 1.0.9-2+deb12u1
  ...

node/k3sec-m4-node  K3s v1.33.5+k3s1
  12 vulns, 12 loaded
  LOADED        CRIT  9.9  CVE-2026-50195     containerd 2.1.4-k3s1  → 2.1.9
```

`KEV` = in CISA or EU KEV, `?` = KEV status could not be checked.

| Flag | Description | Default |
|------|-------------|---------|
| `-n, --namespace <NS>` | Restrict to one namespace | all |
| `--node <NAME>` | This node's name (pod listing scope) | `$NODE_NAME` |
| `--min-severity <low\|medium\|high\|critical>` | Hide lower severities (`vulns`) | all |
| `--only-loaded` | Only vulns in loaded code (`vulns`) | off |
| `--kev-only` | Only known-exploited vulns (`vulns`) | off |
| `--mlab-url <URL>` | vuln.mlab.sh base URL (or on-prem mlab) | `https://vuln.mlab.sh` |
| `--no-cache` | Ignore cached results (still refreshes them) | off |
| `--cache-ttl <SECS>` | Validity of cached results per digest | 21600 (6 h) |
| `--match-kernel` | Also match the kernel by CPE (noisy, see limits) | off |
| `--sbom <DIR>` | Write CycloneDX JSON per digest (`inventory`) | off |
| `-o, --output <pretty\|json>` | Output format | `pretty` |

The API key is read from `$MLAB_API_KEY` (optional: it raises vuln.mlab.sh's
limits, 512 → 1024+ packages per scan, shorter cooldown) and is never logged.
Results are cached per image digest in `$XDG_CACHE_HOME/k3sec` (or
`~/.cache/k3sec`). Network errors are retried with backoff, 429 cooldowns are
waited out; if the API stays unreachable the inventory is still printed, with
the error per image. Packages the API could not scan are reported as such,
never as clean.

**`watch --vulns`** inventories each **new** pod image (realtime: existing pods
only with `--rollback`) off the hot path (background tasks, at most 2 at a
time) and emits, per image, one `vuln_summary` event plus one `vulnerability`
event per **loaded** vuln. With `--ebpf`, an exec of a binary owned by a
dormant vulnerable package flips it to loaded and emits its vulns at that
moment.

```jsonc
{
  "source": "vuln",
  "kind": "vulnerability",             // or "vuln_summary" (one per image)
  "severity": "critical",              // from CVSS; a loaded KEV is always critical
  "namespace": "demo",
  "object": "nginx-7c79c4bf97-abcde/nginx",
  "message": "CVE-2024-6387 in openssh-server 1:9.2p1-2 (loaded, KEV, CVSS 8.1), fixed in ...",
  "metadata": {
    "cve": "CVE-2024-6387", "package": "openssh-server", "version": "1:9.2p1-2",
    "purl": "pkg:deb/debian/openssh-server@...", "vuln_severity": "high",
    "cvss": "8.1", "kev": "true", "fixed": "...", "reachability": "loaded",
    "image": "...", "digest": "sha256:...", "pod": "...", "container": "..."
  },
  "payload": { /* the full finding: advisories, summary, ... */ }
}
```

**Known limits**

- Reachability is a **snapshot** of `/proc/<pid>/maps` (plus exec events since
  k3sec started, with `--ebpf`): a library `dlopen()`ed later is missed until
  the next run. A dedicated eBPF `mmap` hook is planned for a later milestone.
- Language deps are `unknown`: interpreted code (Node, Python, Ruby, PHP) isn't
  visible in maps. Python packages installed without a lockfile
  (`site-packages`) are not inventoried yet. Lockfiles are only searched in
  the usual app dirs, with depth / size / count limits.
- Binaries not owned by any OS package are not matched themselves: the
  official `httpd` and `redis` images build them from source into
  `/usr/local`, so their own CVEs are missed (their linked libraries are).
  Go binaries are the exception (build info). Go deps are reported `unknown`
  even for a running binary.
- Distro advisories are filed per *source* package: a dormant
  `linux-libc-dev` (headers) carries every Debian kernel CVE (~9k). Use
  `--only-loaded` to cut that noise. Per-CVE enrichment (CVSS, EU KEV) is
  capped at 800 CVEs per run, loaded first; the CISA KEV catalogue itself is
  fetched in bulk, so KEV status covers every CVE.
- rpm: only `rpmdb.sqlite` (EL9+, Fedora 33+), behind `--features rpm`. Matching
  covers Debian, Ubuntu, Alpine, Rocky and Alma; other distros are inventoried
  but not matched (shown as a warning).
- The kernel is only matched with `--match-kernel`: NVD's CPE data ignores
  distro backports, so any kernel version gets thousands of hits.
- An image is inventoried from one container's live filesystem: files added at
  runtime in that container are seen; cache entries are per digest.
- The vuln.mlab.sh anonymous tier allows one scan every 10 s and 512 packages
  per request: k3sec batches all images into as few requests as possible and
  waits out the cooldown; set `MLAB_API_KEY` for larger clusters.

## Robustness

- **No polling:** watch API for events and pods.
- **Auto-reconnect** with exponential backoff (1s to 30s) on watch drops.
- **Graceful shutdown** on Ctrl+C.
- **Readable errors** for kubeconfig, connectivity, and RBAC, with no panics.
- The eBPF and scan paths drop with a counter (never crash) on backpressure,
  an unresolved cgroup, or a vanished artifact.

## Architecture

A Cargo **workspace** of focused crates. The output pipeline is
source-agnostic: every collector implements `EventSource` and feeds one printer.

```
crates/
  k3sec-core/   SecEvent envelope, EventSource trait, pretty/NDJSON output
  k3sec-k8s/    K8sEventSource (events), K8sLogSource (logs)
  k3sec-probe/  EbpfSource (aya eBPF probe; Linux, feature = "ebpf")
  k3sec-engine/ YARA (yara-x) detection engine, depends only on k3sec-core
  k3sec-inventory/ container inventory, SBOM, reachability, vuln.mlab.sh
                matching (VulnSource), depends only on k3sec-core
  k3sec/        the CLI binary (clap) wiring sources into the pipeline
```

The probe pushes lightweight scan requests into a queue; `k3sec-engine` drains
them on worker threads and emits detections back into the same pipeline. Neither
the probe nor the engine depends on the other; both meet at core types.

Adding a source (like the probe) never touches rendering. It just implements
`EventSource` and gets wired into the CLI.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo test -p k3sec-inventory --features rpm   # rpm header parser
```

CI (GitHub Actions) runs fmt + clippy (deny warnings) + build + test, plus the
`rpm` feature of the inventory crate.

[`SecEvent`]: crates/k3sec-core/src/event.rs
