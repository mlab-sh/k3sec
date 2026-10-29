# Changelog

All notable changes to k3sec are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.5.0]

k3sec in the mlab ecosystem: on every node, k3sec runs as a tool of
**mlab-agent**, and everything it sees lands in the workspace's Cluster tab.

### Added

- **`k3sec serve`**, the mlab-agent tool mode. Started by the agent and pinned
  to the SHA-256 of its binary, it speaks the agent's tool protocol on stdio.
  k3sec holds no mlab key and opens no connection to mlab: the agent owns the
  identity and the only outbound link.
  - Ops: `status`, `configure`, `events_since`, `inventory`, `sbom`.
  - Events: `batch`, `status` (heartbeat), `inventory_ready`.
  - Batches are numbered (`boot_id` + `seq`). A bounded backlog serves
    `events_since` after a gap, drops are counted, and critical events are
    flushed first.
  - The config is chosen in the workspace and applied live, without a restart,
    always within the node's local policy (`[tools.k3sec.settings]`).
  - Vulnerabilities: k3sec sends the inventory with match coordinates and
    reachability; matching happens in mlab.
- **`k3sec-api`**: the v1 contract (`SecEvent` v1, the ops, the events), frozen
  by golden CBOR files. Spec in [`docs/tool-api.md`](docs/tool-api.md).
- **DaemonSet with mlab-agent**: `deploy/kubernetes/k3sec.yaml` and the
  `ghcr.io/mlab-sh/k3sec` image (`deploy/Dockerfile`).
  - RBAC is read-only, and there is no privileged mode: `hostPID` plus `BPF`,
    `PERFMON`, `SYS_RESOURCE`, `SYS_PTRACE` and `DAC_READ_SEARCH`.
  - Each node enrols once with a cluster enrolment code; its keys stay on the
    node.
- **Packages**: `.deb` on apt.mlab.sh and `.rpm` on pkg.mlab.sh, for x86_64.
  The release binary includes the eBPF probe (verified by the release
  workflow).
  - A `SHA256SUMS` file is signed keyless with Sigstore.
  - A `k3sec.service` unit (disabled) for standalone host use.
- `LICENSE` (Apache-2.0).

### Fixed

- **eBPF: most execs were missed.** On recent kernels (7.0 on the lab), BPF
  programs on `syscalls:sys_enter_execve` ran for 9 of 50 execs in a
  container. Exec capture now uses `sched:sched_process_exec`: 50 of 50, and
  only successful execs (no more failed `PATH` lookups). The process name in
  the message is now the new program's (`exec /usr/bin/ls (ls)`).
- **eBPF: short-lived processes were dropped as host processes.** A process
  gone before its `/proc/<pid>/cgroup` was read is now attributed through the
  kernel's cgroup id (the inode of its container's cgroup directory).
- **Matching: versions that are not one are not matched.** A coordinate with an
  empty version, a wildcard (`*`, `1.x`), a range (`^1.2`, `>=2`) or a tag
  (`latest`, `(devel)`) would have matched every CVE of the product: the
  package stays in the inventory, counted as unmatched.

## [v1.4.0]

Runtime-aware vulnerability detection: k3sec now tells you which CVEs touch
code that is **actually loaded in memory** on the node, not just installed in
an image. On the test node: 11 507 CVEs in total, 335 in loaded code, one of
them known exploited (CVE-2023-44487 in the running `nginx` binary), on the
first line.

### Added

- **`k3sec inventory`.** One-shot inventory of every container running on the
  node, read from its live filesystem through `/proc/<pid>/root` (no registry
  pull, no containerd snapshot access). Images are deduplicated by digest.
  - OS packages: dpkg (including distroless `status.d`), apk, and rpm
    (`rpmdb.sqlite`, behind the new `rpm` cargo feature), with each package's
    file list. Distro from `/etc/os-release`.
  - Language dependencies, best effort: a bounded walk of the usual app
    directories for `package-lock.json`, `yarn.lock`, `Cargo.lock`, `go.sum`,
    `requirements.txt`, `poetry.lock`, `composer.lock`, `Gemfile.lock`, plus the
    build info of Go binaries (modules and the Go `stdlib` version).
  - `--sbom <dir>`: one CycloneDX 1.5 JSON SBOM per image digest, with correct
    purls per ecosystem and the reachability as a `k3sec:reachability`
    property.
  - `-o json` for a single JSON document.
- **Reachability: `loaded` / `dormant` / `unknown`.** A snapshot of
  `/proc/<pid>/maps` of every process of the container is mapped back to the
  owning package, with paths resolved inside the container root (usrmerge,
  absolute symlinks, `(deleted)` libraries). Language deps are `unknown`.
- **`k3sec vulns`.** Inventory + matching through
  [vuln.mlab.sh](https://vuln.mlab.sh): CVE, severity / CVSS, CISA / EU KEV,
  fixed version, package and reachability for every finding. Pretty output is
  grouped by image and sorted loaded+KEV first, with an "X vulns, Y loaded"
  header; `--min-severity`, `--only-loaded`, `--kev-only`, `-o json`.
  - Distro packages are matched by **source** package, as distro advisories
    are filed.
  - The node's own k3s and containerd versions are matched too; the kernel
    with `--match-kernel` (opt-in: NVD's CPE data ignores distro backports).
  - The CISA KEV catalogue is fetched in bulk; per-CVE enrichment is capped at
    800 per run, loaded code first.
- **vuln.mlab.sh client behind a `VulnSource` trait**, mockable and ready for
  an on-prem mlab: `--mlab-url`, optional `MLAB_API_KEY` (never logged),
  retries with backoff, `Retry-After` on cooldowns, timeouts. When the API is
  unreachable the inventory is still printed, with the error per image;
  packages the API couldn't scan are reported as such, never as clean.
- **Local cache** per image digest and for the KEV catalogue, in
  `$XDG_CACHE_HOME/k3sec` (or `~/.cache/k3sec`): `--cache-ttl` (6 h by
  default), `--no-cache`. A cached run of the test node takes 0.75 s instead of
  ~10 s.
- **`k3sec watch --vulns`.** Each new pod image is inventoried and matched in
  the background, off the hot path, and reported as `source: "vuln"` events: a
  `vuln_summary` per image and a `vulnerability` event per loaded finding (a
  loaded KEV is `critical`). Realtime by default: existing pods only with
  `--rollback`. With `--ebpf`, an exec of a binary owned by a dormant package
  flips it to loaded and emits its vulns at that moment.
- **A wiki**, in `wiki/` and synced to the GitHub wiki on push to `main`, with
  real outputs from a test k3s, a reproducible test lab, the `SecEvent` schema,
  deployment (RBAC, DaemonSet template) and troubleshooting.
- **`CHANGELOG.md`** (this file).

### Changed

- The cgroup → container id lookup now takes the **innermost** container id,
  so pods resolve when k3s itself runs in a container (k3d, kind, k3s in
  Docker). Shared by the eBPF probe and the inventory (`k3sec-core`).
- The README is now a short overview; the documentation lives in the
  [wiki](https://github.com/mlab-sh/k3sec/wiki).
- Version jumps to 1.4.0 for all crates.

### Fixed

- Container ids were not found from `/proc/<pid>/cgroup` (newline-terminated):
  the trailing segment was ignored and the lookup could fall back to the outer
  container.
- `cargo test --workspace` failed linking the BPF-only `k3sec-probe-ebpf`
  crate on the host; it now has `test = false`.

### Known limitations

- Reachability is a snapshot of memory maps (plus exec events with `--ebpf`):
  a library `dlopen()`ed later is missed until the next run. An eBPF `mmap`
  hook is planned.
- Binaries built from source outside any package manager (official `httpd`,
  `redis` images) are not matched themselves, only the libraries they load. Go
  binaries are covered through their build info.
- Python packages installed without a lockfile (`site-packages`) are not
  inventoried yet.
- See [Known limits](https://github.com/mlab-sh/k3sec/wiki/Known-Limits).
