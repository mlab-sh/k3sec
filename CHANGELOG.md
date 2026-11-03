# Changelog

All notable changes to k3sec are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.8.0]

### Added

- **Red Hat family matched**: RHEL / UBI 8, 9 and 10, Hummingbird and Oracle
  Linux OS packages are matched against Red Hat's advisories, the product
  stream taken from the image's `CPE_NAME` (`Red Hat:hummingbird:1`,
  `Red Hat:enterprise_linux:9::baseos`). RHEL 8/9 ask both `baseos` and
  `appstream`. Oracle Linux has no feed of its own: it is matched against RHEL,
  with a warning. Only fixed CVEs (errata) are reported for Red Hat.
- **rpmdb in `/usr/lib/sysimage/rpm`** (Fedora 36+, RHEL 10, Hummingbird): 0 to
  11 of 11 Hummingbird images inventoried. Trivy reports no OS on them, grype
  takes them for Fedora and finds nothing.
- **Berkeley DB rpmdb** (RHEL / UBI 8, EL7): UBI 8 inventoried, 101 packages
  as `rpm -qa` lists them.
- **Wolfi / Chainguard** images matched; **BusyBox** seen (by CPE) in images
  without a package database, such as the official Prometheus ones.
- **Java dependencies**: Maven coordinates from `pom.properties` in jars and
  in the jars a fat jar nests (`BOOT-INF/lib/`, `WEB-INF/lib/`). The jars a
  JVM holds open are **loaded**. Log4Shell (`CVE-2021-44228`) is reported
  loaded and KEV on a Spring Boot app; Elasticsearch shows 207 dependencies,
  Keycloak 417.
- **`vulns --vex <PATH>`**: OpenVEX statements applied (Docker Hardened
  Images publish theirs); findings stated `not_affected` or `fixed` are
  dropped. A DHI image scanned without it carries a warning. `dhi.io/nginx`:
  33 findings, 17 loaded without; 5, none loaded, with.
- **CVSS scored locally** from the advisory's v3 vector: on a 9 698-CVE image,
  unscored CVEs go from 8 723 to 2 069, and the per-CVE lookup budget is kept
  for the rest.
- **Exec events without tracefs** (Talos in Docker): a raw tracepoint, the
  path read from `/proc/<pid>/exe`.
- **CRI-O and Docker (cri-dockerd)** runtimes in the node stack.
- **Serverless nodes** (EKS Fargate, virtual kubelet): the DaemonSet's node
  affinity skips them, and k3sec names them in a warning.
- **Podman hosts** (`--podman`), rootful, from the container store.
- **`watch --docker` / `--podman`** takes `--logs` (Docker `json-file`, Podman
  `k8s-file`) and `--vulns` (new containers; `--rollback` adds running ones).
- **Runtimes built from source**: Python, Node.js, PHP, Ruby, Perl, Apache
  httpd and Redis in `/usr/local`, the JDK (`release` file) and the Go
  toolchain, as the official images ship them, are matched by CPE (Go as
  `stdlib`) and tagged loaded when running or mapped: 18 of 45 audited images
  had their interpreter invisible.
- **Python distributions** from `dist-info` / `egg-info` (Home Assistant:
  1 641, as syft); a mapped C extension makes one loaded.
- **`node_modules` without a hidden lockfile** read module by module (Ghost:
  2 301), and the working directory of every container process is walked
  (`/var/lib/ghost`, `/usr/src/redmine`).
- **Rust crates** of `cargo auditable` binaries (`.dep-v0` section).
- **Java without `pom.properties`**: named from the manifest and file name,
  matched when the group is known (Spring, Ant, Groovy, Lucene…); Jenkins
  plugins (`.hpi`, `.jpi`); two nesting levels. A Spring Boot app now shows
  Spring4Shell (`CVE-2022-22965`, KEV).
- **Go and Rust binaries on the PATH** read even when not running.
- **Installed gems** from their gemspecs (`ruby:3.3`: 86, as syft); a
  `Gemfile.lock` is trimmed to what is installed, gem platforms dropped.
- **openSUSE / SLES** NDB rpmdb; openSUSE Leap and Tumbleweed matched.
- **Arch Linux** packages (pacman), listed and tagged.
- **.NET** `deps.json` (the runtimes themselves as NuGet runtime packs),
  **PEAR** packages (as `pear/<name>` on Packagist), the **WordPress** core
  (CPE) and its plugins, **Bitnami** components from their SPDX SBOMs.
- **Drift**: running a binary from the container's writable layer (added or
  changed after the container started) is a critical `exec`, with
  `drift=true`.
- **Process ancestry** on exec events (`ancestry` = `nginx > sh`, `ppid`), and
  `exit` events (`--kind exit`).
- **Suspicious execs**: fileless (memfd) and deleted binaries are critical;
  hidden paths and temporary directories (`/tmp`, `/dev/shm`) are warnings.
- **`secret_read`**: a process opening a service account token,
  `/etc/shadow`, SSH keys or cloud and kubeconfig credentials.
- **`escape`**: writes to `release_agent`, `core_pattern`, `modprobe` or
  `uevent_helper`; connects to a container runtime socket; cgroup, kernel
  interface (debugfs, bpf…) and disk mounts. Nothing reported when pods start.
- **`privesc`**: a non-root process that becomes root (setuid).
- **Network**: `listen`, `accept`, `dns` (with the name queried) and `udp`
  (opt-in) events, from a `cgroup_skb` egress program. The DaemonSet now needs
  `NET_ADMIN`.
- **Cryptominers**: DNS queries for mining pools and miner binaries are
  critical, stratum ports a warning; `rules/cryptominer.yar` catches a renamed
  miner.
- **YARA memory scans** after a suspicious exec: the process's anonymous
  executable memory and its memfd and deleted mappings, so unpacked code is
  matched too.
- **MITRE ATT&CK** technique ids in `mitre` on eBPF events.
- **`watch --detect <PATH>`**: your own detection rules, as JSON files. Each
  rule has a CEL condition over the event and can raise its severity, add
  MITRE ids or drop it. Rules reload when a file changes; a broken edit keeps
  the rules in force.
- **`watch --audit-log <PATH>`**: detections on the API server's audit log.
  Critical: an anonymous request that went through, a cluster-admin grant, a
  privileged or host-sharing pod or workload, `nodes/proxy`. Warning: exec,
  attach or port-forward into a pod, secrets listed, tokens minted, a service
  account probing its permissions, events deleted. On the wire to mlab.sh they
  are `k8s-event`s with `kind: "audit"`.
- **`watch --min-severity <LEVEL>`**: only events at least this severe are
  printed, after `--detect` (which may raise them).
- **Less noise**: a `connect`, `udp` or `dns` destination is reported once per
  5 minutes per container; the next report carries `repeats`, how many were
  held back. 50 connects to one address give 1 event.
- **Host processes filtered in the kernel** (cgroup v2): once userspace has
  seen a host cgroup, the kernel drops its events itself. 2 000 execs from a
  host shell give 7 records instead of 2 000.
- **Agent mode (`serve`) sends less**, on the same v1 wire:
  - An image's dormant → loaded promotions are announced once per 2 minutes,
    not on every exec. Each announcement makes mlab fetch the whole inventory.
  - `status` goes out within 10 s of a change, else every 150 s (was every
    60 s). It no longer carries the remote YARA source (up to 1 MiB).
  - Events no longer say things twice: the payload drops what the metadata
    or the object already says. An eBPF event goes from 423 to 300 B.
  - A Kubernetes Event whose `count` goes up is sent once per 5 minutes, and
    its payload on the wire is its `involvedObject` (1.1 KB to 0.1 KB).
  - Batches are cut every 10 s instead of 2 s; a critical event still goes
    at once. A busy minute is 8 envelopes instead of 30.
- **`detect` and `audit_log` in agent mode**: set in the agent's local policy
  (`[tools.k3sec.settings]`), as paths on the node. Rules that fail to load
  stop the start with the reason.

### Fixed

- **eBPF events lost under load**: every `open()` on the host took a ring
  buffer slot before its path was checked. A burst of 2 000 execs in a pod
  gave 757 events, and an idle node dropped about 1 000 records every 30 s.
  Paths are now checked first and the ring is 2 MiB: 2 000 of 2 000, no drop.
- **Agent mode re-uploaded every inventory after `configure`**, with every
  package back to dormant. What was loaded is now kept, and an image
  rescanned unchanged is not announced again.
- **`configure` refused every eBPF kind but exec, connect and file_write.**
  It now accepts all of them, including the opt-in exit, accept and udp.
- **Fixed versions of Red Hat advisories**: an `N:` epoch is now compared
  first and a missing one counts as 0. `0:2.28-251.el8` was taken as older
  than `2.28-225.el8`: on UBI 8.8, 11 of 221 findings had a fixed version, now
  221.
- **Go binaries over 256 MiB** (Vault, 550 MiB) were skipped: only their
  `.go.buildinfo` section is read now. Vault: 0 to 496 modules.
- **Nodes running in a container** (k3d, kind, k3s in Docker): the container
  is taken from the kernel's cgroup id first, and PIDs are renumbered into
  k3sec's own namespace, where they were the kernel's and pointed nowhere.
- **Docker `data-root`** read from `/etc/docker/daemon.json`.
- **Kernel header packages** (`linux-libc-dev`, `linux-headers`,
  `kernel-headers`) are no longer matched: they carried every kernel CVE for a
  kernel that does not run (golang:1.23: 7 126 findings, 1 075 now). On the
  45-image audit: 37 388 findings, 17 192 now; loaded ones 2 968 → 3 266.
- **Lockfiles that describe no installed software** are skipped: inside an
  installed gem, `testdata`, the Go toolchain's own sources.

## [v1.7.0]

### Added

- **Docker hosts without Kubernetes** (`--docker`): `inventory`, `vulns` and
  `watch --ebpf` on the containers of the local Docker daemon, read from its
  state files (`/var/lib/docker`, or `$DOCKER_DATA_ROOT`). A container shows as
  namespace `docker`, pod and container its name.

## [v1.6.0]

### Added

- **k0s, vanilla Kubernetes and Talos**, tested on single-node labs (k0s
  v1.33.4, kind v1.33.1, Talos v1.10.6): `inventory`, `vulns` and `watch` work
  as on k3s. The wiki home lists the cluster compatibility.
- **Node stack on non-k3s nodes**: a kubelet with a vendor tag (`v1.33.4+k0s`,
  `v1.30.4-eks-a737599`, `v1.30.5-gke.1014001`) is matched as upstream
  `k8s.io/kubernetes@v1.33.4`, not as a prerelease of it, which reported CVEs
  already fixed. A k0s node shows as `k0s`.

### Fixed

- **The DaemonSet is admitted where Pod Security enforces `baseline`** (Talos,
  RKE2, some managed clusters): `hostPID`, `hostPath` and the BPF capabilities
  were refused and no pod was created. The `k3sec` namespace is now labelled
  `pod-security.kubernetes.io/enforce: privileged`.

## [v1.5.2]

### Fixed

- **eBPF: the events of a pod living a second reach it.** When a process is
  gone before its `/proc/<pid>/cgroup` is read, its cgroup id finds its
  container in the host's cgroup tree, which was walked again at most once a
  second: a pod started and deleted in between lost its events (seen on a
  DaemonSet node, where every process takes that path). A cgroup id not seen
  yet now walks the tree at once (a few ms); an id a walk did not find is no
  container and is not walked for again. On the lab, a Job of 40 pods: 200 of
  200 events attributed.
- **eBPF: writes to sensitive paths are all caught.** `file_write` was a BPF
  program on `syscalls:sys_enter_openat`, which on recent kernels (7.0) runs
  for few calls, and `open` / `creat` never pass there: 7 of 200 writes under
  `/etc` seen on the lab. It is now a kprobe on `do_sys_openat2`, where every
  open ends: 200 of 200. A kernel without that symbol gets no `file_write`, with
  a warning, and keeps the other kinds.
- **YARA: a binary that runs for a millisecond is scanned.** Its
  `/proc/<pid>/exe` is gone before the scan; it is now read at its exec'd path
  through the root of a live process of its container. On a DaemonSet node of
  the lab: 0 of 20 execs of a marked binary detected before, 20 of 20 now.
- **The exec → loaded promotion of a process already gone** resolves its path
  in the image's root as inventoried, instead of giving up.

### Changed

- **YARA: a file found clean is not scanned again** while its identity
  (device, inode, size, mtime) is the same: 5000 execs of one binary, 2.8 s of
  CPU before, 0.6 s now. A file that matched is never remembered.
- **`serve`: the `events_since` backlog is kept encoded** (a few hundred bytes
  an event, about 6 KB decoded) and also capped at 32 MiB, whatever
  `backlog_events` says: the pod has a memory limit.
- **`vulns` / `watch --vulns`: vuln.mlab.sh answers are decoded record by
  record** instead of whole as a JSON tree: 628 MiB peak before, 232 MiB now,
  same findings.

## [v1.5.1]

Fixes from the first cluster followed in an mlab workspace.

### Fixed

- **eBPF: connects to `0.0.0.0`, `::` and loopback are no longer reported.**
  They never leave the pod: CoreDNS probing its own health endpoint alone made
  one event a second, all day long.
- **eBPF: the first events of a new container reach its pod.** A container
  runs before its pod's status names it, so its first execs went out without
  a pod (and a namespace filter dropped them). An event whose container is not
  known yet now waits up to 2 s for it, without holding back the others; a
  container still unknown then (the node's own) is not waited for again. A
  deleted pod stays known for a minute, so the last events of a short-lived
  pod still reach it.
- **Vulnerabilities: the Go modules of a running binary are `loaded`.** A Go
  binary is statically linked: when it runs, every module it was built with is
  in memory. They were `unknown`, so a running CoreDNS or Caddy showed no
  loaded vulnerability.
- **Vulnerabilities: Debian "unimportant" CVEs are not findings.** Debian
  triages some CVEs as not an issue for a package (disputed, or harmless as
  Debian builds it): `CVE-2013-0337` for nginx, `CVE-2019-1010022` for glibc.
  They were reported, often as critical, with no fix to apply. Only the
  package's own triage counts. On Debian 12: 3 of 8 advisories for nginx, 7 of
  39 for glibc.

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
