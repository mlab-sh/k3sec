# Known limits

What k3sec does **not** see yet, and how it shows up.

## Reachability

- **A snapshot.** `/proc/<pid>/maps` is read once per inventory (plus exec
  events since k3sec started, with `watch --vulns --ebpf`). A library
  `dlopen()`ed later is missed until the next run. A dedicated eBPF `mmap` hook
  is planned for a later milestone.
- **Package granularity.** A loaded `libssl3` makes all of its CVEs "loaded",
  including ones in functions the app never calls.
- **Language deps are `unknown`.** Interpreted code isn't visible in maps.
  Go modules are the exception: those of a running binary are `loaded`.

## Inventory

- **Binaries no package owns.** The official `httpd` and `redis` images build
  the server from source into `/usr/local`: their own CVEs are not matched, only
  those of the libraries they load (lab: httpd 8 loaded packages, none of them
  `httpd`). Go binaries are the exception, through their build info.
- **Java archives without Maven metadata.** Jars are identified by their
  `pom.properties`; a hand-built jar (Tomcat's `catalina.jar`) is not.
- **Python without a lockfile.** Packages installed by `pip` into
  `site-packages` are not inventoried (lab: `python:3.12-slim` shows 0 language
  deps). Only `requirements.txt` `==` pins and `poetry.lock`.
- **Bounded lockfile search.** Usual app dirs only, depth 6, 50 000 entries,
  32 MiB per lockfile, 512 Go binaries and Java archives. `node_modules` is read through its
  hidden lockfile only.
- **rpm**: `rpmdb.sqlite` (EL9+, Fedora, Hummingbird) and the Berkeley DB
  `Packages` (EL7 / EL8), only with `--features rpm`. NDB (SUSE) is not read. Go build info: Go ≥ 1.18.
- **One root per image.** An image is inventoried from one of its containers;
  runtime changes in the other containers of the same digest are not seen.
- **Node-local.** Only containers with a process on this host: one k3sec per
  node.

## Matching

- **Distros**: Debian, Ubuntu, Alpine, Rocky, Alma, RHEL / UBI, Hummingbird
  and Wolfi (Chainguard's public images) are matched (Red Hat streams from the image's `CPE_NAME`; RHEL
  8/9 ask both `baseos` and `appstream`). Oracle Linux has no feed of its own
  and is matched against RHEL advisories, with a warning. Others are
  inventoried with a warning and their OS packages not matched.
- **Red Hat: fixed CVEs only.** The Red Hat feed holds errata (RHSA/RHBA), so
  a CVE Red Hat has not fixed yet (`not-fixed`, `wont-fix` in its VEX) is not
  reported: a patched `ubi9-minimal` shows 0 where grype lists 212 unfixed.
- **Source-package noise.** Distro advisories are filed per source package: a
  dormant `linux-libc-dev` (kernel headers) carries every Debian kernel CVE
  (httpd: 9492 vulns, 104 loaded). `--only-loaded` cuts it.
- **Enrichment budget.** A CVSS v3 vector in the advisory is scored locally
  (most Debian, Red Hat and GHSA records carry one). Per-CVE lookups (CVSS for
  the rest, EU KEV) are capped at 800 per run, loaded code first; beyond, the
  advisory's severity stays (often `unknown` for Debian). httpd 2.4.57: 8 723
  unscored CVEs out of 9 698 before local scoring, 2 069 after. KEV (CISA)
  covers every CVE through the bulk catalogue; EU KEV only enriched CVEs.
- **Kernel** only with `--match-kernel`, by upstream version: NVD's CPE data
  ignores distro backports (9826 hits for `6.8.0`).
- **Anonymous API tier**: 512 packages per request, one scan every 10 s. k3sec
  batches all images into as few requests as possible and waits out cooldowns;
  set `MLAB_API_KEY` for bigger nodes.
- **Loose version ordering** to pick a fixed version among ranges: the API has
  already decided what is affected, but a `fixed` hint may be off for exotic
  version schemes.

## Live stream

- `watch --vulns` reports pods, not the [node stack](Node-Stack).
- **YARA on exec scans the executable** (`/proc/<pid>/exe`): a script is
  scanned as its interpreter (`/bin/busybox`), not as the script's text.
- **Nodes inside containers (k3d, kind, k3s in Docker).** The node's PID
  namespace is not the kernel's, so the PIDs eBPF reports don't exist in the
  node's `/proc`. Events still reach their pod (through the cgroup id), and
  since 1.5.2 YARA on exec and the exec → loaded promotion reach the binary
  through another process of the container. YARA on `file_write` still reads
  the writer's `/proc/<pid>/root` and sees nothing there. On a real node (or
  VM), `hostPID` is the kernel's namespace and all of it works.
- **tracefs** is mounted on the node at `/sys/kernel/tracing` by systemd and
  Talos (not by Talos in Docker, `talosctl cluster create`); the DaemonSet
  mounts it from there. Without it, exec events come from a raw tracepoint
  (attached by name) and the path is read from `/proc/<pid>/exe`: a process
  gone before that reads `exec <name> (path unknown: process gone)`.
