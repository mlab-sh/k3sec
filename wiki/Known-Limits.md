# Known limits

What k3sec does **not** see yet, and how it shows up.

## Reachability

- **A snapshot.** `/proc/<pid>/maps` is read once per inventory (plus exec
  events since k3sec started, with `watch --vulns --ebpf`). A library
  `dlopen()`ed later is missed until the next run. A dedicated eBPF `mmap` hook
  is planned for a later milestone.
- **Package granularity.** A loaded `libssl3` makes all of its CVEs "loaded",
  including ones in functions the app never calls.
- **Language deps are `unknown`.** Interpreted code isn't visible in maps, and
  Go modules of a running static binary are reported `unknown` too.

## Inventory

- **Binaries no package owns.** The official `httpd` and `redis` images build
  the server from source into `/usr/local`: their own CVEs are not matched, only
  those of the libraries they load (lab: httpd 8 loaded packages, none of them
  `httpd`). Go binaries are the exception, through their build info.
- **Python without a lockfile.** Packages installed by `pip` into
  `site-packages` are not inventoried (lab: `python:3.12-slim` shows 0 language
  deps). Only `requirements.txt` `==` pins and `poetry.lock`.
- **Bounded lockfile search.** Usual app dirs only, depth 6, 50 000 entries,
  32 MiB per lockfile, 128 Go binaries. `node_modules` is read through its
  hidden lockfile only.
- **rpm**: `rpmdb.sqlite` only (EL9+, Fedora 33+), and only with
  `--features rpm`. Go build info: Go ≥ 1.18.
- **One root per image.** An image is inventoried from one of its containers;
  runtime changes in the other containers of the same digest are not seen.
- **Node-local.** Only containers with a process on this host: one k3sec per
  node.

## Matching

- **Distros**: Debian, Ubuntu, Alpine, Rocky and Alma are matched. Others are
  inventoried with a warning and their OS packages not matched.
- **Source-package noise.** Distro advisories are filed per source package: a
  dormant `linux-libc-dev` (kernel headers) carries every Debian kernel CVE
  (httpd: 9492 vulns, 104 loaded). `--only-loaded` cuts it.
- **Enrichment budget.** Per-CVE CVSS / EU KEV lookups are capped at 800 per
  run, loaded code first; the rest keep the advisory's severity (often
  `unknown` for Debian). KEV (CISA) covers every CVE through the bulk catalogue.
  EU KEV only for enriched CVEs.
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
- The eBPF exec → loaded promotion was not exercised on the lab (no
  `bpf-linker`); it's covered by unit tests on a fake rootfs.
- The [DaemonSet](Deployment#as-a-daemonset) manifest is a template, not yet run
  end to end.
