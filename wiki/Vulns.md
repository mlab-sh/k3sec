# `k3sec vulns`

[`inventory`](Inventory) + vulnerability matching through
[vuln.mlab.sh](Vuln-Matching), sorted for triage: **loaded + KEV** first, then
loaded, then KEV, then by severity and CVSS.

```bash
sudo k3sec vulns                                   # everything, grouped by image
sudo k3sec vulns --only-loaded --min-severity high # what to patch first
sudo k3sec vulns --kev-only                        # known exploited, loaded or not
sudo k3sec vulns -o json | jq '.images[].findings[] | select(.reachability=="loaded")'
MLAB_API_KEY=... sudo -E k3sec vulns               # higher API limits
```

## Real output

### Everything

`sudo k3sec vulns` on the [test lab](Development#test-lab), first lines and the
per-image counters:

```text
11507 vulns, 335 loaded (1 KEV loaded) across 7 images
node k3sec-m4-node  v1.33.5+k3s1 · containerd://2.1.4-k3s1 · kernel 7.0.0-38-generic

docker.io/library/alpine:3.19 (sha256:6baf43584bcb)  Alpine Linux v3.19
  17 vulns, 4 loaded (cached)
docker.io/library/httpd:2.4.58 (sha256:374766f5bc59)  Debian GNU/Linux 12 (bookworm)
  9492 vulns, 104 loaded (cached)
docker.io/library/nginx:1.25.3 (sha256:c7a6ad68be85)  Debian GNU/Linux 12 (bookworm)
  829 vulns, 104 loaded (cached)
docker.io/library/redis:7.0.15 (sha256:352c1fdadc91)  Debian GNU/Linux 12 (bookworm)
  489 vulns, 73 loaded (cached)
docker.io/library/rockylinux:9-minimal (sha256:305de618a568)  Rocky Linux 9.3 (Blue Onyx)
  371 vulns, 38 loaded (cached)
docker.io/rancher/mirrored-coredns-coredns:1.12.3 (sha256:1391544c9780)  Distroless
  117 vulns, 0 loaded (cached)
docker.io/rancher/local-path-provisioner:v0.0.31 (sha256:80496fdeb307)  Alpine Linux v3.21
  180 vulns, 0 loaded (cached)
node/k3sec-m4-node  K3s v1.33.5+k3s1
  12 vulns, 12 loaded
```

11507 is what a "list every CVE" scanner reports. 335 are in code that is
mapped in a process right now, and **one** of those is known exploited. httpd's
9492 come almost entirely from the dormant `linux-libc-dev` headers package (see
[Known limits](Known-Limits)).

The nginx section, top of the list:

```text
docker.io/library/nginx:1.25.3 (sha256:c7a6ad68be85)  Debian GNU/Linux 12 (bookworm)
  pods: demo/nginx-75b7c5fd7b-dhmqv/nginx, demo/nginx-75b7c5fd7b-qsx24/nginx
  829 vulns, 104 loaded
  LOADED   KEV  HIGH  7.5  CVE-2023-44487     nginx 1.25.3-1~bookworm
  LOADED        CRIT  9.8  CVE-2019-1010022   libc6 2.36-9+deb12u4
  LOADED        CRIT  9.8  CVE-2023-45853     zlib1g 1:1.2.13.dfsg-1
  LOADED        CRIT  9.8  CVE-2026-31789     libssl3 3.0.11-1~deb12u2  → 3.0.19-1~deb12u2
  LOADED        CRIT  9.8  CVE-2026-5450      libc6 2.36-9+deb12u4
  LOADED        CRIT  9.1  CVE-2024-5535      libssl3 3.0.11-1~deb12u2  → 3.0.15-1~deb12u1
  LOADED        CRIT  9.1  CVE-2026-34182     libssl3 3.0.11-1~deb12u2  → 3.0.20-1~deb12u2
  LOADED        CRIT  9.1  CVE-2026-75803     libssl3 3.0.11-1~deb12u2  → 3.0.22-1~deb12u1
  LOADED        HIGH  8.8  CVE-2025-15467     libssl3 3.0.11-1~deb12u2  → 3.0.18-1~deb12u2
  LOADED        HIGH  8.8  CVE-2026-45447     libssl3 3.0.11-1~deb12u2  → 3.0.20-1~deb12u2
```

Columns: reachability, `KEV` (CISA or EU known-exploited; `?` = could not be
checked), severity, CVSS, CVE (or the advisory id when there is no CVE),
package, installed version, and `→ fixed version` when the advisory gives one
for this distro release.

CVE-2023-44487 (HTTP/2 Rapid Reset) is in the running `nginx` binary itself and
is actively exploited: it's the first line, ahead of 9.8s in dormant packages.

### What to patch first

`sudo k3sec vulns --only-loaded --min-severity high -n demo`:

```text
164 vulns, 164 loaded (1 KEV loaded) across 5 images
node k3sec-m4-node  v1.33.5+k3s1 · containerd://2.1.4-k3s1 · kernel 7.0.0-38-generic

docker.io/library/alpine:3.19 (sha256:6baf43584bcb)  Alpine Linux v3.19
  pods: demo/alpine-app/app
  1 vulns, 1 loaded (cached)
  LOADED        HIGH  8.1  CVE-2026-40200     musl 1.2.4_git20230717-r5  → 1.2.4_git20230717-r6

docker.io/library/httpd:2.4.58 (sha256:374766f5bc59)  Debian GNU/Linux 12 (bookworm)
  pods: demo/httpd/httpd
  48 vulns, 48 loaded (cached)
  LOADED        CRIT  9.8  CVE-2019-1010022   libc6 2.36-9+deb12u4
  LOADED        CRIT  9.8  CVE-2024-45491     libexpat1 2.5.0-1  → 2.5.0-1+deb12u1
  LOADED        CRIT  9.8  CVE-2024-45492     libexpat1 2.5.0-1  → 2.5.0-1+deb12u1
  ...

docker.io/library/rockylinux:9-minimal (sha256:305de618a568)  Rocky Linux 9.3 (Blue Onyx)
  pods: demo/rocky/rocky
  20 vulns, 20 loaded (cached)
  LOADED        CRIT  9.8  CVE-2026-5450      glibc 2.34-83.el9.7
  LOADED        HIGH  8.4  CVE-2026-0861      glibc 2.34-83.el9.7
  LOADED        HIGH  8.2  CVE-2026-86145     pcre2 10.40-2.el9
```

From 9492 to 48 for httpd. The counters in the header and per image always
count what the filters kept.

### Known exploited

`sudo k3sec vulns --kev-only` (the KEV lines):

```text
18 vulns, 1 loaded (1 KEV loaded) across 7 images
  dormant  KEV  CRIT  9.8  CVE-2025-39682     linux-libc-dev 6.1.76-1  → 6.1.153-1
  dormant  KEV  CRIT  9.8  CVE-2026-111497    libbrotli1 1.0.9-2+b6  → 1.0.9-2+deb12u1
  dormant  KEV  HIGH  8.8  CVE-2026-53266     linux-libc-dev 6.1.76-1  → 6.1.176-1
  ...
  LOADED   KEV  HIGH  7.5  CVE-2023-44487     nginx 1.25.3-1~bookworm
  dormant  KEV  CRIT  9.8  CVE-2026-111497    libbrotli1 1.0.9-2+b6  → 1.0.9-2+deb12u1
  dormant  KEV  HIGH  8.1  CVE-2025-27363     libfreetype6 2.12.1+dfsg-5  → 2.12.1+dfsg-5+deb12u4
  dormant  KEV  MED   6.1  CVE-2020-11023     libgcc 11.4.1-2.1.el9
  dormant  KEV  MED   6.1  CVE-2020-11023     libstdc++ 11.4.1-2.1.el9
```

18 known-exploited CVEs on the node, one of them in running code. The
`linux-libc-dev` ones are kernel CVEs filed against kernel *headers* in httpd's
image: present, never executed.

### The kernel too

The kernel is only matched with `--match-kernel` ([why](Node-Stack)). Combined
with the filters it is usable:
`sudo k3sec vulns --match-kernel --only-loaded --kev-only`, node section:

```text
node/k3sec-m4-node  K3s v1.33.5+k3s1
  4 vulns, 4 loaded
  LOADED   KEV  HIGH  8.8  CVE-2026-53266     linux 7.0.0-38-generic
  LOADED   KEV  HIGH  7.8  CVE-2026-31431     linux 7.0.0-38-generic
  LOADED   KEV  HIGH  7.8  CVE-2026-46300     linux 7.0.0-38-generic
  LOADED   KEV  HIGH  7.8  CVE-2026-53362     linux 7.0.0-38-generic
```

Kernel matches go by upstream version (NVD CPE): check each against your
distro's kernel changelog before acting.

## JSON

`-o json` prints one document. `sudo k3sec vulns --kev-only -o json`:

```json
{
  "summary": { "vulns": 18, "loaded": 1, "kev_loaded": 1 },
  "node": { "node": "k3sec-m4-node", "kubelet": "v1.33.5+k3s1", "...": "..." },
  "images": [{
    "image": "docker.io/library/nginx:1.25.3",
    "digest": "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2",
    "os": { "id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)" },
    "containers": [ "..." ],
    "findings": [{
      "id": "CVE-2023-44487",
      "advisories": ["DEBIAN-CVE-2023-44487"],
      "package": "nginx",
      "version": "1.25.3-1~bookworm",
      "purl": "pkg:deb/debian/nginx@1.25.3-1~bookworm?arch=amd64&distro=debian-12",
      "severity": "high",
      "cvss": 7.5,
      "kev": true,
      "reachability": "loaded"
    }],
    "unmatched_packages": 0,
    "unscanned_packages": 0,
    "cached": true,
    "error": null,
    "warnings": []
  }]
}
```

- `kev`: `true` / `false`, or `null` when it couldn't be checked.
- `fixed`, `summary`, `cvss` are omitted when unknown.
- `unmatched_packages`: packages whose ecosystem can't be matched (unsupported
  distro).
- `unscanned_packages`: packages the API didn't answer for this run. **Not
  clean**: they were not checked.
- `error`: set when matching failed for the image (API down); the inventory is
  still there.

## When the API is down

`sudo k3sec vulns -n demo --no-cache --mlab-url http://127.0.0.1:9`:

```text
2026-10-29T14:44:24.087968Z  INFO inventoried running containers (skipped = no process on this host) images=5 containers=7 skipped=0
2026-10-29T14:44:31.094465Z  WARN vulnerability matching unavailable; inventory only error=cannot reach http://127.0.0.1:9 after 4 attempts: error sending request for url (http://127.0.0.1:9/api/v2/scan)
0 vulns, 0 loaded (0 KEV loaded) across 5 images
node k3sec-m4-node  v1.33.5+k3s1 · containerd://2.1.4-k3s1 · kernel 7.0.0-38-generic

docker.io/library/alpine:3.19 (sha256:6baf43584bcb)  Alpine Linux v3.19
  pods: demo/alpine-app/app
  0 vulns, 0 loaded
  ! vulnerability matching unavailable: cannot reach http://127.0.0.1:9 after 4 attempts: error sending request for url (http://127.0.0.1:9/api/v2/scan)
```

Retried with backoff (1 s, 2 s, 4 s), then reported per image, exit code 0. See
[Vulnerability matching](Vuln-Matching#retries-and-degradation).

## Speed

On the lab node (7 images, 516 OS packages + 222 language deps), anonymous tier: about 10 s the first
time, 20 s with the 9k-CVE httpd image (enrichment capped), **0.75 s** from the
cache.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-n, --namespace <NS>` | One namespace | all |
| `--node <NAME>` | This node's name | `$NODE_NAME`, else all pods |
| `--min-severity <unknown\|low\|medium\|high\|critical>` | Hide lower severities | all |
| `--only-loaded` | Only vulns in loaded code | off |
| `--kev-only` | Only known-exploited vulns (CISA / EU KEV) | off |
| `--mlab-url <URL>` | vuln.mlab.sh base URL, or an on-prem mlab | `https://vuln.mlab.sh` |
| `--no-cache` | Don't read the cache (still refreshes it) | off |
| `--cache-ttl <SECS>` | Validity of cached results per digest | 21600 (6 h) |
| `--match-kernel` | Also match the kernel by CPE | off |
| `-o, --output <pretty\|json>` | Output format | `pretty` |

Environment: `MLAB_API_KEY` (optional, never logged), `XDG_CACHE_HOME`,
`NODE_NAME`, `NO_COLOR`, `RUST_LOG`.
