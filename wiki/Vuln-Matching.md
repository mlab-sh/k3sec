# Vulnerability matching

k3sec matches packages through [vuln.mlab.sh](https://vuln.mlab.sh) (OSV, NVD,
GitHub advisories, distro feeds, CISA and EU KEV). The client sits behind a
`VulnSource` trait in `k3sec-inventory`, so tests use a mock and an on-prem mlab
plugs in with `--mlab-url`.

Spec: `openapi.vuln.yaml` of vuln.mlab.sh API 2.5.0 (doc.mlab.sh).

## Endpoints used

| Call | Why |
|------|-----|
| `POST /api/v2/scan` `{"packages":[…]}` | The SBOM / manifest scan endpoint, in its pre-parsed mode: one coordinate per package, `results[i]` answers `packages[i]` with OSV records. |
| `GET /api/v1/cve?kevOnly=1&limit=100&page=N` | The whole CISA KEV catalogue (1762 CVEs, 18 pages), with CVSS. Fetched once, cached. |
| `GET /api/v1/cve/{id}` | CVSS, CISA KEV and EU KEV for one CVE. |

### Why pre-parsed coordinates rather than uploading the SBOM

The API also accepts a CycloneDX document as body. k3sec sends coordinates
instead because:

- the answer is **aligned by index** with what was sent: no re-matching of
  echoed coordinates back to packages;
- distro packages can be asked by **source** package. Measured on the API:
  `{"ecosystem":"Debian:12","name":"openssh-server","version":"1:9.2p1-2"}`
  returns **0** advisories, `openssh` returns **49**.

Coordinates sent, per [package source](Package-Sources):

```json
{"packages": [
  {"ecosystem": "Debian:12", "name": "openssl", "version": "3.0.11-1~deb12u2"},
  {"ecosystem": "Alpine:v3.19", "name": "busybox", "version": "1.36.1-r20"},
  {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
  {"ecosystem": "Go", "name": "github.com/containerd/containerd/v2", "version": "v2.1.4"},
  {"cpe": "cpe:2.3:o:linux:linux_kernel:7.0.0:*:*:*:*:*:*:*"}
]}
```

Coordinates are **deduplicated across images** (every Debian 12 image shares
`glibc`) and sent in chunks of 512 (the anonymous tier's limit).

## From advisories to findings

- **One finding per CVE per package.** The CVE comes from the advisory id
  (`CVE-…`, `DEBIAN-CVE-…`, `ALPINE-CVE-…`), `aliases` or `upstream`. Several
  feeds describing one CVE (`DEBIAN-CVE-2023-42363` + `GHSA-…`) merge into one
  finding listing both in `advisories`. A distro erratum fixing several CVEs
  (`RLSA-…`) gives one finding per CVE. An advisory with no CVE keeps its own id
  (`GHSA-…`, `GO-…`).
- **Debian "unimportant"**: an advisory Debian triaged `unimportant` for this
  package (`ecosystem_specific.urgency`: disputed, or harmless as Debian builds
  it) is not a finding. Only this package's entries count: `CVE-2023-44487` is
  `end-of-life` for `dnsdist`, which says nothing about `nginx`. On Debian 12:
  3 of 8 advisories for nginx, 7 of 39 for glibc.
- **Fixed version**: the smallest `fixed` of a range that contains the
  installed version, for **this** package in **this** ecosystem (an Alpine record
  lists every branch: `Alpine:v3.18 … fixed 1.36.1-r7`,
  `Alpine:v3.19 … fixed 1.36.1-r17`; k3sec picks the v3.19 one).
- **Severity**: the CVE's CVSS (v3.1, else v3.0, else v2) when known, banded
  critical ≥ 9, high ≥ 7, medium ≥ 4, low; else the advisory's label (`HIGH`,
  `MODERATE`, …); else `unknown`.
- **KEV**: in the CISA catalogue (bulk) or CISA / EU KEV for enriched CVEs. A
  CVE-less advisory is never KEV.

### Enrichment budget

One distro package can carry thousands of CVEs: the dormant `linux-libc-dev`
in httpd's image carries the ~9 000 Debian files against the `linux` source.
So:

- the **KEV catalogue** is fetched in bulk, so every CVE gets a KEV status;
- **per-CVE** lookups (CVSS, EU KEV) are capped at 800 per run, CVEs of loaded
  packages first. The rest keep their advisory severity. On the lab:

```text
INFO CVE enrichment capped: the rest keep their advisory severity skipped=8699
INFO enriching CVEs (CVSS, KEV) cves=800
```

## Cache

| Path | Content | Validity |
|------|---------|----------|
| `$XDG_CACHE_HOME/k3sec/vulns/<digest>.json` (else `~/.cache/k3sec/…`) | Findings by package purl for one image digest | `--cache-ttl`, default 6 h |
| `$XDG_CACHE_HOME/k3sec/kev.json` | The KEV catalogue | same |

Lab cache after a run:

```text
-rw-r--r-- 1 root root  162641 Oct 29 13:51 kev.json
vulns/
-rw-r--r-- 1 root root   46593 sha256_1391544c978029fcddc65068f6ad67f396e55585b664ecccd7fefba029b9b706.json
-rw-r--r-- 1 root root  123921 sha256_305de618a5681ff75b1d608fd22b10f362867dff2f550a4f1d427d21cd7f42b4.json
-rw-r--r-- 1 root root  145387 sha256_352c1fdadc91926edda08f45aeb3f27f37194c2f14101229c0523a11195c96e3.json
-rw-r--r-- 1 root root 2708187 sha256_374766f5bc5977c9b72fdb8ae3ed05b7fc89060e7edc88fcbf142d6988e58eeb.json
-rw-r--r-- 1 root root    6311 sha256_6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1.json
-rw-r--r-- 1 root root   56436 sha256_80496fdeb307541007621959aa13aed41d31db9cd2dc4167c19833e0bfa3878c.json
-rw-r--r-- 1 root root  246673 sha256_c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2.json
```

- An image is immutable per digest; advisories aren't: hence the TTL.
- Reachability is **never** cached: it's recomputed every run and applied to
  the cached findings.
- Entries remember which `--mlab-url` produced them: switching to an on-prem
  mlab doesn't serve vuln.mlab.sh's answers.
- An image with packages the API didn't answer for is not cached.
- `--no-cache` skips reading, still writes fresh results.
- Writes go to a temp file renamed into place; any cache error is a miss.
- Under `sudo`, `~` is root's: set `XDG_CACHE_HOME` to choose.

## Retries and degradation

| Situation | Behavior |
|-----------|----------|
| Network error, 5xx | 4 attempts, backoff 1 s, 2 s, 4 s |
| `429` (anonymous: one scan / 10 s) | wait `Retry-After` (≤ 60 s), up to 6 times: `INFO vuln.mlab.sh cooldown, retrying in 2s` |
| `413` and other 4xx | fail with the API's message: `… refused the request (413 Payload Too Large): The request body is larger than 4 MiB` |
| `ok: false`, `outage: true`, truncated answer | those packages are **not scanned** (`unscanned_packages`), never reported clean, not cached |
| KEV catalogue unavailable | `WARN KEV catalogue unavailable, checking CVEs one by one` |
| API unreachable | inventory printed anyway, `error` per image, exit 0 |

Timeouts: 10 s to connect, 60 s per request. A malformed OSV record is skipped
alone, it doesn't sink the response.

## API key

`MLAB_API_KEY` (optional) is sent as `Authorization: Bearer`. It raises the
tier's limits (anonymous: 512 packages per scan, 4 MiB, 10 s cooldown; free
account: 1024, 8 MiB, 5 s; paid: 4096, 32 MiB, none). It never appears in logs,
errors or `Debug` output. Create one at <https://vuln.mlab.sh/me/tokens>.

```bash
sudo MLAB_API_KEY=... k3sec vulns
sudo k3sec vulns --mlab-url https://vuln.internal.example   # on-prem mlab
```
