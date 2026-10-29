# Package sources

Everything is read from the **live** container filesystem, through
`/proc/<pid>/root` of one of the container's processes: no registry pull, no
access to containerd snapshots, nothing to configure. Files added at runtime in
that container are seen too.

## Distro detection

`/etc/os-release`, falling back to `/usr/lib/os-release`. It decides the
vulnerability ecosystem and the purl `distro` qualifier:

| `ID` | Ecosystem (matching) | purl | Lab image |
|------|----------------------|------|-----------|
| `debian` | `Debian:<major>` | `pkg:deb/debian/...&distro=debian-12` | nginx, redis, httpd (12), python:3.12-slim (13) |
| `ubuntu` | `Ubuntu:<ver>:LTS` (even year `.04`), else `Ubuntu:<ver>` | `pkg:deb/ubuntu/...` | |
| `alpine` | `Alpine:v<major.minor>` | `pkg:apk/alpine/...&distro=alpine-3.19.9` | alpine:3.19, local-path-provisioner (3.21) |
| `rocky` | `Rocky Linux:<major>` | `pkg:rpm/rocky/...` | rockylinux:9-minimal |
| `almalinux` | `AlmaLinux:<major>` | `pkg:rpm/almalinux/...` | |
| anything else | not matched (warning) | inventoried | |

Distroless images report `PRETTY_NAME="Distroless"` with `ID=debian`.

## OS packages

| Manager | Read from | Files per package | Notes |
|---------|-----------|-------------------|-------|
| **dpkg** | `/var/lib/dpkg/status` | `info/<pkg>.list`, `info/<pkg>:<arch>.list` | only `Status: … installed`; `Source:` kept (`bash (5.2.15-2)` gives source name **and** version) |
| **dpkg, distroless** | `/var/lib/dpkg/status.d/<pkg>` | `status.d/<pkg>.md5sums` | coredns on the lab |
| **apk** | `/lib/apk/db/installed` | `F:` directory + `R:` files | `o:` origin = source package |
| **rpm** | `/var/lib/rpm/rpmdb.sqlite` | header `DIRNAMES` / `BASENAMES` / `DIRINDEXES` | build with `--features rpm`; source package from `SOURCERPM`; epoch kept; `gpg-pubkey` skipped |

Distro advisories are filed against the **source** package: Debian tracks
`openssh`, not `openssh-server`; `libssl3` is matched as `openssl`, `libc6` as
`glibc`. k3sec matches on the source name and version, and keeps the binary
name in the purl with an `upstream=` qualifier:

```text
pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl
```

**rpm and the magic link.** SQLite canonicalizes the path of the database it
opens, and `/proc/<pid>/root` is a magic link whose target reads as `/`: opened
in place, it would open the *host's* rpmdb. k3sec copies the database (bounded
to 64 MiB) to a temp file and opens the copy read-only (`immutable=1`). Older
Berkeley DB / NDB rpmdbs (EL8 and earlier) are not read.

Without `--features rpm`, an rpm image is listed with a warning (real output,
default build):

```text
docker.io/library/rockylinux:9-minimal (sha256:305de618a568)  Rocky Linux 9.3 (Blue Onyx)
  pods: demo/rocky/rocky
  packages: 0 OS (0 loaded, 0 dormant), 0 language deps · 8 mapped files
  ! rpm-based image: OS packages not inventoried (build k3sec with `--features rpm`)
```

With it: `118 OS (7 loaded, 111 dormant)`.

Package databases over 64 MiB are refused (corrupt or hostile).

## Language dependencies (best effort)

A bounded walk of the usual app directories: `/app`, `/usr/src/app`, `/srv`,
`/opt`, `/home`, `/root`, `/var/www`, `/workspace`, `/code`, `/usr/local/bin`,
`/usr/local/lib`. Depth 6, 50 000 directory entries in total, symlinks not
followed, `.git` / `__pycache__` / `.cache` skipped. `node_modules` is not
descended: its hidden `node_modules/.package-lock.json` (npm ≥ 7) describes the
whole tree.

| File | Ecosystem | What is read |
|------|-----------|--------------|
| `package-lock.json`, `npm-shrinkwrap.json`, `node_modules/.package-lock.json` | npm | v2/v3 `packages` (links skipped), v1 nested `dependencies` |
| `yarn.lock` | npm | v1 and berry |
| `Cargo.lock` | crates.io | `[[package]]` with a `source` (workspace members skipped) |
| `go.sum` | Go | `module version`, deduplicated |
| `requirements.txt` | PyPI | `==` pins only (extras, markers, comments stripped) |
| `poetry.lock` | PyPI | `[[package]]` |
| `composer.lock` | Packagist | `packages` + `packages-dev` |
| `Gemfile.lock` | RubyGems | top-level `GEM` specs |
| **Go binaries** | Go | build info (Go ≥ 1.18): every module **and** the Go `stdlib` version |

Lockfiles over 32 MiB are skipped. Go build info is read from the running
binaries (`/proc/<pid>/exe`) first, then from executables met in the walk, 128
binaries at most, 256 MiB each.

On the lab:

| Image | Language deps | From |
|-------|---------------|------|
| alpine-app | `lodash 4.17.20`, `express 4.17.1` | `/app/package-lock.json` |
| redis | `stdlib 1.18.2`, `github.com/moby/sys/user v0.1.0`, `golang.org/x/sys v0.13.0` | `/usr/local/bin/gosu` |
| coredns | 162 | the `coredns` binary |
| local-path-provisioner | 55 | its binary |

Language deps are always [`unknown`](Reachability#why-language-deps-are-unknown).

## purls

| Ecosystem | purl |
|-----------|------|
| npm | `pkg:npm/%40babel/core@7.24.0`, `pkg:npm/lodash@4.17.20` |
| crates.io | `pkg:cargo/serde@1.0.197` |
| Go | `pkg:golang/github.com/gin-gonic/gin@v1.9.1`, `pkg:golang/stdlib@1.18.2` |
| PyPI | `pkg:pypi/django-rest-framework@3.15.1` (PEP 503 normalized) |
| Packagist | `pkg:composer/symfony/http-kernel@6.4.3` |
| RubyGems | `pkg:gem/rails@7.1.3` |
| dpkg | `pkg:deb/debian/<name>@<ver>?arch=…&distro=…[&upstream=<src>]` |
| apk | `pkg:apk/alpine/<name>@<ver>?arch=…&distro=…[&upstream=<origin>]` |
| rpm | `pkg:rpm/rocky/<name>@<ver>-<rel>?arch=…&distro=…[&epoch=…][&upstream=<src>]` |

Qualifiers are sorted, values percent-encoded (`+` → `%2B`; `:` kept, as in
Debian epochs).

## Deduplication

Containers are grouped by image **digest** (from `containerStatus.imageID`):
10 pods of one image are one inventory. The [cache](Vuln-Matching#cache) is
keyed by digest as well.
