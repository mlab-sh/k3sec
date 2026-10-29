# `k3sec inventory`

One-shot inventory of every container **running on this node**: OS packages,
language dependencies, and for each package whether its code is
[loaded](Reachability) in memory right now.

```bash
sudo k3sec inventory                     # pretty, all namespaces
sudo k3sec inventory -n demo -o json     # one JSON document
sudo k3sec inventory --sbom ./sboms/     # + one CycloneDX SBOM per image digest
```

Needs root (it reads containers' filesystems through `/proc/<pid>/root`), see
[Deployment](Deployment). Nothing is pulled from a registry: the inventory is
read from the live container filesystem.

## Real output

On the [test lab](Development#test-lab) node (2 nginx replicas, redis × 2,
httpd, an Alpine app with a `package-lock.json`, Rocky 9, plus k3s's own
coredns and local-path-provisioner):

```text
node k3sec-m4-node  v1.33.5+k3s1 · containerd://2.1.4-k3s1 · kernel 7.0.0-38-generic

docker.io/library/alpine:3.19 (sha256:6baf43584bcb)  Alpine Linux v3.19
  pods: demo/alpine-app/app
  packages: 15 OS (2 loaded, 13 dormant), 2 language deps · 2 mapped files
  loaded: busybox 1.36.1-r20, musl 1.2.4_git20230717-r5

docker.io/library/httpd:2.4.58 (sha256:374766f5bc59)  Debian GNU/Linux 12 (bookworm)
  pods: demo/httpd/httpd
  packages: 126 OS (8 loaded, 118 dormant), 0 language deps · 33 mapped files
  loaded: libapr1 1.7.2-3, libaprutil1 1.6.3-1, libc6 2.36-9+deb12u4, libcrypt1 1:4.4.33-2, libexpat1 2.5.0-1, libgcc-s1 12.2.0-14, libpcre3 2:8.39-15, libuuid1 2.38.1-5+b1

docker.io/library/nginx:1.25.3 (sha256:c7a6ad68be85)  Debian GNU/Linux 12 (bookworm)
  pods: demo/nginx-57fcccff77-4hhkt/nginx, demo/nginx-57fcccff77-l8lzs/nginx
  packages: 149 OS (6 loaded, 143 dormant), 0 language deps · 10 mapped files
  loaded: libc6 2.36-9+deb12u4, libcrypt1 1:4.4.33-2, libpcre2-8-0 10.42-1, libssl3 3.0.11-1~deb12u2, nginx 1.25.3-1~bookworm, zlib1g 1:1.2.13.dfsg-1

docker.io/library/redis:7.0.15 (sha256:352c1fdadc91)  Debian GNU/Linux 12 (bookworm)
  pods: demo/redis/redis, demo/redis2/redis2
  packages: 89 OS (2 loaded, 87 dormant), 3 language deps · 6 mapped files
  loaded: libc6 2.36-9+deb12u8, libssl3 3.0.14-1~deb12u2

docker.io/library/rockylinux:9-minimal (sha256:305de618a568)  Rocky Linux 9.3 (Blue Onyx)
  pods: demo/rocky/rocky
  packages: 118 OS (7 loaded, 111 dormant), 0 language deps · 8 mapped files
  loaded: glibc 2.34-83.el9.7, libattr 2.5.1-3.el9, libacl 2.3.1-3.el9, libcap 2.48-9.el9_2, pcre2 10.40-2.el9, libselinux 3.5-1.el9, coreutils-single 8.32-34.el9

docker.io/rancher/mirrored-coredns-coredns:1.12.3 (sha256:1391544c9780)  Distroless
  pods: kube-system/coredns-64fd4b4794-4ssl2/coredns
  packages: 4 OS (0 loaded, 4 dormant), 162 language deps · 1 mapped files

docker.io/rancher/local-path-provisioner:v0.0.31 (sha256:80496fdeb307)  Alpine Linux v3.21
  pods: kube-system/local-path-provisioner-774c6665dc-m2mn4/local-path-provisioner
  packages: 15 OS (0 loaded, 15 dormant), 55 language deps · 1 mapped files
```

What to read in it:

- **Dedup by digest**: the two nginx pods (and the two redis pods) are one
  inventory each.
- **nginx**: 6 of 149 packages are in memory. The other 143 are on disk only.
- **redis**: `redis-server` is built from source into `/usr/local/bin` by the
  official image, so only its libraries are owned by a package. The 3 language
  deps come from the Go build info of `gosu`.
- **Rocky**: `sleep` runs, so `coreutils-single` (and its libraries) is loaded
  (needs `--features rpm`).
- **coredns**: distroless (`/var/lib/dpkg/status.d`), one static Go binary: the
  162 deps come from its embedded build info, reported `unknown`.

stderr:

```text
2026-10-29T14:43:50.368103Z  INFO inventoried running containers (skipped = no process on this host) images=7 containers=9 skipped=0
2026-10-29T14:43:51.097137Z  INFO wrote SBOM image=docker.io/library/nginx:1.25.3 path=./sboms/sha256_c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2.cdx.json
```

## JSON

`-o json` prints one document: `{"node": {...}, "images": [...]}`. Excerpts
from `sudo k3sec inventory -n demo -o json`:

```json
{
  "node": { "node": "k3sec-m4-node", "kubelet": "v1.33.5+k3s1", "container_runtime": "containerd://2.1.4-k3s1", "kernel": "7.0.0-38-generic", "os_image": "K3s v1.33.5+k3s1" },
  "images": [{
    "image": "docker.io/library/nginx:1.25.3",
    "digest": "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2",
    "os": { "id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)" },
    "containers": [
      { "namespace": "demo", "pod": "nginx-57fcccff77-4hhkt", "container": "nginx",
        "image": "docker.io/library/nginx:1.25.3",
        "image_digest": "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2",
        "container_id": "10e68b8f2cbcede549288a7cf3441e7dcef752b31180f2bedb5df860935a9a5f" }
    ],
    "packages": [
      { "name": "libssl3", "version": "3.0.11-1~deb12u2", "kind": "os",
        "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
        "source": "openssl", "reachability": "loaded" },
      { "name": "nginx", "version": "1.25.3-1~bookworm", "kind": "os",
        "purl": "pkg:deb/debian/nginx@1.25.3-1~bookworm?arch=amd64&distro=debian-12",
        "reachability": "loaded" }
    ],
    "mapped_files": 10
  }]
}
```

A language dependency carries the lockfile it came from:

```json
{ "name": "lodash", "version": "4.17.20", "kind": "lang", "purl": "pkg:npm/lodash@4.17.20",
  "location": "/app/package-lock.json", "reachability": "unknown" }
```

Package fields: `name`, `version`, `kind` (`os` / `lang` / `node`), `purl`,
`source` (source package when it differs), `location` (language deps),
`reachability`. An image also has `warnings` when something couldn't be read
(unsupported distro, rpm db without `--features rpm`, ...).

## SBOMs (`--sbom <dir>`)

One CycloneDX 1.5 JSON file per image digest, `<dir>/<digest>.cdx.json`. The
container image is the root component, each package a `library` component with
its purl as `bom-ref`, and the reachability in a `k3sec:reachability` property:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-29T18:37:31Z",
    "tools": { "components": [{ "type": "application", "name": "k3sec", "version": "1.5.0" }] },
    "component": { "type": "container",
      "bom-ref": "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2",
      "name": "docker.io/library/nginx:1.25.3",
      "version": "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2" }
  },
  "components": [
    { "type": "library", "bom-ref": "pkg:deb/debian/adduser@3.134?arch=all&distro=debian-12",
      "name": "adduser", "version": "3.134", "purl": "pkg:deb/debian/adduser@3.134?arch=all&distro=debian-12",
      "properties": [{ "name": "k3sec:reachability", "value": "dormant" }, { "name": "k3sec:kind", "value": "os" }] }
  ]
}
```

The nginx SBOM has 149 components. Language deps add a `k3sec:location`
property.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-n, --namespace <NS>` | One namespace | all |
| `--node <NAME>` | This node's name (pod listing scope) | `$NODE_NAME`, else all pods |
| `--sbom <DIR>` | Write CycloneDX JSON per digest | off |
| `--match-kernel` | Accepted for symmetry with `vulns` (no effect here) | off |
| `-o, --output <pretty\|json>` | Output format | `pretty` |

Without `--node`, every pod of the cluster is listed and the ones with no
process on this host are skipped (`skipped=` on stderr): run k3sec on each node.
