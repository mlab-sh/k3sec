# Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo clippy -p k3sec-inventory --all-targets --features rpm -- -D warnings
cargo test -p k3sec-inventory --features rpm     # rpm header parser
```

CI (`.github/workflows/ci.yml`) runs exactly that. The `ebpf` feature is left
out (it needs a nightly BPF toolchain and `bpf-linker`); `k3sec-probe-ebpf` is a
workspace member but not a default member, and has `test = false`, so a host
`cargo test --workspace` doesn't try to link it.

## Tests

| Area | How |
|------|-----|
| dpkg, distroless `status.d`, apk, os-release | real files extracted from `debian:12-slim`, `alpine:3.19`, `ubuntu:22.04`, `rockylinux:9-minimal` (`crates/k3sec-inventory/tests/fixtures/`) |
| lockfiles | fixtures for npm v1/v3, yarn v1/berry, Cargo, poetry, go.sum, requirements, composer, Gemfile |
| rpm | synthetic header blobs (feature `rpm`) |
| Go build info | synthetic binary with a real-format `.go.buildinfo` |
| rootfs resolver | temp dir with usrmerge, absolute, escaping and looping symlinks |
| reachability | fake Debian rootfs + `/proc/<pid>/maps` text → loaded / dormant |
| vuln.mlab.sh client | an in-process HTTP mock: 429 + `Retry-After`, bearer auth, `ok:false`, malformed records, 413 |
| matching | a mock `VulnSource`: dedup, enrichment, KEV catalogue, cache, API down |
| events, rendering | schema and triage order |

## Test lab

All the outputs in this wiki come from this lab: a single-node k3s in Docker
(k3sec reads containers through the host's `/proc`, which works because the k3s
"node" shares the host kernel). Needs Docker only.

**1. k3s**

```bash
docker run -d --name k3sec-m4-k3s --hostname k3sec-m4-node --privileged \
  --tmpfs /run --tmpfs /var/run -p 127.0.0.1:16443:6443 -e K3S_KUBECONFIG_MODE=644 \
  rancher/k3s:v1.33.5-k3s1 server --disable traefik --disable metrics-server --tls-san 127.0.0.1

docker exec k3sec-m4-k3s cat /etc/rancher/k3s/k3s.yaml \
  | sed 's#127.0.0.1:6443#127.0.0.1:16443#' > lab.kubeconfig
docker exec k3sec-m4-k3s kubectl get nodes
```

```text
NAME            STATUS   ROLES                  AGE   VERSION
k3sec-m4-node   Ready    control-plane,master   31s   v1.33.5+k3s1
```

**2. Workloads**: Debian (nginx × 2, redis), Alpine with an npm lockfile,
Rocky 9:

```yaml
apiVersion: v1
kind: Namespace
metadata: {name: demo}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: npm-lock, namespace: demo}
data:
  package-lock.json: |
    {"name":"web","lockfileVersion":3,"packages":{"":{"name":"web"},
     "node_modules/lodash":{"version":"4.17.20"},
     "node_modules/express":{"version":"4.17.1"}}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: nginx, namespace: demo}
spec:
  replicas: 2
  selector: {matchLabels: {app: nginx}}
  template:
    metadata: {labels: {app: nginx}}
    spec:
      containers: [{name: nginx, image: "nginx:1.25.3"}]
---
apiVersion: v1
kind: Pod
metadata: {name: redis, namespace: demo}
spec:
  containers: [{name: redis, image: "redis:7.0.15"}]
---
apiVersion: v1
kind: Pod
metadata: {name: alpine-app, namespace: demo}
spec:
  containers:
  - name: app
    image: "alpine:3.19"
    # copy, don't mount: ConfigMap files are symlinks, which the walk doesn't follow
    command: ["sh", "-c", "mkdir -p /app && cp /cfg/package-lock.json /app/ && exec sleep infinity"]
    volumeMounts: [{name: cfg, mountPath: /cfg}]
  volumes: [{name: cfg, configMap: {name: npm-lock}}]
---
apiVersion: v1
kind: Pod
metadata: {name: rocky, namespace: demo}
spec:
  containers: [{name: rocky, image: "rockylinux:9-minimal", command: ["sleep", "infinity"]}]
```

```bash
docker cp workloads.yaml k3sec-m4-k3s:/tmp/w.yaml
docker exec k3sec-m4-k3s kubectl apply -f /tmp/w.yaml
# later, for watch / watch --vulns:
docker exec k3sec-m4-k3s kubectl -n demo run httpd --image=httpd:2.4.58
docker exec k3sec-m4-k3s kubectl -n demo run redis2 --image=redis:7.0.15
docker exec k3sec-m4-k3s kubectl -n demo rollout restart deploy/nginx
```

**3. k3sec as root, without sudo**: a privileged container in the host PID
namespace that chroots into the host, like a `hostPID` DaemonSet would:

```bash
#!/bin/sh
# asroot.sh: run k3sec as root in the host PID namespace.
exec docker run --rm --privileged --pid=host --network host -v /:/host \
  -e XDG_CACHE_HOME=$PWD/cache -e NO_COLOR=1 -e RUST_LOG=${RUST_LOG:-info} -e MLAB_API_KEY \
  alpine:3.19 chroot /host $PWD/k3sec --kubeconfig $PWD/lab.kubeconfig "$@"
```

```bash
cargo build --release --features rpm && cp target/release/k3sec .
./k3sec --kubeconfig lab.kubeconfig watch -n demo --logs   # non-root modes run directly
./asroot.sh inventory --sbom ./sboms
./asroot.sh vulns --only-loaded
timeout -s INT 60 ./asroot.sh watch --vulns -n demo          # SIGINT = Ctrl+C: clean shutdown
```

**4. Teardown**

```bash
docker rm -f k3sec-m4-k3s
```

### What the lab caught

Bugs that unit tests didn't, found on this lab and fixed:

- `/proc/<pid>/cgroup` ends with a newline: the last 64-hex segment was 65
  chars and the lookup fell back to the **outer** (k3s node) container id. Zero
  containers found.
- SQLite canonicalizes its path and followed the `/proc/<pid>/root` magic link
  to the host's rpmdb.
- A dormant `linux-libc-dev` triggered 9145 one-by-one CVE lookups: led to the
  bulk KEV catalogue and the enrichment budget.
- `watch --vulns -n demo` inventoried `kube-system` too.

## Wiki

This wiki lives in `wiki/` and is mirrored to the GitHub wiki by
`.github/workflows/wiki-sync.yml` on every push to `main` that touches it.
Edit the markdown in the repo, never in the wiki UI (overwritten on the next
sync). Page links are wiki-style (`[Vulns](Vulns)`, no `.md`); `_Sidebar.md`
is the navigation. The GitHub wiki must have been initialized once (create any
page in the UI) before the first sync.
