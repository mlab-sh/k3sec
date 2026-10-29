# Deployment

## What each mode needs

| Mode | Privileges | Where |
|------|------------|-------|
| `watch`, `watch --logs` | a kubeconfig with the RBAC below | anywhere |
| `watch --ebpf`, `--rules` | root, or `CAP_BPF` + `CAP_PERFMON` | on each node |
| `inventory`, `vulns`, `watch --vulns` | root (reads `/proc/<pid>/root` of containers), host PID namespace | on each node |

The node-local modes only see the containers with a process on the host they
run on. Run one k3sec per node (DaemonSet), with `--node` or `$NODE_NAME` set
so it lists only its node's pods.

Without root, `inventory` / `vulns` stop before touching the cluster (real
output):

```text
$ k3sec inventory
2026-10-29T14:42:54.266458Z ERROR inventory needs root to read containers' filesystems (/proc/<pid>/root): re-run with sudo, or as a privileged DaemonSet with hostPID
error: inventory needs root to read containers' filesystems (/proc/<pid>/root): re-run with sudo, or as a privileged DaemonSet with hostPID
```

## RBAC

Read-only, cluster-wide:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k3sec
rules:
  - apiGroups: [""]
    resources: ["events"]                 # watch
    verbs: ["list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]                   # watch --logs/--ebpf/--vulns, inventory, vulns
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]               # watch --logs
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["nodes"]                  # vulns: k3s / containerd / kernel versions
    verbs: ["get", "list"]
```

Without `nodes`, `vulns` warns and skips the [node stack](Node-Stack); the
rest works.

## On the node, directly

```bash
sudo NODE_NAME=$(hostname) k3sec vulns --kubeconfig /etc/rancher/k3s/k3s.yaml
```

`/etc/rancher/k3s/k3s.yaml` is the admin kubeconfig k3s writes on server nodes.
Under `sudo`, the cache lands in root's `~/.cache/k3sec`; set
`XDG_CACHE_HOME` to choose.

## In a privileged container (what the lab runs)

The lab runs k3sec as root in the host PID namespace, from a container that
chroots into the host. This is the setup every root output in this wiki comes
from:

```bash
docker run --rm --privileged --pid=host --network host -v /:/host \
  -e XDG_CACHE_HOME=/var/cache -e MLAB_API_KEY \
  alpine:3.19 chroot /host /path/to/k3sec --kubeconfig /path/to/kubeconfig vulns
```

## As a DaemonSet

A template. **Not yet run end to end**: the lab tested the equivalent container
above, not this manifest. It needs an image containing the k3sec binary.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: k3sec
  namespace: k3sec
spec:
  selector: { matchLabels: { app: k3sec } }
  template:
    metadata: { labels: { app: k3sec } }
    spec:
      serviceAccountName: k3sec          # bound to the ClusterRole above
      hostPID: true                      # /proc of the host: container PIDs and roots
      containers:
        - name: k3sec
          image: <your-registry>/k3sec:0.2.0
          args: ["watch", "--vulns", "-o", "json"]   # add --ebpf --rules /rules with an ebpf build
          env:
            - name: NODE_NAME
              valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
            - name: XDG_CACHE_HOME
              value: /cache
            - name: MLAB_API_KEY
              valueFrom: { secretKeyRef: { name: k3sec, key: mlab-api-key, optional: true } }
          securityContext:
            privileged: true             # /proc/<pid>/root of other containers, eBPF
          volumeMounts:
            - { name: cache, mountPath: /cache }
      volumes:
        - name: cache
          emptyDir: {}
```

Output goes to stdout as NDJSON: ship it with your log collector.

## Network

`vulns` and `watch --vulns` call `https://vuln.mlab.sh` (or `--mlab-url`).
Air-gapped: point `--mlab-url` at an on-prem mlab; the inventory, `--sbom` and
everything else work without network beyond the API server.
