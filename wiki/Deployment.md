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

## As a DaemonSet, with mlab-agent

[`deploy/kubernetes/k3sec.yaml`](https://github.com/mlab-sh/k3sec/blob/main/deploy/kubernetes/k3sec.yaml)
runs one pod per node from `ghcr.io/mlab-sh/k3sec` (k3sec, mlab-agent, the
rules). The agent enrols the node in an mlab workspace, holds its keys and the
only outbound connection, and starts `k3sec serve` as its tool
([Tool API](Tool-API)). Everything k3sec sees lands in the workspace's
**Cluster** tab.

```bash
kubectl create namespace k3sec
kubectl -n k3sec create secret generic k3sec-enroll --from-literal=code=<cluster enrolment code>
kubectl apply -f k3sec.yaml
```

A **cluster enrolment code** (workspace → Agents → Enrol an agent → A Kubernetes cluster)
enrols up to the number of nodes it was made for, for 24 hours. Each node
enrols once: its keys stay on the node (`hostPath` `/var/lib/mlab-agent`, mode
0700), never in a Secret, and a restarted pod reuses them. The Secret can be
deleted once every node shows up.

What the pod runs as:

| | |
|---|---|
| RBAC | read-only: events list/watch, pods get/list/watch, pods/log get, nodes get/list, the `kube-system` namespace (its UID is the cluster id) |
| Host | `hostPID` (container processes, their `/proc/<pid>/root` and maps) and tracefs, read-only |
| Capabilities | `drop: ALL`, then `BPF`, `PERFMON`, `SYS_RESOURCE`, `SYS_PTRACE`, `DAC_READ_SEARCH`; no privileged mode, `readOnlyRootFilesystem` |
| Network | the agent to mlab's relay (WebSocket) and upload host; k3sec to the API server only |

**The ConfigMap is the node's policy, and the ceiling.** mlab chooses the
k3sec config from the workspace (sources, namespaces, severity, rule set) and
pushes it live, without a restart; it can never go beyond
`[tools.k3sec.settings]`:

```toml
[tools.k3sec.settings]
allow_k8s_events = true
allow_logs = false        # pod logs stay on the cluster, whatever mlab asks
allow_ebpf = true
allow_rules = true
allow_vulns = true
namespaces = []           # empty: all; otherwise mlab can only narrow this list
rulesets = ["/usr/share/k3sec/rules"]
allow_remote_rules = false
```

`allowed_ops` is the closed list of what mlab may call, and k3sec is pinned to
the SHA-256 of the binary in the image (the entrypoint fills it in). Set
`upload_hosts` to the upload host mlab's policy editor shows: inventories and
SBOMs go there, nowhere else.

Logs: `kubectl -n k3sec logs ds/k3sec` (the agent's, and k3sec's stderr).

### Without mlab

The same binary runs standalone: a privileged pod (`hostPID`,
`privileged: true`) with `args: ["watch", "--vulns", "-o", "json"]`, the RBAC
above, and NDJSON on stdout for your log collector. `--ebpf --rules
/usr/share/k3sec/rules` adds the kernel events and YARA detections.

## Network

`vulns` and `watch --vulns` call `https://vuln.mlab.sh` (or `--mlab-url`).
Air-gapped: point `--mlab-url` at an on-prem mlab; the inventory, `--sbom` and
everything else work without network beyond the API server.
