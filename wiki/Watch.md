# `k3sec watch`

The live stream. Every source (k8s events, pod logs, the eBPF probe, YARA
detections, vulnerability findings) is normalized into one
[`SecEvent`](SecEvent-Schema) and printed by a single printer, so lines from
concurrent sources never interleave.

```bash
k3sec watch                              # k8s events, all namespaces
k3sec watch -n demo --logs               # one namespace, + pod logs
k3sec watch --rollback                   # replay the existing backlog first
k3sec watch -o json | jq 'select(.severity=="warning")'
sudo k3sec watch --ebpf --rules ./rules  # + kernel events + YARA (see eBPF probe)
sudo k3sec watch --vulns                 # + vulnerability events (see Watch --vulns)
```

## Realtime by default

k3sec is a detection tool, not a history viewer: it shows what happens **after**
you start watching. The backlog the API replays on connect is dropped.
`--rollback` replays it once, sorted by time, then goes live (and, with
`--vulns`, also inventories the pods that already exist).

## Real output: a rollout, with `--logs`

`k3sec watch -n demo --logs`, then `kubectl -n demo rollout restart deploy/nginx`
in another terminal:

```text
14:43:06  NORMAL  demo/deployment/nginx  Scaled up replica set nginx-57fcccff77 from 0 to 1
14:43:06  NORMAL  demo/replicaset/nginx-57fcccff77  Created pod: nginx-57fcccff77-l8lzs
14:43:06  NORMAL  demo/pod/nginx-57fcccff77-l8lzs  Successfully assigned demo/nginx-57fcccff77-l8lzs to k3sec-m4-node
14:43:06  NORMAL  demo/pod/nginx-57fcccff77-l8lzs  Container image "nginx:1.25.3" already present on machine
14:43:06  NORMAL  demo/pod/nginx-57fcccff77-l8lzs  Created container: nginx
14:43:06  NORMAL  demo/pod/nginx-57fcccff77-l8lzs  Started container nginx
14:43:07  NORMAL  demo/deployment/nginx  Scaled down replica set nginx-75b7c5fd7b from 2 to 1
14:43:07  NORMAL  demo/replicaset/nginx-75b7c5fd7b  Deleted pod: nginx-75b7c5fd7b-dhmqv
14:43:07  NORMAL  demo/pod/nginx-75b7c5fd7b-dhmqv  Stopping container nginx
14:43:07  INFO    demo/nginx-75b7c5fd7b-dhmqv/nginx  2026/10/29 14:43:07 [notice] 1#1: signal 3 (SIGQUIT) received, shutting down
14:43:07  INFO    demo/nginx-75b7c5fd7b-dhmqv/nginx  2026/10/29 14:43:07 [notice] 31#31: gracefully shutting down
```

Each line is `time  SEVERITY  location  message`. The location is
`namespace/kind/name` for k8s events and `namespace/pod/container` for log lines.
On a TTY the severity is colored (gray normal, yellow warning, red error and
critical); `NO_COLOR` turns colors off.

stderr carries only diagnostics:

```text
2026-10-29T14:43:01.289751Z  INFO connected to cluster, starting watch namespace="demo" logs=true ebpf=false rules=false vulns=false rollback=false output=Pretty sources=2
2026-10-29T14:43:26.285604Z  INFO received Ctrl+C, shutting down gracefully
```

## JSON (NDJSON)

`-o json` prints one `SecEvent` per line. A k8s event from
`k3sec watch -n demo --rollback -o json` (payload trimmed):

```json
{"source":"k8s-event","timestamp":"2026-10-29T13:46:09Z","kind":"Pulling","severity":"normal","namespace":"demo","object":"pod/httpd","message":"Pulling image \"httpd:2.4.58\"","metadata":{"component":"kubelet","count":"1","host":"k3sec-m4-node","reason":"Pulling","type":"Normal"},"payload":{"apiVersion":"v1","kind":"Event","reason":"Pulling","type":"Normal", "...": "the raw Event object"}}
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-n, --namespace <NS>` | Restrict to one namespace | all namespaces |
| `--logs` | Follow pod container logs | off |
| `--ebpf` | Enable the [eBPF probe](eBPF-Probe) | off |
| `--kind <exec,connect,file_write>` | Restrict eBPF events to these kinds | all |
| `--node <NAME>` | Node name scoping pod resolution (`--ebpf`, `--vulns`) | `$NODE_NAME`, else all pods |
| `--rules <PATH>` | [YARA](YARA-Detection) rules file/dir (needs `--ebpf`) | off |
| `--max-scan-size <BYTES>` | Skip artifacts larger than this | 32 MiB |
| `--scan-workers <N>` | YARA worker threads | CPU count |
| `--vulns` | [Vulnerability events](Watch-Vulns) for new pod images (needs root) | off |
| `--mlab-url`, `--no-cache`, `--cache-ttl` | [Matching](Vuln-Matching) options for `--vulns` | see Vulns |
| `--rollback` | Replay backlog first (and inventory existing pods with `--vulns`) | off |
| `-o, --output <pretty\|json>` | Output format | `pretty` |
| `--kubeconfig <PATH>` | Kubeconfig file | `$KUBECONFIG` / `~/.kube/config` |

## Robustness

- Watch API only, no polling; dropped watches reconnect with exponential
  backoff (1 s to 30 s).
- Ctrl+C shuts every source down and drains the printer (5 s cap).
- `k3sec watch | head` exits cleanly: a broken pipe is not an error.
- Flags that do nothing say so instead of being silently ignored:

```text
$ k3sec watch --rules ./x
2026-10-29T14:42:58.276860Z  WARN --rules has no effect without --ebpf; scanning is driven by eBPF events
```
