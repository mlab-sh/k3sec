# Troubleshooting

Every error is one readable line on stderr (and logged), exit code 1; k3sec
never panics on bad input. Messages below are real captures from the lab,
except the "distro not matched" one (format shown, no such image on the lab).

## `inventory needs root`

```text
error: inventory needs root to read containers' filesystems (/proc/<pid>/root): re-run with sudo, or as a privileged DaemonSet with hostPID
```

`inventory`, `vulns` and `watch --vulns` read other processes' roots. Run with
`sudo`, or see [Deployment](Deployment). Checked before contacting the cluster.

## Kubeconfig / cluster

```text
$ k3sec --kubeconfig /nope watch
error: failed to read kubeconfig at /nope: failed to read kubeconfig from '"/nope"': No such file or directory (os error 2): No such file or directory (os error 2)
```

API server down, wrong address or missing RBAC, reported before any watch
starts:

```text
error: cannot reach the Kubernetes API server (check your kubeconfig, network, and RBAC): ServiceError: client error (Connect): client error (Connect): tcp connect error: Connection refused (os error 111)
```

Without `--kubeconfig`: `$KUBECONFIG`, then `~/.kube/config`, then in-cluster.
On a k3s server node the kubeconfig is `/etc/rancher/k3s/k3s.yaml`.

## `eBPF probe unavailable`

```text
ERROR source failed: eBPF probe unavailable: this binary was built without eBPF support. Build on Linux with `--features ebpf`, and run as root (or with CAP_BPF+CAP_PERFMON). source="ebpf"
```

Rebuild with `--features ebpf` ([eBPF probe](eBPF-Probe#build)). The other
sources keep running.

## `invalid --mlab-url`

```text
$ k3sec vulns --mlab-url ftp://x
error: invalid --mlab-url `ftp://x`: expected http(s)://host
```

## `vulnerability matching unavailable`

```text
WARN vulnerability matching unavailable; inventory only error=cannot reach http://127.0.0.1:9 after 4 attempts: error sending request for url (http://127.0.0.1:9/api/v2/scan)
```

The API couldn't be reached after retries. The inventory is still printed,
with the error per image. Check network / proxy, or `--mlab-url`.

## Slow first run, `cooldown` lines

```text
INFO vuln.mlab.sh cooldown, retrying in 2s
```

The anonymous tier allows one scan every 10 s; k3sec waits it out. Set
`MLAB_API_KEY`. Later runs within `--cache-ttl` come from the
[cache](Vuln-Matching#cache) (0.75 s on the lab instead of ~10 s).

## `0 containers` / `skipped=N`

```text
INFO inventoried running containers (skipped = no process on this host) images=7 containers=9 skipped=0
```

`skipped` counts pods whose containers have no process on this host: pods of
other nodes (run k3sec per node, set `--node`), or containers that just exited.
`no running containers with processes on this node` with everything skipped on
a single node means `/proc` isn't the host's: run in the host PID namespace
(`hostPID: true`, `docker run --pid=host`).

## Distro not matched

```text
  ! distro `arch-1` is not covered by vulnerability matching: OS packages listed, not matched
```

See [Package sources](Package-Sources#distro-detection) for what is covered.

## Many `unknown` severities

Debian advisories usually carry no severity; k3sec takes it from the CVE's CVSS,
but enriches at most 800 CVEs per run, loaded first. Huge counts usually come
from `linux-libc-dev`: use `--only-loaded`. See
[Vulnerability matching](Vuln-Matching#enrichment-budget).

## Debug logs

```bash
RUST_LOG=k3sec=debug sudo -E k3sec vulns 2> debug.log
```

Shows, among others, how many containers were found in `/proc`
(`scanned /proc containers_with_pids=…`), skipped malformed OSV records and
per-CVE enrichment failures. The API key is never logged.
