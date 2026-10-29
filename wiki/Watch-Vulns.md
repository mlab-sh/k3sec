# `watch --vulns`

Vulnerability findings as events in the [live stream](Watch). Each new pod
image is inventoried and matched in the background, then reported as
`source: "vuln"` [SecEvents](SecEvent-Schema):

- one **`vuln_summary`** event per image,
- one **`vulnerability`** event per **loaded** vuln (dormant ones stay in the
  summary count; use [`vulns`](Vulns) to list them).

```bash
sudo k3sec watch --vulns                  # new pods only (realtime)
sudo k3sec watch --vulns --rollback       # + the pods already running
sudo k3sec watch --vulns --ebpf           # + exec events promote dormant packages
sudo k3sec watch --vulns -o json | jq 'select(.source=="vuln")'
```

## Real output

`sudo k3sec watch --vulns -n demo`, then `kubectl -n demo run python
--image=python:3.12-slim -- sleep infinity`:

```text
14:44:48  NORMAL  demo/pod/python  Successfully assigned demo/python to k3sec-m4-node
14:44:48  NORMAL  demo/pod/python  Pulling image "python:3.12-slim"
14:44:53  NORMAL  demo/pod/python  Successfully pulled image "python:3.12-slim" in 4.576s (4.576s including waiting). Image size: 43284989 bytes.
14:44:53  NORMAL  demo/pod/python  Created container: python
14:44:53  NORMAL  demo/pod/python  Started container python
14:44:58  CRIT    demo/python/python  docker.io/library/python:3.12-slim: 164 vulns, 46 loaded (0 KEV loaded), 87 packages
14:44:58  CRIT    demo/python/python  CVE-2019-1010022 in libc-bin 2.41-12+deb13u4 (loaded, CVSS 9.8)
14:44:58  CRIT    demo/python/python  CVE-2019-1010022 in libc6 2.41-12+deb13u4 (loaded, CVSS 9.8)
14:44:58  ERROR   demo/python/python  CVE-2026-19499 in libc-bin 2.41-12+deb13u4 (loaded, CVSS 7.7)
14:44:58  ERROR   demo/python/python  CVE-2026-19499 in libc6 2.41-12+deb13u4 (loaded, CVSS 7.7)
```

Five seconds from `Started container` to the findings: a 3 s settle delay (so
the process has mapped its libraries), the inventory, one API call for the new
digest (69 CVEs to enrich, stderr: `INFO enriching CVEs (CVSS, KEV) cves=69`).

With the nginx image, the loaded KEV is its own critical event:

```text
13:54:56  CRIT    demo/nginx-75b7c5fd7b-dhmqv/nginx  docker.io/library/nginx:1.25.3: 829 vulns, 104 loaded (1 KEV loaded), 149 packages
13:54:56  CRIT    demo/nginx-75b7c5fd7b-dhmqv/nginx  CVE-2023-44487 in nginx 1.25.3-1~bookworm (loaded, KEV, CVSS 7.5)
```

A Go image with nothing loaded from OS packages (`caddy:2.7.6`, `-o json`):

```json
{"source":"vuln","kind":"vuln_summary","severity":"info","namespace":"demo","object":"caddy/caddy","message":"docker.io/library/caddy:2.7.6: 210 vulns, 0 loaded (0 KEV loaded), 147 packages", "...": "..."}
```

The 210 are in the Alpine base (dormant) and in Go modules of the static
`caddy` binary, which are [`unknown`](Reachability): no loaded finding, so no
`vulnerability` event, and the summary is `info`.

## Severity

| Finding | Event severity |
|---------|----------------|
| loaded **and** KEV | `critical` |
| CVSS ≥ 9.0 | `critical` |
| CVSS ≥ 7.0 | `error` |
| CVSS ≥ 4.0 | `warning` |
| CVSS > 0 | `normal` |
| unscored | `info` |

The summary takes the highest severity of its loaded findings (`info` if none).

## Behavior

- **Realtime**: images of pods running when the watch starts are not
  inventoried, unless `--rollback`.
- **Once per digest**: a second pod of an image already seen just joins it (no
  new inventory, no new events). Across runs, the [cache](Vuln-Matching#cache)
  avoids the API too.
- **Off the hot path**: inventories run as background tasks, at most 2 at a
  time; the pod watch and the other sources never wait on them. The pod watch
  drops (never blocks) when the queue (256) is full.
- **Namespace**: `-n` restricts which pods are inventoried.
- **Retries**: a container that has no process yet is retried 3 times, 2 s apart.

## With `--ebpf`: dormant → loaded

The probe's exec events feed the watcher. When a container executes a binary
owned by a package that was **dormant** at inventory time, the package flips to
loaded and its vulns are emitted **then**, as `vulnerability` events. That is
the moment worth an alert: vulnerable code that just started running (a shell
spawned in a container, a debug tool, a cron job).

The exec'd path is resolved like the rest of [reachability](Reachability):
through `/proc/<pid>/exe`, else the `execve` path resolved inside the container
root (`/bin/sh` → `/usr/bin/dash` → `dash`).

> This path is covered by unit tests on a fake rootfs; it was not exercised on
> the lab, which had no `bpf-linker` to build the probe.

## Event fields

See [SecEvent schema](SecEvent-Schema#vuln). In short, a `vulnerability` event
carries `cve`, `package`, `version`, `purl`, `vuln_severity`, `cvss`, `kev`
(`true` / `false` / `unknown`), `fixed`, `reachability`, `image`, `digest`,
`pod`, `container` in `metadata`, and the full finding in `payload`.
