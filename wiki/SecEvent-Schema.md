# SecEvent schema

Every source emits the same envelope. With `-o json` the [live stream](Watch)
prints one per line (NDJSON). Treat the field names as a contract (beta: they
may still change between milestones).

```text
source     where it came from        k8s-event | k8s-log | ebpf | yara | vuln
timestamp  when it happened          RFC 3339, UTC
kind       type discriminator        event reason | log | exec | connect | file_write | detection | vulnerability | vuln_summary
severity   normalized severity       info | normal | warning | error | critical
namespace  k8s namespace             omitted when none
object     the subject               pod/foo, deployment/bar, <pod>/<container>
message    human-readable text
metadata   flat string key/values    omitted when empty; keys sorted
payload    raw source object         omitted when null
```

`severity` is ordered: `info < normal < warning < error < critical`.

## k8s-event

`kind` is the Event `reason`; severity `normal` / `warning` from the Event
`type`. Real event (payload trimmed):

```json
{"source":"k8s-event","timestamp":"2026-10-29T13:46:09Z","kind":"Pulling","severity":"normal","namespace":"demo","object":"pod/httpd","message":"Pulling image \"httpd:2.4.58\"","metadata":{"component":"kubelet","count":"1","host":"k3sec-m4-node","reason":"Pulling","type":"Normal"},"payload":{"apiVersion":"v1","kind":"Event","reason":"Pulling","type":"Normal"}}
```

`metadata`: `type`, `reason`, `component`, `count`, `host`. `payload`: the raw
`Event`.

## k8s-log

`kind: "log"`, `object: "<pod>/<container>"`, `metadata`: `pod`, `container`.
One event per log line (`--logs`).

## ebpf

`kind`: `exec` (info), `connect` (info), `file_write` (warning).
`object: "<pod>/<container>"` when the cgroup resolved to a pod.

| metadata | |
|---|---|
| `pid`, `uid`, `comm` | the process |
| `container_id` | short (12 hex) runtime id |
| `pod`, `container` | when resolved |

`payload`: `pid`, `uid`, `cgroup_id`, `comm`, full `container_id`, `path`
(exec / file_write) or `dest` (`ip:port`, connect), and `namespace` / `pod` /
`container`. See [eBPF probe](eBPF-Probe).

## yara

`kind: "detection"`, always `critical`. `metadata`: `rules`, `rule_namespace`,
`tags`, `artifact`, `trigger` (`exec` / `file_write`), `pid`, `comm`, `pod`,
`container`. `payload.matches`: `[{rule, namespace, tags}]`. See
[YARA detection](YARA-Detection).

## vuln

From [`watch --vulns`](Watch-Vulns).

**`kind: "vulnerability"`**, one per loaded finding:

```jsonc
{
  "source": "vuln",
  "kind": "vulnerability",
  "severity": "critical",             // CVSS band; a loaded KEV is always critical
  "namespace": "demo",
  "object": "nginx-75b7c5fd7b-dhmqv/nginx",
  "message": "CVE-2023-44487 in nginx 1.25.3-1~bookworm (loaded, KEV, CVSS 7.5)",
  "metadata": {
    "container": "nginx", "pod": "nginx-75b7c5fd7b-dhmqv",
    "cve": "CVE-2023-44487", "package": "nginx", "version": "1.25.3-1~bookworm",
    "purl": "pkg:deb/debian/nginx@1.25.3-1~bookworm?arch=amd64&distro=debian-12",
    "vuln_severity": "high", "cvss": "7.5", "kev": "true", "reachability": "loaded",
    "image": "docker.io/library/nginx:1.25.3",
    "digest": "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2"
  },
  "payload": { /* the finding: id, advisories, package, version, purl, severity, cvss, kev, fixed, summary, reachability */ }
}
```

`kev` is `true`, `false` or `unknown`; `fixed` and `cvss` are omitted when not
known.

**`kind: "vuln_summary"`**, one per image. Real event (`watch --vulns -o json`,
pod `redis2`, payload trimmed):

```json
{
  "source": "vuln",
  "timestamp": "2026-10-29T13:46:13.567191971Z",
  "kind": "vuln_summary",
  "severity": "critical",
  "namespace": "demo",
  "object": "redis2/redis2",
  "message": "docker.io/library/redis:7.0.15: 489 vulns, 73 loaded (0 KEV loaded), 92 packages",
  "metadata": {
    "container": "redis2",
    "digest": "sha256:352c1fdadc91926edda08f45aeb3f27f37194c2f14101229c0523a11195c96e3",
    "image": "docker.io/library/redis:7.0.15",
    "kev_loaded": "0",
    "loaded": "73",
    "packages": "92",
    "pod": "redis2",
    "unscanned": "0",
    "vulns": "489"
  },
  "payload": {
    "image": "docker.io/library/redis:7.0.15",
    "digest": "sha256:352c1fdadc91926edda08f45aeb3f27f37194c2f14101229c0523a11195c96e3",
    "containers": [{ "namespace": "demo", "pod": "redis2", "container": "redis2", "container_id": "98bc1979…" }],
    "loaded": 2, "dormant": 87, "unknown": 3
  }
}
```

In `metadata`, `vulns` / `loaded` / `kev_loaded` count **findings**; in
`payload`, `loaded` / `dormant` / `unknown` count **packages**. `error` is set
when matching failed (the summary then says "vulnerability matching
unavailable").

## Filtering recipes

```bash
k3sec watch -o json | jq -c 'select(.severity=="critical")'
sudo k3sec watch --vulns -o json | jq -c 'select(.kind=="vulnerability" and .metadata.kev=="true")'
sudo k3sec watch --ebpf -o json | jq -r 'select(.kind=="connect") | "\(.object) \(.payload.dest)"'
```
