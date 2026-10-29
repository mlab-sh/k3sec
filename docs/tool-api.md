# k3sec tool API, v1

What mlab can ask `k3sec serve` through the workspace agent, and what the
tool sends on its own: `tool = "k3sec"` (mlab-agent `docs/protocol.md` §6).
Arguments, answers and event bodies are CBOR, typed in the `k3sec-api` crate
(`crates/k3sec-api`), which depends on nothing else of k3sec so the mlab
backend can import it alone. Every struct refuses unknown fields.

k3sec never talks to mlab, nor to vuln.mlab.sh, in this mode: the agent holds
the workspace identity and the only outbound connection. k3sec reads the node
(`/proc`, eBPF, the k8s API) and answers the agent on stdin/stdout.

## Versioning

`API_VERSION = 1`. Every [`Batch`], [`Status`] and [`Inventory`] carries
`api_version`; mlab accepts the versions it knows (`check_version`) and
refuses the others. A new field, op or event kind is a new version. The v1
encoding is frozen by golden files (`crates/k3sec-api/tests/golden/*.hex`):
a test fails if it changes.

## Ops

| `op` | Arguments | Answer |
|---|---|---|
| `status` | none | `Status` |
| `configure` | `Config` | `Configured {config, clamped}` |
| `events_since` | `EventsSince {boot_id, after_seq}` | `Backlog {boot_id, batches, oldest_seq, last_seq}` |
| `inventory` | `InventoryRequest {digest?}` + upload target | blob: the CBOR `Inventory`; body `InventoryInfo {images, packages}` |
| `sbom` | `ImageRef {digest}` + upload target | blob: CycloneDX 1.5 JSON; body `SbomInfo {digest, components}` |

The agent's local policy may restrict them (`[tools.k3sec] allowed_ops`).

## Events (tool → mlab)

| `name` | Body | When |
|---|---|---|
| `batch` | `Batch` | runtime events, in order |
| `status` | `Status` | every minute, and when the config or a source changes |
| `inventory_ready` | `InventoryReady {digest, image, packages, loaded}` | an image was (re)inventoried; fetch it with `inventory` / `sbom` |

Agent events are best effort (mlab-agent `docs/protocol.md` §6.4). The
event stream is made reliable on top of that:

- Batches are numbered: `seq` grows by 1 per batch within a `boot_id` (one
  `k3sec serve` process, random id). mlab keeps the last `(boot_id, seq)` per
  instance; a gap means lost batches, fetched with `events_since`.
- The tool keeps the last batches (`settings.backlog_events` events, 50 000 by
  default) for that. `Backlog.oldest_seq` says how far back it still goes:
  older batches are lost, and mlab records the gap.
- A new `boot_id` starts again at `seq` 1. What the previous process hadn't
  delivered is lost (not persisted to disk in v1).
- A batch is at most `MAX_BATCH_BYTES` (768 KiB) and `MAX_BATCH_EVENTS`
  (2 000) events, so it fits the agent's 1 MiB envelope. `events_since`
  answers one batch at a time (`MAX_BATCHES_PER_ANSWER`).
- Capture never blocks on delivery. A full buffer drops events and counts
  them: `Batch.dropped` (since the previous batch) and `Status.counters.dropped`.
- **Critical first**: a batch holding a `critical` event (YARA detection,
  loaded KEV vulnerability) is flushed at once, `urgent: true`; others wait
  for the batch interval or size.

## `SecEvent` v1

The same fields as k3sec's NDJSON output, `timestamp` in Unix milliseconds:

| Field | Type | |
|---|---|---|
| `source` | `k8s-event` \| `k8s-log` \| `ebpf` \| `yara` \| `vuln` | |
| `timestamp` | int | Unix ms, UTC |
| `kind` | text | `exec`, `connect`, `file_write`, `detection`, `vulnerability`, `vuln_summary`, `log`, or a k8s event reason |
| `severity` | `info` \| `normal` \| `warning` \| `error` \| `critical` | ordered |
| `namespace` | text? | |
| `object` | text? | `pod/<name>`, `<pod>/<container>`, ... |
| `message` | text | for humans |
| `metadata` | map text → text | flat fields, per source below |
| `payload` | any | raw source detail, `null` when none |

`metadata` keys per source (v1):

| Source / kind | Keys |
|---|---|
| `k8s-event` | `type`, `reason`, `component`, `count`, `host` |
| `k8s-log` | `pod`, `container` |
| `ebpf` (all) | `pid`, `uid`, `comm`, `container_id` (12 hex), `pod`, `container` |
| `ebpf` `exec` | + `sha256` of the executed binary, when it could be read (for hash reputation on the mlab side) |
| `yara` `detection` | `rules`, `rule_namespace`, `tags`, `artifact`, `trigger`, `pid`, `comm`, `pod`, `container` |
| `vuln` `vulnerability` | `cve`, `package`, `version`, `purl`, `vuln_severity`, `cvss`, `kev`, `fixed`, `reachability`, `image`, `digest`, `pod`, `container` |
| `vuln` `vuln_summary` | `vulns`, `loaded`, `kev_loaded`, `packages`, `unscanned`, `error`, `image`, `digest`, `pod`, `container` |

`ebpf` `connect` payloads carry `dest` (`ip:port`), for IP enrichment on the
mlab side. In agent mode `vuln` events are not produced by the tool: matching
happens in mlab from the inventory (below).

## Config and the local policy

mlab chooses a `Config` with `configure`; the host admin bounds it with the
tool's table in the agent's local policy, which nothing remote can change:

```toml
[tools.k3sec]
path = "/usr/bin/k3sec"
sha256 = "<mlab-agent tools hash /usr/bin/k3sec>"
enabled = true

[tools.k3sec.settings]          # k3sec_api::Settings; every key optional, all flat
allow_k8s_events = true         # sources mlab may turn on
allow_logs = false
allow_ebpf = true
allow_rules = true
allow_vulns = true
namespaces = []                 # namespaces mlab may watch; empty = all
rulesets = ["/usr/share/k3sec/rules"]   # offered to mlab by name: "rules"
allow_remote_rules = false      # accept YARA source sent by mlab
node = "node-1"                 # else $NODE_NAME
kubeconfig = "/etc/rancher/k3s/k3s.yaml"   # else in-cluster
backlog_events = 50000
```

`Config`:

| Field | |
|---|---|
| `sources {k8s_events, logs, ebpf, rules, vulns}` | each also needs `allow_<source>`; `rules` needs `ebpf` |
| `kinds` | eBPF kinds; empty = all |
| `namespaces` | empty = every allowed namespace; outside `settings.namespaces` is cut |
| `min_severity` | events below are not sent |
| `ruleset` | a name from `settings.rulesets` (its last path component, `.yar` dropped) |
| `rules_source` | YARA source (≤ 1 MiB), only with `allow_remote_rules`; replaces `ruleset` |

`configure` applies the intersection and answers what is in force plus, in
`clamped`, what the policy cut, in words. The applied config is kept in the
tool's work directory and reloaded at start. Changing it restarts the
affected sources inside the process, not the process. Until mlab configures
it, the tool runs `Config::default()` clamped to the policy.

YARA rules are data, not code: yara-x has no `include` of host files and no
process execution. They are compiled before use; invalid rules are refused
by `configure` with the compiler's message, and the previous rules stay.

## Inventory

In this mode the whole node is inventoried (the pods running when the tool
starts included, within the configured namespaces), in the background, two
images at a time; each image sends `inventory_ready` when done. `inventory`
answers what is done so far, plus the node stack (`node/<name>`: k3s,
containerd, kernel) and drops images whose containers are all gone.

`inventory` uploads one CBOR `Inventory` (`format: "k3sec-inventory"`):

```
Inventory {format, api_version, generated_at, node, cluster_id?, node_versions?, images: [
  ImageInventory {image, digest?, os? {id, version_id, pretty_name},
    containers: [{namespace, pod, container, container_id}],
    packages: [Package {name, version, kind: os|lang|node, purl, source?, location?,
                        reachability: loaded|dormant|unknown,
                        coordinate? {ecosystem?, name?, version?, purl?, cpe?}}],
    mapped_files, warnings}]}
```

`coordinate` is what to send to vuln.mlab.sh `POST /api/v2/scan`, built the
way k3sec does it (distro packages by source package and version); `None`
means not matchable (unsupported distro). mlab matches there and joins the
findings with `reachability`. `cluster_id` is the UID of the `kube-system`
namespace.

## Running it

The agent starts `<path> serve` with an empty environment (`PATH` aside),
its working directory as `work_dir`, stdin/stdout as the protocol channel and
stderr to its log. So, in this mode:

- the Kubernetes API comes from `settings.kubeconfig`, else the pod's service
  account through `kubernetes.default.svc` (no `KUBERNETES_SERVICE_*`
  variables needed);
- the node is `settings.node`, else `$NODE_NAME`, else read from the tool's
  own pod (`spec.nodeName`); without any, `init` fails;
- `cluster_id` needs `get` on namespaces, node versions `get` on nodes;
- inventory and eBPF need the privileges described in the wiki's Deployment
  page (root, host PID namespace, `CAP_BPF` + `CAP_PERFMON`).

The local protocol (u32 big-endian length + CBOR, tagged by `t`) is
implemented in `crates/k3sec-agent/src/protocol.rs` from mlab-agent's
`docs/tool-protocol.md` v1, not through `mlab-agent-tool-sdk`: k3sec is
public, the SDK is not. It was checked against the SDK's own types with a
harness driving `k3sec serve` (init, every op, events, shutdown).

## Status

```
Status {api_version, k3sec_version, boot_id, started_at, node, cluster_id?, node_versions?,
        config, allow, allowed_namespaces, rulesets, allow_remote_rules,
        sources: [{name, state: running|off|failed, error?}],
        counters {events, dropped, last_seq}, images}
```

Rulesets are listed by name: host paths never leave the node.
