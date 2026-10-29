# Tool API (mlab-agent integration)

With an [mlab](https://mlab.sh) workspace, k3sec runs as a **tool of the
mlab-agent** on each node: the agent starts `k3sec serve` as a child process,
pinned to the SHA-256 of its binary in the agent's local policy, and talks to
it on stdin/stdout. k3sec holds no mlab key and opens no connection to mlab or
vuln.mlab.sh: the agent owns the workspace identity and the only outbound
link.

The contract is versioned and frozen: **v1**, crate `k3sec-api`, spec in
[`docs/tool-api.md`](https://github.com/mlab-sh/k3sec/blob/main/docs/tool-api.md).

| | |
|---|---|
| Ops (mlab → k3sec) | `status`, `configure`, `events_since`, `inventory` (blob), `sbom` (blob) |
| Events (k3sec → mlab) | `batch` (runtime events), `status` (heartbeat), `inventory_ready` |
| Event schema | `SecEvent` v1: the [SecEvent](SecEvent-Schema) fields, `timestamp` in Unix ms |
| Reliability | numbered batches (`boot_id` + `seq`), gaps recovered with `events_since`, drops counted, critical events flushed first |
| Config | chosen in the workspace (`configure`), bounded by `[tools.k3sec.settings]` in the agent's local policy |
| Vulnerabilities | k3sec sends the inventory with match coordinates and reachability; matching happens in mlab |

`k3sec serve` is that mode: it is started by the agent, never by hand. The
DaemonSet running the agent and k3sec side by side is being built (M5); the
standalone commands on the other pages are unchanged.
