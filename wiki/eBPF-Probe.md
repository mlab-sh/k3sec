# eBPF probe (`--ebpf`)

Kernel-sourced runtime events from inside containers, tagged with the pod they
came from:

| Kind | Hook | Severity | Filter |
|------|------|----------|--------|
| `exec` | tracepoint `sched:sched_process_exec` | info | every successful exec in a container |
| `connect` | kprobes `tcp_v4_connect`, `tcp_v6_connect` | info | outbound TCP, except to `0.0.0.0`, `::` and loopback (health checks) |
| `file_write` | kprobe `do_sys_openat2` (every `open`, `openat`, `openat2`, `creat` with write flags) | warning | paths under `/etc/`, `/usr/bin/`, `/root/`, `/var/run/secrets`, `/sys/fs/cgroup/`, `/proc/sys/` (in-kernel) |
| `exit` | raw tracepoint `sched_process_exit` | info | a process (not a thread) ends; only with `--kind exit` |
| `escape` | kprobes `do_sys_openat2` (writes), `unix_stream_connect`, `alloc_fs_context` | critical | a write to a cgroup `release_agent` / `notify_on_release`, `/proc/sys/kernel/core_pattern` or `modprobe`; a connect to the runtime's socket (`docker.sock`, `containerd.sock`, `crio.sock`…); a new mount of the cgroup hierarchy, a kernel interface (`debugfs`, `securityfs`, `bpf`) or a disk filesystem (`ext4`, `xfs`…). runc's own mounts at container start are not reported |
| `privesc` | kprobe `commit_creds`, non-root callers only | critical | a non-root process whose effective uid is 0 right after (read from `/proc/<pid>/status`: the `struct cred` layout varies by kernel): a setuid-root binary, a setuid call. The old uid is in the payload |
| `listen` | kprobe `inet_csk_listen_start` | info | a TCP socket starts listening (address and port from `struct sock_common`) |
| `accept` | kretprobe `inet_csk_accept` | info | an inbound TCP connection, its peer and local port; only with `--kind accept` (a server accepts all day: coredns' health checks alone, one a second) |
| `dns` | `cgroup_skb/egress` on the root cgroup | info | a DNS query (UDP 53), its name read from the packet; the same name from the same container is reported once per 10 s. Kubernetes' search domains show as the queries they are (`example.org.cvss.svc.cluster.local`, then `example.org`). Needs `CAP_NET_ADMIN` (in the manifest) |
| `udp` | same program | info | any other UDP datagram sent; only with `--kind udp` |
| `secret_read` | kprobe `do_sys_openat2`, read-only opens | warning | service account tokens, `/etc/shadow`, `/etc/kubernetes/`, kubelet PKI, `.ssh` / `.aws` / `.kube` / `.docker` / gcloud / Azure credentials of `root` and of `/home/*` users (in-kernel prefixes, `/home` narrowed in userspace). Kubernetes clients read their token too: lab background, 1 read in 40 s |

```bash
sudo k3sec watch --ebpf
sudo k3sec watch --ebpf --kind exec,connect -o json
sudo k3sec watch --ebpf --rules ./rules        # + YARA on exec'd binaries / written files
sudo k3sec watch --ebpf --vulns                # + exec events feed reachability
```

Only the programs for the requested `--kind`s are attached.

## Detections

| Detection | Event | How |
|-----------|-------|-----|
| **Ancestry** | `exec`: "exec /bin/sh (sh) by nginx", `ppid`, `ancestry` = `nginx > sh` | the parents of the process in its container, read from `/proc/<pid>/stat` (8 at most, up to the container's first process) |
| **Fileless, deleted, hidden, temp dir** | `exec` with `exec_anomaly` = `fileless` / `deleted` (critical), `hidden` / `temp_dir` (warning) | the exe link: `/memfd:…` (runc's own `runc_cloned` memfd excepted), `(deleted)`, a dotted path component, `/tmp`, `/dev/shm`, `/var/tmp`. Drift, when it applies too, names the event |
| **Cryptominer** | the event's kind, its severity raised, `cryptominer` = the reason | a DNS query for a mining pool's domain (supportxmr, nanopool, moneroocean, c3pool, 2miners, f2pool, unmineable…) or the exec of a miner's binary (xmrig, cpuminer, t-rex, lolminer…): critical; a connect to a stratum port (3333, 4444, 5555, 7777, 14444…): warning. A renamed miner: `rules/cryptominer.yar` |
| **Drift** | `exec`, severity critical, `drift=true`, "a binary not in the image" | the exec'd file is in the container's writable overlay layer (`upperdir` of its root mount): added or modified after the container started. The layer is read once per container, through another process of it when the exec is already gone |

## Build

The probe is Linux-only, behind a cargo feature. The kernel program
(`crates/k3sec-probe-ebpf`, its own BPF-target crate) is compiled by
`k3sec-probe`'s build script through `aya-build`:

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
# bpf-linker: the prebuilt static binary (`cargo install` needs a system LLVM
# of the exact major it was released for, 23 for 0.12)
curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
  | tar --zstd -x -C ~/.cargo/bin
cargo build --release --features ebpf
```

A normal build (without the feature) never touches the BPF toolchain. Running
`--ebpf` on such a binary is a clear error, and the other sources keep going
(real output from the lab binary, built without the feature):

```text
$ k3sec watch --ebpf
2026-10-29T14:42:54.273739Z  INFO connected to cluster, starting watch namespace="<all>" logs=false ebpf=true rules=false vulns=false rollback=false output=Pretty sources=2
2026-10-29T14:42:54.273818Z ERROR source failed: eBPF probe unavailable: this binary was built without eBPF support. Build on Linux with `--features ebpf`, and run as root (or with CAP_BPF+CAP_PERFMON). source="ebpf"
```

Kernel requirements: Linux 6.x with BTF, root or `CAP_BPF` + `CAP_PERFMON`.

## Pod enrichment

Each event's PID → `/proc/<pid>/cgroup` → container id (innermost 64-hex
segment) → pod, through a node-scoped pod watch (`--node` / `$NODE_NAME`).
When the process is already gone (a short `exec`), the kernel's cgroup id
does it instead: it is the inode of the container's cgroup directory, found in
the host's cgroup tree (`/proc/1/root/sys/fs/cgroup`, also from a `hostPID`
pod). Host processes are dropped: k3sec is pod-scoped.

A new container runs before its pod's status names it: its first events would
reach no pod. An event whose container the pod watch does not know yet waits
2 s for it, without holding back the others. A container still unknown then is
not a pod (the node's own containers): its next events go out at once, for a
minute.

Writes are caught on the kernel function every open ends in, not on the
`syscalls:sys_enter_openat` tracepoint, for the same reason as exec below: on
the lab's kernel, 7 of 200 writes under `/etc` reached the tracepoint's
program (and `open` / `creat` never pass there); on the kprobe, 200 of 200. A
kernel that inlined `do_sys_openat2` gets no `file_write` (a warning says
so), the other kinds keep going.

Exec capture uses `sched:sched_process_exec`, not `syscalls:sys_enter_execve`:
on the lab's kernel (7.0), BPF programs on the syscall tracepoint ran for 9 of
50 execs in a container; on `sched_process_exec`, 50 of 50.

## Robustness

Events go through a BPF ring buffer; nothing in the reader blocks or panics on
event data. A full ring buffer (in-kernel), a host process, an unresolved
container or a malformed record increments a counter, logged on shutdown
(format; values elided):

```text
INFO eBPF probe drop counters kernel_ringbuf_full=0 host=… unresolved=… malformed=0
```

Scan requests for [YARA](YARA-Detection) are sent with `try_send`: a full scan
queue drops the scan, never stalls capture.

> The probe shipped in M2. The lab used for this wiki's
> outputs had no `bpf-linker`, so the event samples are described from the code
> rather than captured; see [SecEvent schema](SecEvent-Schema#ebpf) for the
> exact fields.
