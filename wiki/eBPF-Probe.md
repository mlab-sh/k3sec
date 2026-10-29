# eBPF probe (`--ebpf`)

Kernel-sourced runtime events from inside containers, tagged with the pod they
came from:

| Kind | Hook | Severity | Filter |
|------|------|----------|--------|
| `exec` | tracepoint `sched:sched_process_exec` | info | every successful exec in a container |
| `connect` | kprobes `tcp_v4_connect`, `tcp_v6_connect` | info | outbound TCP |
| `file_write` | tracepoint `syscalls:sys_enter_openat` (write flags) | warning | paths under `/etc/`, `/usr/bin/`, `/root/`, `/var/run/secrets` (in-kernel) |

```bash
sudo k3sec watch --ebpf
sudo k3sec watch --ebpf --kind exec,connect -o json
sudo k3sec watch --ebpf --rules ./rules        # + YARA on exec'd binaries / written files
sudo k3sec watch --ebpf --vulns                # + exec events feed reachability
```

Only the programs for the requested `--kind`s are attached.

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
