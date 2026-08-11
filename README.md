# k3sec

Runtime security CLI for **k3s** clusters, written in Rust.

k3sec gives you a single real-time stream of what's happening in your cluster,
normalized into one event schema:

- **Kubernetes events** (watch API, no polling)
- **Pod logs** (`--logs`, multi-pod, follow)
- **Kernel runtime activity** via an **eBPF** probe (`--ebpf`) — exec, outbound
  connects, and writes to sensitive paths, enriched with the pod/namespace they
  came from *(M2, landing now — see status below)*

Everything flows through the generic [`SecEvent`] envelope, so the detection
engine (M3: rules + yara-x) can plug into the same stream later.

> **Realtime by default.** k3sec is a detection tool, not a history viewer. It
> shows what happens *after* you start watching. Use `--rollback` to replay the
> existing backlog first.

## Status

- **M1** — live k8s events & pod logs, pretty/JSON output. ✅
- **M2** — eBPF runtime probe: `exec` / `connect` / `file_write`, pod-enriched,
  via a ring buffer with in-kernel filtering. ✅ (build with `--features ebpf`).
- **M3** — detection rules + yara-x. Planned.

## Install

Requires a recent stable Rust toolchain (2021 edition).

```bash
git clone https://github.com/Sn0wAlice/k3sec
cd k3sec
cargo build --release
# binary at ./target/release/k3sec
```

The eBPF probe is Linux-only and behind a feature flag. Building it needs a
nightly toolchain (to cross-compile the kernel program) and `bpf-linker`:

```bash
# One-time toolchain setup on the node (Linux, kernel 6.x, BTF enabled):
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker        # needs LLVM (apt install llvm clang)

# Build with the probe compiled in:
cargo build --release --features ebpf
```

The kernel program lives in `crates/k3sec-probe-ebpf` (its own standalone
workspace); `k3sec-probe`'s build script compiles it via `aya-build`. A normal
host build (no `--features ebpf`) never touches any of this.

## Usage

k3sec uses your current kubeconfig (`$KUBECONFIG`, then `~/.kube/config`), or an
explicit `--kubeconfig <path>`.

```bash
# Live events from all namespaces (realtime, pretty)
k3sec watch

# Replay existing events (sorted by time), then go live
k3sec watch --rollback

# One namespace only
k3sec watch --namespace default

# Also follow pod logs
k3sec watch --logs

# Kernel runtime events via eBPF (needs root or CAP_BPF+CAP_PERFMON)
sudo k3sec watch --ebpf

# Only exec + connect from the probe, as NDJSON
sudo k3sec watch --ebpf --kind exec,connect --output json
```

Flags (`k3sec watch --help`):

| Flag | Description | Default |
|------|-------------|---------|
| `-n, --namespace <NS>` | Restrict to one namespace | all namespaces |
| `--logs` | Follow pod container logs | off |
| `--ebpf` | Enable the eBPF runtime probe | off |
| `--kind <exec,connect,file_write>` | Restrict eBPF events to these kinds | all |
| `--rollback` | Replay backlog before going live | off (realtime) |
| `-o, --output <pretty\|json>` | Output format | `pretty` |
| `--kubeconfig <PATH>` | Kubeconfig file | `$KUBECONFIG` / `~/.kube/config` |

Internal diagnostics go to **stderr** (`RUST_LOG`, e.g. `RUST_LOG=k3sec=debug`);
event output goes to **stdout**, so JSON piping stays clean. **Ctrl+C** shuts
down gracefully.

### JSON output (NDJSON)

One `SecEvent` per line — a source-agnostic envelope shared by every source
(k8s events, logs, and the eBPF probe):

```jsonc
{
  "source": "ebpf",                    // k8s-event | k8s-log | ebpf
  "timestamp": "2026-08-11T18:30:05Z",
  "kind": "exec",                      // event reason | "log" | exec|connect|file_write
  "severity": "warning",
  "namespace": "default",
  "object": "pod/academy-…",
  "message": "…",
  "metadata": { /* flat string fields: pod, container, pid, … */ },
  "payload": { /* raw source-specific detail */ }
}
```

## Robustness

- **No polling** — watch API for events and pods.
- **Auto-reconnect** with exponential backoff (1s → 30s) on watch drops.
- **Graceful shutdown** on Ctrl+C.
- **Readable errors** for kubeconfig / connectivity / RBAC — no panics.
- The eBPF path is designed to **drop, not crash**, on backpressure or
  unresolved context (M2/Phase 1).

## Architecture

A Cargo **workspace** of focused crates. The output pipeline is
source-agnostic: every collector implements `EventSource` and feeds one printer.

```
crates/
  k3sec-core/   SecEvent envelope · EventSource trait · pretty/NDJSON output
  k3sec-k8s/    K8sEventSource (events) · K8sLogSource (logs)
  k3sec-probe/  EbpfSource (aya eBPF probe; Linux, feature = "ebpf")
  k3sec/        the CLI binary (clap) wiring sources into the pipeline
```

Adding a source (like the probe) never touches rendering — it just implements
`EventSource` and gets wired into the CLI.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

CI (GitHub Actions) runs fmt + clippy (deny warnings) + build + test.

[`SecEvent`]: crates/k3sec-core/src/event.rs
