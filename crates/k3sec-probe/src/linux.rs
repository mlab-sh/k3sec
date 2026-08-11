//! Linux eBPF probe: aya loader, ring-buffer reader, and pod enrichment.
//!
//! Loads the kernel programs, attaches the `execve` tracepoint, then drains the
//! `EVENTS` ring buffer. Each raw kernel [`Event`] is resolved to its owning pod
//! (via the process cgroup → container id → [`ContainerResolver`]) and turned
//! into a [`SecEvent`]. Everything here is best-effort: a malformed record, a
//! full ring buffer, or an unresolved cgroup increments a counter and is dropped
//!, the reader never blocks and never panics on event data.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use k3sec_core::{
    container_id_from_cgroup, ContainerInfo, ContainerResolver, EventSink, ScanRequest,
    ScanRequestSink, ScanTrigger, SecEvent, Severity, Source,
};
use k3sec_probe_common::{af, kind, Event, COMM_LEN, FILENAME_LEN};

use crate::{ProbeConfig, ProbeKind};

/// Counters for dropped events, logged on shutdown.
#[derive(Default)]
struct DropStats {
    /// Records skipped because they carried no container id (host processes).
    host: AtomicU64,
    /// Records whose container id didn't resolve to a known pod.
    unresolved: AtomicU64,
    /// Malformed / short ring-buffer records.
    malformed: AtomicU64,
}

pub async fn run(
    config: ProbeConfig,
    resolver: Arc<dyn ContainerResolver>,
    scan_tx: Option<ScanRequestSink>,
    sink: EventSink,
    cancel: CancellationToken,
) -> Result<()> {
    // eBPF object embedded at build time (see build.rs / aya-build).
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/k3sec-bpf"
    )))
    .context("failed to load eBPF object (need root, or CAP_BPF+CAP_PERFMON)")?;

    attach_programs(&mut ebpf, &config)?;

    let ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("EVENTS ring buffer map missing from eBPF object"))?,
    )?;
    let drops_map: Array<_, u64> = Array::try_from(
        ebpf.take_map("DROPS")
            .ok_or_else(|| anyhow!("DROPS map missing from eBPF object"))?,
    )?;

    tracing::info!("eBPF probe loaded; streaming kernel events");

    let stats = DropStats::default();
    let mut async_fd = AsyncFd::new(ring).context("failed to register ring buffer for polling")?;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            readable = async_fd.readable_mut() => {
                let mut guard = readable.context("ring buffer poll error")?;

                // Copy out every ready record, then release the guard before any
                // awaiting so we don't hold the ring borrow across an .await.
                let mut batch: Vec<Event> = Vec::new();
                {
                    let ring = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        match Event::from_bytes(&item) {
                            Some(ev) => batch.push(ev),
                            None => { stats.malformed.fetch_add(1, Ordering::Relaxed); }
                        }
                    }
                }
                guard.clear_ready();

                for ev in batch {
                    if let Some(sec) =
                        build_event(&ev, &config, resolver.as_ref(), scan_tx.as_ref(), &stats).await
                    {
                        if sink.send(sec).await.is_err() {
                            return Ok(()); // printer gone
                        }
                    }
                }
            }
        }
    }

    report_drops(&stats, &drops_map);
    Ok(())
}

/// Load and attach only the programs whose kind is enabled by `--kind`.
fn attach_programs(ebpf: &mut Ebpf, config: &ProbeConfig) -> Result<()> {
    if config.kinds.allows(ProbeKind::Exec) {
        attach_tracepoint(ebpf, "k3sec_execve", "syscalls", "sys_enter_execve")?;
    }
    if config.kinds.allows(ProbeKind::FileWrite) {
        attach_tracepoint(ebpf, "k3sec_openat", "syscalls", "sys_enter_openat")?;
    }
    if config.kinds.allows(ProbeKind::Connect) {
        attach_kprobe(ebpf, "k3sec_tcp_v4_connect", "tcp_v4_connect")?;
        attach_kprobe(ebpf, "k3sec_tcp_v6_connect", "tcp_v6_connect")?;
    }
    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, prog: &str, category: &str, name: &str) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(prog)
        .ok_or_else(|| anyhow!("eBPF program `{prog}` not found"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("failed to load {prog}"))?;
    program
        .attach(category, name)
        .with_context(|| format!("failed to attach {prog} to {category}:{name}"))?;
    Ok(())
}

fn attach_kprobe(ebpf: &mut Ebpf, prog: &str, symbol: &str) -> Result<()> {
    let program: &mut KProbe = ebpf
        .program_mut(prog)
        .ok_or_else(|| anyhow!("eBPF program `{prog}` not found"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("failed to load {prog}"))?;
    program
        .attach(symbol, 0)
        .with_context(|| format!("failed to attach {prog} to kprobe {symbol}"))?;
    Ok(())
}

/// Turn a raw kernel event into a [`SecEvent`], attaching pod context.
///
/// Returns `None` (with a counter bumped) for host processes and kind-filtered
/// events, so only in-container, requested kinds reach the pipeline.
async fn build_event(
    ev: &Event,
    config: &ProbeConfig,
    resolver: &dyn ContainerResolver,
    scan_tx: Option<&ScanRequestSink>,
    stats: &DropStats,
) -> Option<SecEvent> {
    let probe_kind = match ev.kind {
        kind::EXEC => ProbeKind::Exec,
        kind::CONNECT => ProbeKind::Connect,
        kind::FILE_WRITE => ProbeKind::FileWrite,
        _ => {
            stats.malformed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    if !config.kinds.allows(probe_kind) {
        return None;
    }

    // Resolve pod context from the process cgroup. Host processes (no container
    // id) are dropped, this is a pod-scoped tool.
    let container_id = read_container_id(ev.pid);
    let Some(container_id) = container_id else {
        stats.host.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let info = resolver.by_container_id(&container_id).await;
    if info.is_none() {
        stats.unresolved.fetch_add(1, Ordering::Relaxed);
    }

    let comm = cstr(&ev.comm[..COMM_LEN]);

    // Fire off a scan request (best-effort, non-blocking) for scannable kinds.
    if let Some(scan_tx) = scan_tx {
        maybe_request_scan(scan_tx, ev, probe_kind, &comm, info.as_ref());
    }

    let (kind_str, severity, message) = match probe_kind {
        ProbeKind::Exec => {
            let bin = cstr(&ev.filename[..FILENAME_LEN]);
            ("exec", Severity::Info, format!("exec {bin} ({comm})"))
        }
        ProbeKind::Connect => {
            let dst = format_dest(ev);
            ("connect", Severity::Info, format!("connect {dst} ({comm})"))
        }
        ProbeKind::FileWrite => {
            let path = cstr(&ev.filename[..FILENAME_LEN]);
            (
                "file_write",
                Severity::Warning,
                format!("write {path} ({comm})"),
            )
        }
    };

    let mut builder = SecEvent::builder(Source::Ebpf, chrono::Utc::now())
        .kind(kind_str)
        .severity(severity)
        .message(message)
        .meta("pid", ev.pid.to_string())
        .meta("uid", ev.uid.to_string())
        .meta("comm", comm)
        .meta("container_id", short_id(&container_id));

    if let Some(info) = &info {
        builder = builder
            .namespace(info.namespace.clone())
            .object(format!("{}/{}", info.pod, info.container))
            .meta("pod", info.pod.clone())
            .meta("container", info.container.clone());
    }

    builder = builder.payload(payload(ev, probe_kind, &container_id, info.as_ref()));
    Some(builder.build())
}

/// Enqueue a scan for exec/file_write events; never blocks event capture.
fn maybe_request_scan(
    scan_tx: &ScanRequestSink,
    ev: &Event,
    probe_kind: ProbeKind,
    comm: &str,
    info: Option<&ContainerInfo>,
) {
    let trigger = match probe_kind {
        ProbeKind::Exec => ScanTrigger::Exec,
        ProbeKind::FileWrite => ScanTrigger::FileWrite,
        ProbeKind::Connect => return, // no bytes to scan
    };
    let path =
        matches!(probe_kind, ProbeKind::FileWrite).then(|| cstr(&ev.filename[..FILENAME_LEN]));

    let req = ScanRequest {
        trigger,
        pid: ev.pid,
        path,
        container: info.cloned(),
        comm: comm.to_string(),
    };

    // Non-blocking: if the scan queue is full we drop the request rather than
    // stall event capture, a dropped scan is cheaper than a blocked probe.
    if scan_tx.try_send(req).is_err() {
        tracing::debug!("scan queue full or closed; dropping scan request");
    }
}

/// Read `/proc/<pid>/cgroup` and extract the container id, if any.
fn read_container_id(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    container_id_from_cgroup(&content)
}

/// Convert a NUL-padded byte field to a `String` (lossy, trimmed at first NUL).
fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// First 12 hex chars of a container id (docker-style short id).
fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Format a connect event's destination as `ip:port`.
fn format_dest(ev: &Event) -> String {
    let ip = match ev.af {
        af::INET => {
            let o = &ev.daddr;
            Ipv4Addr::new(o[0], o[1], o[2], o[3]).to_string()
        }
        af::INET6 => Ipv6Addr::from(ev.daddr).to_string(),
        _ => "?".to_string(),
    };
    format!("{ip}:{}", ev.dport)
}

fn payload(
    ev: &Event,
    probe_kind: ProbeKind,
    container_id: &str,
    info: Option<&ContainerInfo>,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "pid": ev.pid,
        "uid": ev.uid,
        "cgroup_id": ev.cgroup_id,
        "comm": cstr(&ev.comm[..COMM_LEN]),
        "container_id": container_id,
    });
    match probe_kind {
        ProbeKind::Exec | ProbeKind::FileWrite => {
            obj["path"] = serde_json::json!(cstr(&ev.filename[..FILENAME_LEN]));
        }
        ProbeKind::Connect => {
            obj["dest"] = serde_json::json!(format_dest(ev));
        }
    }
    if let Some(info) = info {
        obj["namespace"] = serde_json::json!(info.namespace);
        obj["pod"] = serde_json::json!(info.pod);
        obj["container"] = serde_json::json!(info.container);
    }
    obj
}

fn report_drops(stats: &DropStats, drops_map: &Array<aya::maps::MapData, u64>) {
    let kernel = drops_map.get(&0, 0).unwrap_or(0);
    tracing::info!(
        kernel_ringbuf_full = kernel,
        host = stats.host.load(Ordering::Relaxed),
        unresolved = stats.unresolved.load(Ordering::Relaxed),
        malformed = stats.malformed.load(Ordering::Relaxed),
        "eBPF probe drop counters",
    );
}
