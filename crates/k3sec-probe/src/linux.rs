//! Linux eBPF probe: aya loader, ring-buffer reader, and pod enrichment.
//!
//! Loads the kernel programs, attaches the exec tracepoint, then drains the
//! `EVENTS` ring buffer. Each raw kernel [`Event`] is resolved to its owning pod
//! (via the process cgroup → container id → [`ContainerResolver`]) and turned
//! into a [`SecEvent`]. Everything here is best-effort: a malformed record, a
//! full ring buffer, or an unresolved cgroup increments a counter and is dropped
//!, the reader never blocks and never panics on event data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, RingBuf};
use aya::programs::{KProbe, RawTracePoint, TracePoint};
use aya::Ebpf;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use k3sec_core::{
    container_id_of_cgroup, container_id_of_pid, ContainerInfo, ContainerResolver, EventSink,
    ScanRequest, ScanRequestSink, ScanTrigger, SecEvent, Severity, Source,
};
use k3sec_probe_common::{af, kind, Event, COMM_LEN, FILENAME_LEN};

use crate::{is_local_destination, NotPods, ProbeConfig, ProbeKind};

/// How long the events of a container the pod watch does not know yet wait
/// for it: a new container runs before its pod's status names it.
const RESOLVE_WAIT: Duration = Duration::from_secs(2);

/// Counters for dropped events, logged on shutdown.
#[derive(Default)]
struct DropStats {
    /// Records skipped because they carried no container id (host processes).
    host: AtomicU64,
    /// Records whose container id didn't resolve to a known pod.
    unresolved: AtomicU64,
    /// Connects to `0.0.0.0` or loopback (health checks), not reported.
    local: AtomicU64,
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

    let stats = Arc::new(DropStats::default());
    let not_pods = Arc::new(NotPods::new(Duration::from_secs(60)));
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

                for mut ev in batch {
                    let at = chrono::Utc::now();
                    let Some((probe_kind, container_id)) = classify(&ev, &config, &stats) else {
                        continue;
                    };
                    if let Some(pid) = local_pid(&ev, &container_id) {
                        ev.pid = pid;
                    }
                    fill_exec_path(&mut ev);
                    // Read now, while the process (and its mount namespace) lives.
                    let facts = Facts::of(&ev, probe_kind, &container_id);
                    let info = resolver.by_container_id(&container_id).await;
                    if info.is_none() && !not_pods.contains(&container_id) {
                        // Resolved later, off the reader: the next records keep flowing.
                        let (resolver, sink, scan_tx, stats, not_pods) =
                            (resolver.clone(), sink.clone(), scan_tx.clone(), stats.clone(), not_pods.clone());
                        tokio::spawn(async move {
                            tokio::time::sleep(RESOLVE_WAIT).await;
                            let info = resolver.by_container_id(&container_id).await;
                            if info.is_none() {
                                not_pods.insert(&container_id);
                            }
                            let sec = build_event(&ev, probe_kind, &facts, &container_id, info, scan_tx.as_ref(), &stats, at);
                            let _ = sink.send(sec).await;
                        });
                        continue;
                    }
                    let sec = build_event(&ev, probe_kind, &facts, &container_id, info, scan_tx.as_ref(), &stats, at);
                    if sink.send(sec).await.is_err() {
                        return Ok(()); // printer gone
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
        if let Err(e) = attach_tracepoint(ebpf, "k3sec_execve", "sched", "sched_process_exec") {
            // No tracefs (Talos in Docker): the raw tracepoint needs none.
            attach_raw_tracepoint(ebpf, "k3sec_execve_raw", "sched_process_exec")
                .with_context(|| format!("{e:#}"))?;
            tracing::warn!(
                error = %format!("{e:#}"),
                "exec events through the raw tracepoint: paths read from /proc \
                 (a process gone before that shows its name only)"
            );
        }
    }
    if config.kinds.allows(ProbeKind::Exit) {
        attach_raw_tracepoint(ebpf, "k3sec_exit", "sched_process_exit")?;
    }
    if config.kinds.allows(ProbeKind::Escape) {
        // Internal functions a kernel may have inlined: the other primitives keep going.
        for (prog, symbol) in [
            ("k3sec_unix_connect", "unix_stream_connect"),
            ("k3sec_mount", "alloc_fs_context"),
        ] {
            if let Err(e) = attach_kprobe(ebpf, prog, symbol) {
                tracing::warn!(error = %format!("{e:#}"), "escape detection without {symbol}");
            }
        }
    }
    if config.kinds.allows(ProbeKind::FileWrite)
        || config.kinds.allows(ProbeKind::SecretRead)
        || config.kinds.allows(ProbeKind::Escape)
    {
        // An internal function: a kernel may have inlined it. Then no
        // file_write, but exec and connect keep going.
        if let Err(e) = attach_kprobe(ebpf, "k3sec_openat", "do_sys_openat2") {
            tracing::warn!(error = %format!("{e:#}"), "file_write events unavailable on this kernel");
        }
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

fn attach_raw_tracepoint(ebpf: &mut Ebpf, prog: &str, name: &str) -> Result<()> {
    let program: &mut RawTracePoint = ebpf
        .program_mut(prog)
        .ok_or_else(|| anyhow!("eBPF program `{prog}` not found"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("failed to load {prog}"))?;
    program
        .attach(name)
        .with_context(|| format!("failed to attach {prog} to raw tracepoint {name}"))?;
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

/// The kind and container of a record worth reporting; `None` (with a counter
/// bumped) for host processes, local connects and kind-filtered events, so
/// only in-container, requested kinds reach the pipeline.
fn classify(ev: &Event, config: &ProbeConfig, stats: &DropStats) -> Option<(ProbeKind, String)> {
    let probe_kind = match ev.kind {
        kind::EXEC => ProbeKind::Exec,
        kind::CONNECT => ProbeKind::Connect,
        kind::FILE_WRITE if escape_technique(ev).is_some() => ProbeKind::Escape,
        kind::FILE_WRITE => ProbeKind::FileWrite,
        kind::EXIT => ProbeKind::Exit,
        kind::SECRET_READ => ProbeKind::SecretRead,
        kind::UNIX_CONNECT | kind::MOUNT => match escape_technique(ev) {
            Some(_) => ProbeKind::Escape,
            None => return None,
        },
        _ => {
            stats.malformed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    if !config.kinds.allows(probe_kind) {
        return None;
    }
    if probe_kind == ProbeKind::SecretRead && !is_credential(&cstr(&ev.filename[..FILENAME_LEN])) {
        return None;
    }
    if probe_kind == ProbeKind::Connect && dest_ip(ev).is_some_and(is_local_destination) {
        stats.local.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    // Resolve pod context from the kernel's cgroup id, which cannot point at
    // another process; from the PID when the cgroup tree is not v2. Host
    // processes (no container id) are dropped, this is a pod-scoped tool.
    let container_id = container_id_of_cgroup(ev.cgroup_id).or_else(|| container_id_of_pid(ev.pid));
    let Some(container_id) = container_id else {
        stats.host.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    Some((probe_kind, container_id))
}

/// Turn a classified kernel event into a [`SecEvent`], with its pod when known.
#[allow(clippy::too_many_arguments)]
fn build_event(
    ev: &Event,
    probe_kind: ProbeKind,
    facts: &Facts,
    container_id: &str,
    info: Option<ContainerInfo>,
    scan_tx: Option<&ScanRequestSink>,
    stats: &DropStats,
    at: chrono::DateTime<chrono::Utc>,
) -> SecEvent {
    if info.is_none() {
        stats.unresolved.fetch_add(1, Ordering::Relaxed);
    }

    let comm = cstr(&ev.comm[..COMM_LEN]);

    // Fire off a scan request (best-effort, non-blocking) for scannable kinds.
    if let Some(scan_tx) = scan_tx {
        maybe_request_scan(scan_tx, ev, probe_kind, &comm, container_id, info.as_ref());
    }

    let (kind_str, severity, message) = match probe_kind {
        ProbeKind::Exec => {
            let bin = cstr(&ev.filename[..FILENAME_LEN]);
            if let Some((what, severity)) = facts
                .anomaly
                .filter(|_| !facts.drift)
                .map(ExecAnomaly::describe)
            {
                let shown = if bin.is_empty() {
                    comm.clone()
                } else {
                    bin.clone()
                };
                ("exec", severity, format!("exec {shown} ({comm}): {what}"))
            } else if facts.drift {
                (
                    "exec",
                    Severity::Critical,
                    format!("drift: exec {bin} ({comm}), a binary not in the image"),
                )
            } else if bin.is_empty() {
                (
                    "exec",
                    Severity::Info,
                    format!("exec {comm} (path unknown: process gone)"),
                )
            } else if let Some((_, parent)) = facts.ancestors.first() {
                (
                    "exec",
                    Severity::Info,
                    format!("exec {bin} ({comm}) by {parent}"),
                )
            } else {
                ("exec", Severity::Info, format!("exec {bin} ({comm})"))
            }
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
        ProbeKind::Exit => ("exit", Severity::Info, format!("exit {comm}")),
        ProbeKind::SecretRead => {
            let path = cstr(&ev.filename[..FILENAME_LEN]);
            (
                "secret_read",
                Severity::Warning,
                format!("read {path} ({comm})"),
            )
        }
        ProbeKind::Escape => {
            let what = escape_technique(ev).unwrap_or_default();
            (
                "escape",
                Severity::Critical,
                format!("escape: {what} ({comm})"),
            )
        }
    };

    let mut builder = SecEvent::builder(Source::Ebpf, at)
        .kind(kind_str)
        .severity(severity)
        .message(message)
        .meta("pid", ev.pid.to_string())
        .meta("uid", ev.uid.to_string())
        .meta("comm", comm)
        .meta("container_id", short_id(container_id));
    if facts.drift {
        builder = builder.meta("drift", "true");
    }
    if let Some(a) = facts.anomaly {
        builder = builder.meta("exec_anomaly", a.as_str());
    }
    if let Some((ppid, _)) = facts.ancestors.first() {
        let chain: Vec<&str> = facts
            .ancestors
            .iter()
            .rev()
            .map(|(_, c)| c.as_str())
            .collect();
        builder = builder
            .meta("ppid", ppid.to_string())
            .meta("ancestry", chain.join(" > "));
    }

    if let Some(info) = &info {
        builder = builder
            .namespace(info.namespace.clone())
            .object(format!("{}/{}", info.pod, info.container))
            .meta("pod", info.pod.clone())
            .meta("container", info.container.clone());
    }

    builder = builder.payload(payload(ev, probe_kind, container_id, info.as_ref()));
    builder.build()
}

/// Enqueue a scan for exec/file_write events; never blocks event capture.
fn maybe_request_scan(
    scan_tx: &ScanRequestSink,
    ev: &Event,
    probe_kind: ProbeKind,
    comm: &str,
    container_id: &str,
    info: Option<&ContainerInfo>,
) {
    let trigger = match probe_kind {
        ProbeKind::Exec => ScanTrigger::Exec,
        ProbeKind::FileWrite => ScanTrigger::FileWrite,
        ProbeKind::Connect | ProbeKind::Exit | ProbeKind::SecretRead | ProbeKind::Escape => return,
    };
    let req = ScanRequest {
        trigger,
        pid: ev.pid,
        path: Some(cstr(&ev.filename[..FILENAME_LEN])),
        container_id: Some(container_id.to_string()),
        container: info.cloned(),
        comm: comm.to_string(),
    };

    // Non-blocking: if the scan queue is full we drop the request rather than
    // stall event capture, a dropped scan is cheaper than a blocked probe.
    if scan_tx.try_send(req).is_err() {
        tracing::debug!("scan queue full or closed; dropping scan request");
    }
}

/// Convert a NUL-padded byte field to a `String` (lossy, trimmed at first NUL).
/// The kernel reports PIDs of the root namespace. When k3sec runs in a nested
/// one (a node that is itself a container: k3d, kind, k3s in Docker) those
/// exist nowhere in its `/proc`: the event's process is then taken to be the
/// newest of its container with its name. `None` keeps the kernel's PID.
fn local_pid(ev: &Event, container_id: &str) -> Option<u32> {
    /// The root PID namespace's inode (`PROC_PID_INIT_INO`).
    const INIT_PID_NS: u64 = 0xEFFF_FFFC;
    static NESTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let nested = *NESTED.get_or_init(|| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/pid").is_ok_and(|m| m.ino() != INIT_PID_NS)
    });
    if !nested || container_id_of_pid(ev.pid).as_deref() == Some(container_id) {
        return None;
    }
    let comm = cstr(&ev.comm[..COMM_LEN]);
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|p| {
            std::fs::read_to_string(format!("/proc/{p}/comm")).is_ok_and(|c| c.trim_end() == comm)
        })
        .filter(|&p| container_id_of_pid(p).as_deref() == Some(container_id))
        .max()
}

/// What makes `ev` a container-escape primitive, if it is one.
fn escape_technique(ev: &Event) -> Option<String> {
    let path = cstr(&ev.filename[..FILENAME_LEN]);
    let comm = cstr(&ev.comm[..COMM_LEN]);
    match ev.kind {
        kind::FILE_WRITE => {
            let file = path.rsplit('/').next().unwrap_or("");
            let what = match file {
                "release_agent" | "notify_on_release" if path.starts_with("/sys/fs/cgroup/") => {
                    "cgroup release_agent"
                }
                "core_pattern" if path.starts_with("/proc/sys/kernel/") => "core_pattern",
                "modprobe" if path.starts_with("/proc/sys/kernel/") => "modprobe helper",
                "uevent_helper" => "uevent helper",
                _ => return None,
            };
            Some(format!("write {path} ({what})"))
        }
        kind::UNIX_CONNECT => [
            "docker.sock",
            "containerd.sock",
            "crio.sock",
            "cri-dockerd.sock",
            "podman.sock",
        ]
        .iter()
        .any(|s| path.ends_with(s))
        .then(|| format!("connect to the container runtime's socket {path}")),
        kind::MOUNT => {
            // runc sets the container's own mounts up before the process starts.
            if comm.starts_with("runc") || comm.starts_with("containerd") || comm == "k3s" {
                return None;
            }
            let fstype = cstr(&ev.aux);
            let what = match fstype.as_str() {
                "cgroup" | "cgroup2" => "the cgroup hierarchy",
                "debugfs" | "securityfs" | "bpf" | "tracefs" => "a kernel interface",
                // A disk filesystem: a host block device, from a container.
                "ext4" | "ext3" | "ext2" | "xfs" | "btrfs" | "vfat" | "ntfs" | "ntfs3" | "f2fs" => {
                    "a disk"
                }
                _ => return None,
            };
            Some(format!("mount of {what} ({fstype})"))
        }
        _ => None,
    }
}

/// A `secret_read` path worth reporting: the kernel matched prefixes; under
/// `/home/` only users' credential directories count.
fn is_credential(path: &str) -> bool {
    match path.strip_prefix("/home/") {
        Some(rest) => [
            "/.ssh/",
            "/.aws/",
            "/.kube/",
            "/.docker/config.json",
            "/.config/gcloud/",
            "/.azure/",
        ]
        .iter()
        .any(|d| rest.contains(d)),
        None => true,
    }
}

/// What is read about a record's process while it still runs.
#[derive(Debug, Default)]
struct Facts {
    /// The exec'd file is in the container's writable layer: added or
    /// modified after the container started, so not the image's.
    drift: bool,
    /// The process's ancestors in its container, nearest first: `(pid, comm)`.
    ancestors: Vec<(u32, String)>,
    /// How the exec'd file itself is suspicious, if it is.
    anomaly: Option<ExecAnomaly>,
}

/// Where an exec'd binary lives, when that is itself a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecAnomaly {
    /// Run from memory (`memfd_create`), no file on disk.
    Fileless,
    /// The file was deleted after it started (or while it was being run).
    Deleted,
    /// A path component starts with a dot (`/tmp/.x/payload`).
    Hidden,
    /// From a world-writable temporary directory.
    TempDir,
}

impl ExecAnomaly {
    fn of(path: &str, exe_link: &str) -> Option<Self> {
        if let Some(memfd) = exe_link.strip_prefix("/memfd:") {
            // runc re-executes itself from a memfd to start every container.
            return (!memfd.starts_with("runc_cloned")).then_some(Self::Fileless);
        }
        if exe_link.ends_with(" (deleted)") {
            return Some(Self::Deleted);
        }
        let path = if path.is_empty() { exe_link } else { path };
        if path
            .split('/')
            .any(|c| c.starts_with('.') && c != "." && c != "..")
        {
            return Some(Self::Hidden);
        }
        ["/tmp/", "/dev/shm/", "/var/tmp/"]
            .iter()
            .any(|d| path.starts_with(d))
            .then_some(Self::TempDir)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Fileless => "fileless",
            Self::Deleted => "deleted",
            Self::Hidden => "hidden",
            Self::TempDir => "temp_dir",
        }
    }

    fn describe(self) -> (&'static str, Severity) {
        match self {
            Self::Fileless => (
                "run from memory (memfd), no file on disk",
                Severity::Critical,
            ),
            Self::Deleted => ("its file is deleted", Severity::Critical),
            Self::Hidden => ("a hidden path", Severity::Warning),
            Self::TempDir => ("from a temporary directory", Severity::Warning),
        }
    }
}

impl Facts {
    fn of(ev: &Event, kind: ProbeKind, container_id: &str) -> Self {
        let mut facts = Facts::default();
        if kind == ProbeKind::Exec {
            let path = cstr(&ev.filename[..FILENAME_LEN]);
            facts.drift = !path.is_empty()
                && upper_dir(container_id, ev.pid)
                    .is_some_and(|upper| in_upper_layer(&upper, &path));
            facts.ancestors = ancestors(ev.pid, container_id);
            let exe_link = std::fs::read_link(format!("/proc/{}/exe", ev.pid))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            facts.anomaly = ExecAnomaly::of(&path, &exe_link);
        }
        facts
    }
}

/// Up to 8 ancestors of `pid` in the same container, nearest first: the
/// chain stops at the container's first process (its parent is the runtime).
fn ancestors(pid: u32, container_id: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut pid = pid;
    for _ in 0..8 {
        let Some(ppid) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| parent_of(&s))
        else {
            break;
        };
        if ppid == 0 || container_id_of_pid(ppid).as_deref() != Some(container_id) {
            break;
        }
        let comm = std::fs::read_to_string(format!("/proc/{ppid}/comm")).unwrap_or_default();
        out.push((ppid, comm.trim_end().to_string()));
        pid = ppid;
    }
    out
}

/// The 4th field of `/proc/<pid>/stat`, after the parenthesized command
/// (which may hold spaces and parentheses itself).
fn parent_of(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The writable (upper) layer of a container's root overlay, as a path
/// readable here: through `/proc/1/root`, the host's (or node's) root even in
/// a pod. One per container, kept: a short exec is gone before its mountinfo
/// is read, another process of the container then gives it.
fn upper_dir(container_id: &str, pid: u32) -> Option<std::path::PathBuf> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static UPPER: Mutex<Option<HashMap<String, std::path::PathBuf>>> = Mutex::new(None);
    if let Some(hit) = UPPER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .get(container_id)
    {
        return Some(hit.clone());
    }
    let read = |pid: u32| {
        let info = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
        let upper = root_upper_dir(&info)?;
        Some(std::path::Path::new("/proc/1/root").join(upper.trim_start_matches('/')))
    };
    let found = read(pid).or_else(|| {
        std::fs::read_dir("/proc")
            .ok()?
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|&p| container_id_of_pid(p).as_deref() == Some(container_id))
            .find_map(read)
    })?;
    let mut cache = UPPER.lock().unwrap_or_else(|e| e.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    // shortcut: wholesale reset instead of expiry, bounded by containers seen
    if cache.len() >= 4096 {
        cache.clear();
    }
    cache.insert(container_id.to_string(), found.clone());
    Some(found)
}

/// `upperdir=` of the overlay mounted on `/` in a mountinfo.
fn root_upper_dir(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let (mount, fs) = line.split_once(" - ")?;
        if mount.split(' ').nth(4)? != "/" || !fs.starts_with("overlay ") {
            return None;
        }
        fs.split([' ', ','])
            .find_map(|o| o.strip_prefix("upperdir="))
            .map(str::to_string)
    })
}

fn in_upper_layer(upper: &std::path::Path, path: &str) -> bool {
    // A whiteout or a directory there is no binary of this container.
    upper
        .join(path.trim_start_matches('/'))
        .symlink_metadata()
        .is_ok_and(|m| m.is_file())
}

/// An exec record from the raw tracepoint has no path: read it now, while
/// the process lives. Gone already, it keeps its name only.
fn fill_exec_path(ev: &mut Event) {
    if ev.kind != kind::EXEC || ev.filename[0] != 0 {
        return;
    }
    if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", ev.pid)) {
        let path = exe.to_string_lossy();
        let path = path.trim_end_matches(" (deleted)").as_bytes();
        let n = path.len().min(FILENAME_LEN - 1);
        ev.filename[..n].copy_from_slice(&path[..n]);
    }
}

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
    let ip = dest_ip(ev).map_or_else(|| "?".to_string(), |ip| ip.to_string());
    format!("{ip}:{}", ev.dport)
}

/// A connect event's destination address.
fn dest_ip(ev: &Event) -> Option<IpAddr> {
    match ev.af {
        af::INET => {
            let o = &ev.daddr;
            Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]).into())
        }
        af::INET6 => Some(Ipv6Addr::from(ev.daddr).into()),
        _ => None,
    }
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
        ProbeKind::Exec | ProbeKind::FileWrite | ProbeKind::SecretRead => {
            obj["path"] = serde_json::json!(cstr(&ev.filename[..FILENAME_LEN]));
        }
        ProbeKind::Escape => {
            obj["path"] = serde_json::json!(cstr(&ev.filename[..FILENAME_LEN]));
            obj["technique"] = serde_json::json!(escape_technique(ev));
        }
        ProbeKind::Connect => {
            obj["dest"] = serde_json::json!(format_dest(ev));
        }
        ProbeKind::Exit => {}
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
        local = stats.local.load(Ordering::Relaxed),
        malformed = stats.malformed.load(Ordering::Relaxed),
        "eBPF probe drop counters",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_exec_records_get_their_path_from_proc() {
        let mut ev = Event::zeroed();
        ev.kind = kind::EXEC;
        ev.pid = std::process::id();
        fill_exec_path(&mut ev);
        let me = std::env::current_exe().unwrap();
        assert_eq!(cstr(&ev.filename), me.to_string_lossy());

        // A path the tracepoint already gave is kept; other kinds are left alone.
        ev.filename = [0; FILENAME_LEN];
        ev.filename[..9].copy_from_slice(b"/bin/true");
        fill_exec_path(&mut ev);
        assert_eq!(cstr(&ev.filename), "/bin/true");
        let mut conn = Event::zeroed();
        conn.kind = kind::CONNECT;
        conn.pid = std::process::id();
        fill_exec_path(&mut conn);
        assert_eq!(conn.filename[0], 0);
    }

    #[test]
    fn overlay_upper_dir_and_drift() {
        let info = "2717 2512 0:736 / / rw,relatime - overlay overlay rw,lowerdir=/s/939/fs:/s/938/fs,upperdir=/s/940/fs,workdir=/s/940/work\n\
                    2718 2717 0:740 / /proc rw - proc proc rw\n";
        assert_eq!(root_upper_dir(info).as_deref(), Some("/s/940/fs"));
        assert_eq!(root_upper_dir("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"), None);

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        std::fs::write(dir.path().join("tmp/x"), b"\x7fELF").unwrap();
        assert!(in_upper_layer(dir.path(), "/tmp/x"));
        assert!(!in_upper_layer(dir.path(), "/bin/sh"));
        assert!(!in_upper_layer(dir.path(), "/tmp"));
    }

    #[test]
    fn parent_from_stat() {
        assert_eq!(
            parent_of("4242 (nginx: worker) S 4200 4200 4200 0 -1"),
            Some(4200)
        );
        assert_eq!(parent_of("7 (a) b) R 1 7 7"), Some(1));
        assert_eq!(parent_of("garbage"), None);
        // This test's own parent is in no container of that name: none listed.
        assert!(ancestors(std::process::id(), "no-such-container").is_empty());
    }

    #[test]
    fn exec_anomalies() {
        use ExecAnomaly::*;
        assert_eq!(
            ExecAnomaly::of("/proc/self/fd/3", "/memfd:payload (deleted)"),
            Some(Fileless)
        );
        assert_eq!(
            ExecAnomaly::of(
                "/proc/self/fd/6",
                "/memfd:runc_cloned:/proc/self/exe (deleted)"
            ),
            None,
            "runc starting a container"
        );
        assert_eq!(
            ExecAnomaly::of("/usr/bin/x", "/usr/bin/x (deleted)"),
            Some(Deleted)
        );
        assert_eq!(
            ExecAnomaly::of("/var/lib/.cache/kworker", "/var/lib/.cache/kworker"),
            Some(Hidden)
        );
        assert_eq!(ExecAnomaly::of("/dev/shm/x", "/dev/shm/x"), Some(TempDir));
        assert_eq!(ExecAnomaly::of("/usr/bin/curl", "/usr/bin/curl"), None);
        assert_eq!(
            ExecAnomaly::of("", "/tmp/a"),
            Some(TempDir),
            "path gone, the link tells"
        );
    }

    #[test]
    fn credential_paths() {
        assert!(is_credential(
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ));
        assert!(is_credential("/home/app/.ssh/id_ed25519"));
        assert!(is_credential("/home/app/.docker/config.json"));
        assert!(!is_credential("/home/app/notes.txt"));
    }

    #[test]
    fn escape_primitives() {
        let ev = |k: u32, path: &str, comm: &str, aux: &str| {
            let mut e = Event::zeroed();
            e.kind = k;
            e.filename[..path.len()].copy_from_slice(path.as_bytes());
            e.comm[..comm.len()].copy_from_slice(comm.as_bytes());
            e.aux[..aux.len()].copy_from_slice(aux.as_bytes());
            e
        };
        let t = |k, p, c, a| escape_technique(&ev(k, p, c, a));
        assert!(t(
            kind::FILE_WRITE,
            "/sys/fs/cgroup/rdma/release_agent",
            "sh",
            ""
        )
        .is_some());
        assert!(t(kind::FILE_WRITE, "/proc/sys/kernel/core_pattern", "sh", "").is_some());
        assert!(t(kind::FILE_WRITE, "/sys/fs/cgroup/memory.max", "sh", "").is_none());
        assert!(t(kind::FILE_WRITE, "/etc/passwd", "sh", "").is_none());
        assert!(t(kind::UNIX_CONNECT, "/var/run/docker.sock", "curl", "").is_some());
        assert!(t(kind::UNIX_CONNECT, "/run/app.sock", "curl", "").is_none());
        assert!(t(kind::MOUNT, "", "mount", "ext4").is_some());
        assert!(t(kind::MOUNT, "", "mount", "cgroup2").is_some());
        assert!(t(kind::MOUNT, "", "runc:[2:INIT]", "cgroup2").is_none());
        assert!(t(kind::MOUNT, "", "mount", "tmpfs").is_none());
    }
}
