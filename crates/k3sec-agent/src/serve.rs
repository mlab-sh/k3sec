//! `k3sec serve`: k3sec as an mlab-agent tool, on stdin/stdout.
//!
//! ```text
//! sources ──▶ [capture queue] ──relay (drops, counted)──▶ [stream queue] ──▶ collector
//!   collector: filter, exec sha256, → v1 SecEvent → Stream (batches, backlog) ──▶ writer
//! agent ──frames──▶ protocol loop (this thread): init, calls (ops), shutdown
//!                     └── writer (one thread owns stdout: answers + events, whole frames)
//! ```
//!
//! Capture never waits on the agent: events reach the stream through a
//! dropping relay, and a batch the writer can't take now stays in the
//! backlog for `events_since`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use k3sec_api::{self as api, op, Config, Settings};
use k3sec_core::SecEvent;
use k3sec_inventory::{node_inventory, ExecObservation, ImageInventory};
use kube::Client;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::config::{self, Effective};
use crate::convert;
use crate::hash::ExecHasher;
use crate::pipeline::{Deps, Pipeline, States};
use crate::protocol::{self, ErrorBody, ErrorCode, HostMsg, ToolMsg, TOOL_PROTOCOL_VERSION};
use crate::stream::Stream;

/// Batches are cut at least this often.
const BATCH_INTERVAL: Duration = Duration::from_secs(2);
const HEARTBEAT: Duration = Duration::from_secs(60);
/// Between the capture queue and the stream: the relay drops past this.
const STREAM_QUEUE: usize = 8192;
/// Frames waiting for stdout; events past this wait in the backlog.
const WRITER_QUEUE: usize = 256;

/// Run the tool protocol on stdin/stdout until the agent says stop.
pub async fn serve() -> Result<()> {
    let handle = Handle::current();
    tokio::task::spawn_blocking(move || {
        let (mut stdin, stdout) = (std::io::stdin().lock(), std::io::stdout());
        serve_on(&handle, &mut stdin, Box::new(stdout))
    })
    .await
    .context("serve loop panicked")?
}

struct State {
    settings: Settings,
    work_dir: PathBuf,
    effective: Effective,
    stream: Stream,
    inventories: BTreeMap<String, ImageInventory>,
    node: String,
    cluster_id: Option<String>,
    node_versions: Option<k3sec_core::NodeVersions>,
    started_at: i64,
    states: States,
    pipeline: Option<Pipeline>,
    /// What a `configure` restart needs (set once `init` built it).
    deps: Option<Deps>,
}

type Shared = Arc<Mutex<State>>;

/// Frames to stdout, from any thread.
#[derive(Clone)]
struct Writer(std_mpsc::SyncSender<Vec<u8>>);

impl Writer {
    fn spawn(mut out: Box<dyn Write + Send>) -> Self {
        let (tx, rx) = std_mpsc::sync_channel::<Vec<u8>>(WRITER_QUEUE);
        std::thread::spawn(move || {
            for frame in rx {
                if out.write_all(&frame).and_then(|()| out.flush()).is_err() {
                    break; // agent gone
                }
            }
        });
        Self(tx)
    }

    /// Answers wait for room: the agent is reading, it asked.
    fn answer(&self, msg: &ToolMsg) {
        if let Ok(frame) = protocol::encode(msg) {
            let _ = self.0.send(frame);
        }
    }

    /// Events never wait; `false` when not queued.
    fn event<T: serde::Serialize>(&self, name: &str, body: &T) -> bool {
        let Ok(body) = api::to_cbor(body) else {
            return false;
        };
        protocol::encode(&ToolMsg::Event {
            name: name.into(),
            body,
        })
        .is_ok_and(|frame| self.0.try_send(frame).is_ok())
    }
}

/// The protocol loop over any pipe pair (tests use in-memory ones).
pub fn serve_on(rt: &Handle, input: &mut dyn Read, output: Box<dyn Write + Send>) -> Result<()> {
    let writer = Writer::spawn(output);
    let Some(HostMsg::Init {
        protocol,
        settings,
        work_dir,
    }) = protocol::read(input)?
    else {
        anyhow::bail!("expected init from the agent");
    };
    if protocol != TOOL_PROTOCOL_VERSION {
        writer.answer(&ToolMsg::InitFailed {
            message: format!(
                "agent speaks tool protocol {protocol}, k3sec {TOOL_PROTOCOL_VERSION}"
            ),
        });
        return Ok(());
    }
    let shared = match rt.block_on(init(settings, PathBuf::from(work_dir), writer.clone())) {
        Ok(s) => s,
        Err(e) => {
            writer.answer(&ToolMsg::InitFailed {
                message: format!("{e:#}"),
            });
            return Ok(());
        }
    };
    writer.answer(&ToolMsg::Ready {
        name: api::TOOL.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        ops: op::ALL.iter().map(|s| (*s).to_string()).collect(),
    });

    while let Some(msg) = protocol::read::<HostMsg>(input)? {
        match msg {
            HostMsg::Call {
                id,
                op,
                args,
                blob_ok,
            } => {
                let msg = match call(rt, &shared, &writer, &op, &args, blob_ok) {
                    Ok((body, blob_path)) => ToolMsg::Result {
                        id,
                        body,
                        blob_path: blob_path.map(|p| p.to_string_lossy().into_owned()),
                    },
                    Err(error) => ToolMsg::Failure { id, error },
                };
                writer.answer(&msg);
            }
            HostMsg::Shutdown => break,
            HostMsg::Init { .. } => anyhow::bail!("init sent twice"),
        }
    }
    let pipeline = shared.lock().ok().and_then(|mut s| s.pipeline.take());
    if let Some(p) = pipeline {
        rt.block_on(p.stop());
    }
    Ok(())
}

fn parse_settings(v: ciborium::Value) -> Result<Settings> {
    if v.is_null() {
        return Ok(Settings::default());
    }
    v.deserialized::<Settings>()
        .map_err(|e| anyhow::anyhow!("invalid [tools.k3sec.settings]: {e}"))
}

async fn init(settings: ciborium::Value, work_dir: PathBuf, writer: Writer) -> Result<Shared> {
    let settings = parse_settings(settings)?;
    std::fs::create_dir_all(&work_dir).context("work dir not writable")?;
    let client = match &settings.kubeconfig {
        Some(path) => k3sec_k8s::build_client(Some(Path::new(path))).await?,
        None => k3sec_k8s::build_incluster_client()?,
    };
    // The agent gives tools an empty environment: no $NODE_NAME in a pod.
    let node = match settings
        .node
        .clone()
        .or_else(|| std::env::var("NODE_NAME").ok())
    {
        Some(n) => n,
        None => k3sec_k8s::own_node(&client)
            .await
            .context("node unknown: set `node` in [tools.k3sec.settings]")?,
    };

    let saved = config::load(&work_dir).unwrap_or_default();
    let (clamped, cut) = config::clamp(&settings, &saved);
    for reason in &cut {
        tracing::info!("config clamped: {reason}");
    }
    let effective = config::effective(&settings, clamped, &work_dir)?;

    let boot_id = format!("b-{:016x}", rand_u64());
    let states: States = Arc::default();
    let shared: Shared = Arc::new(Mutex::new(State {
        stream: Stream::new(boot_id, node.clone(), settings.backlog_events as usize),
        settings,
        work_dir,
        effective,
        inventories: BTreeMap::new(),
        node: node.clone(),
        cluster_id: None,
        node_versions: None,
        started_at: chrono::Utc::now().timestamp_millis(),
        states: states.clone(),
        pipeline: None,
        deps: None,
    }));

    let (capture_tx, capture_rx) = mpsc::channel::<SecEvent>(1024);
    let (inv_tx, inv_rx) = mpsc::channel::<ImageInventory>(64);
    let deps = Deps {
        client: client.clone(),
        node,
        sink: capture_tx,
        inventories: inv_tx,
        states,
    };
    let dropped = Arc::new(AtomicU64::new(0));
    let (stream_tx, stream_rx) = mpsc::channel::<SecEvent>(STREAM_QUEUE);
    tokio::spawn(relay(capture_rx, stream_tx, dropped.clone()));
    tokio::spawn(collector(
        stream_rx,
        shared.clone(),
        writer.clone(),
        dropped,
    ));
    tokio::spawn(inventories(inv_rx, shared.clone(), writer.clone()));
    tokio::spawn(facts(client, shared.clone()));
    tokio::spawn(heartbeat(shared.clone(), writer));

    restart(&shared, &deps).await;
    if let Ok(mut s) = shared.lock() {
        s.deps = Some(deps);
    }
    Ok(shared)
}

async fn restart(shared: &Shared, deps: &Deps) {
    let (old, eff) = {
        let Ok(mut s) = shared.lock() else { return };
        (s.pipeline.take(), s.effective.clone())
    };
    if let Some(p) = old {
        p.stop().await;
    }
    let p = Pipeline::start(deps, &eff);
    if let Ok(mut s) = shared.lock() {
        s.pipeline = Some(p);
    }
}

/// Capture → stream, never blocking the sources: a full stream drops.
async fn relay(
    mut rx: mpsc::Receiver<SecEvent>,
    tx: mpsc::Sender<SecEvent>,
    dropped: Arc<AtomicU64>,
) {
    while let Some(ev) = rx.recv().await {
        if tx.try_send(ev).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn collector(
    mut rx: mpsc::Receiver<SecEvent>,
    shared: Shared,
    writer: Writer,
    dropped: Arc<AtomicU64>,
) {
    let hasher = Arc::new(Mutex::new(ExecHasher::default()));
    let mut tick = tokio::time::interval(BATCH_INTERVAL);
    loop {
        let batches = tokio::select! {
            ev = rx.recv() => {
                let Some(mut ev) = ev else { return };
                let (keep, execs) = {
                    let Ok(s) = shared.lock() else { return };
                    (keeps(&s.effective, &ev), s.pipeline.as_ref().and_then(|p| p.execs.clone()))
                };
                if let Some(obs) = ExecObservation::from_event(&ev) {
                    if let Some(tx) = execs {
                        let _ = tx.try_send(obs.clone());
                    }
                    if keep {
                        let h = hasher.clone();
                        let digest = tokio::task::spawn_blocking(move || h.lock().ok()?.of_pid(obs.pid))
                            .await
                            .ok()
                            .flatten();
                        if let Some(d) = digest {
                            ev.metadata.insert("sha256".into(), d);
                        }
                    }
                }
                if !keep {
                    continue;
                }
                let Ok(mut s) = shared.lock() else { return };
                take_drops(&mut s, &dropped);
                s.stream.push(convert::event(&ev))
            }
            _ = tick.tick() => {
                let Ok(mut s) = shared.lock() else { return };
                take_drops(&mut s, &dropped);
                s.stream.flush().into_iter().collect()
            }
        };
        for b in batches {
            if !writer.event(api::event::BATCH, &b) {
                tracing::debug!(seq = b.seq, "writer busy; batch kept for events_since");
            }
        }
    }
}

fn take_drops(s: &mut State, dropped: &AtomicU64) {
    let n = dropped.swap(0, Ordering::Relaxed);
    if n > 0 {
        s.stream.note_dropped(n);
    }
}

/// The config's namespace and severity filters.
fn keeps(eff: &Effective, ev: &SecEvent) -> bool {
    if convert::severity(ev.severity) < eff.config.min_severity {
        return false;
    }
    match &ev.namespace {
        // Host-level events with no namespace (unresolved pod) are kept.
        Some(ns) => eff.namespaces.is_empty() || eff.namespaces.iter().any(|n| n == ns),
        None => true,
    }
}

async fn inventories(mut rx: mpsc::Receiver<ImageInventory>, shared: Shared, writer: Writer) {
    while let Some(inv) = rx.recv().await {
        let ready = api::InventoryReady {
            digest: inv.key().to_string(),
            image: inv.image.clone(),
            packages: inv.packages.len() as u32,
            loaded: inv.count(k3sec_inventory::Reachability::Loaded) as u32,
        };
        if let Ok(mut s) = shared.lock() {
            s.inventories.insert(inv.key().to_string(), inv);
        }
        writer.event(api::event::INVENTORY_READY, &ready);
    }
}

/// Cluster id and node versions, fetched once at start (best effort).
async fn facts(client: Client, shared: Shared) {
    let cluster_id = k3sec_k8s::cluster_id(&client).await;
    let node = shared.lock().map(|s| s.node.clone()).unwrap_or_default();
    let versions = k3sec_k8s::node_versions(&client, Some(&node))
        .await
        .inspect_err(|e| tracing::warn!("node versions unavailable: {e:#}"))
        .ok();
    if let Ok(mut s) = shared.lock() {
        s.cluster_id = cluster_id;
        s.node_versions = versions;
    }
}

async fn heartbeat(shared: Shared, writer: Writer) {
    let mut tick = tokio::time::interval(HEARTBEAT);
    loop {
        tick.tick().await;
        let Some(st) = shared.lock().ok().map(|s| status(&s)) else {
            return;
        };
        writer.event(api::event::STATUS, &st);
    }
}

fn status(s: &State) -> api::Status {
    api::Status {
        api_version: api::API_VERSION,
        k3sec_version: env!("CARGO_PKG_VERSION").into(),
        boot_id: s.stream.boot_id().to_string(),
        started_at: s.started_at,
        node: s.node.clone(),
        cluster_id: s.cluster_id.clone(),
        node_versions: s.node_versions.as_ref().map(convert::node_versions),
        config: s.effective.config.clone(),
        allow: s.settings.allow,
        allowed_namespaces: s.settings.namespaces.clone(),
        rulesets: s.settings.rulesets.keys().cloned().collect(),
        allow_remote_rules: s.settings.allow_remote_rules,
        sources: s
            .states
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default(),
        counters: s.stream.counters(),
        images: s.inventories.len() as u32,
    }
}

fn args<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ErrorBody> {
    if bytes.is_empty() {
        // No-argument ops: mlab may send nothing or CBOR null.
        return api::from_cbor(&[0xf6])
            .map_err(|_| ErrorBody::new(ErrorCode::BadRequest, "arguments required"));
    }
    api::from_cbor(bytes)
        .map_err(|e| ErrorBody::new(ErrorCode::BadRequest, format!("invalid arguments: {e}")))
}

fn reply<T: serde::Serialize>(v: &T) -> Result<(Vec<u8>, Option<PathBuf>), ErrorBody> {
    api::to_cbor(v)
        .map(|b| (b, None))
        .map_err(|_| ErrorBody::new(ErrorCode::Internal, "answer could not be encoded"))
}

fn internal(e: impl std::fmt::Display) -> ErrorBody {
    ErrorBody::new(ErrorCode::Internal, e.to_string())
}

fn call(
    rt: &Handle,
    shared: &Shared,
    writer: &Writer,
    op_name: &str,
    raw: &[u8],
    blob_ok: bool,
) -> Result<(Vec<u8>, Option<PathBuf>), ErrorBody> {
    let lock = || shared.lock().map_err(|_| internal("state poisoned"));
    match op_name {
        op::STATUS => reply(&status(&*lock()?)),
        op::EVENTS_SINCE => {
            let a: api::EventsSince = args(raw)?;
            reply(&lock()?.stream.since(&a.boot_id, a.after_seq))
        }
        op::CONFIGURE => {
            let wanted: Config = args(raw)?;
            let (settings, work_dir) = {
                let s = lock()?;
                (s.settings.clone(), s.work_dir.clone())
            };
            let (clamped, cut) = config::clamp(&settings, &wanted);
            let eff = config::effective(&settings, clamped.clone(), &work_dir).map_err(internal)?;
            // Refuse bad rules now, keeping the running ones.
            if let Some(path) = &eff.rules_path {
                if let Err(e) = k3sec_engine::RuleSet::compile(path) {
                    return Err(ErrorBody::new(
                        ErrorCode::BadRequest,
                        format!("rules refused: {e:#}"),
                    ));
                }
            }
            config::save(&work_dir, &clamped).map_err(internal)?;
            lock()?.effective = eff;
            let deps = lock()?
                .deps
                .clone()
                .ok_or_else(|| internal("not initialized"))?;
            rt.block_on(restart(shared, &deps));
            writer.event(api::event::STATUS, &status(&*lock()?));
            reply(&api::Configured {
                config: clamped,
                clamped: cut,
            })
        }
        op::INVENTORY => {
            let a: api::InventoryRequest = args(raw)?;
            if !blob_ok {
                return Err(ErrorBody::new(
                    ErrorCode::BadRequest,
                    "inventory needs an upload target",
                ));
            }
            let mut s = lock()?;
            // Images whose containers are all gone (pod deleted) leave the inventory.
            let live = k3sec_inventory::pids_by_container();
            s.inventories.retain(|_, inv| {
                inv.containers
                    .iter()
                    .any(|c| live.contains_key(&c.container_id))
            });
            let mut images: Vec<api::ImageInventory> = s
                .inventories
                .iter()
                .filter(|(k, _)| a.digest.as_ref().is_none_or(|d| d == *k))
                .map(|(_, inv)| convert::image(inv))
                .collect();
            if a.digest.is_none() {
                if let Some(v) = &s.node_versions {
                    images.push(convert::image(&node_inventory(v, false)));
                }
            } else if images.is_empty() {
                return Err(ErrorBody::new(
                    ErrorCode::NotFound,
                    "no such image on this node",
                ));
            }
            let info = api::InventoryInfo {
                images: images.len() as u32,
                packages: images.iter().map(|i| i.packages.len() as u32).sum(),
            };
            let doc = api::Inventory {
                format: api::inventory::INVENTORY_FORMAT.into(),
                api_version: api::API_VERSION,
                generated_at: chrono::Utc::now().timestamp_millis(),
                node: s.node.clone(),
                cluster_id: s.cluster_id.clone(),
                node_versions: s.node_versions.as_ref().map(convert::node_versions),
                images,
            };
            let path = s.work_dir.join("inventory.cbor");
            std::fs::write(&path, doc.encode().map_err(internal)?).map_err(internal)?;
            let (body, _) = reply(&info)?;
            Ok((body, Some(path)))
        }
        op::SBOM => {
            let a: api::ImageRef = args(raw)?;
            if !blob_ok {
                return Err(ErrorBody::new(
                    ErrorCode::BadRequest,
                    "sbom needs an upload target",
                ));
            }
            let s = lock()?;
            let inv = s
                .inventories
                .get(&a.digest)
                .ok_or_else(|| ErrorBody::new(ErrorCode::NotFound, "no such image on this node"))?;
            let bom = k3sec_inventory::sbom::cyclonedx(inv);
            let path = s.work_dir.join("sbom.cdx.json");
            std::fs::write(&path, serde_json::to_vec(&bom).map_err(internal)?).map_err(internal)?;
            let (body, _) = reply(&api::SbomInfo {
                digest: a.digest,
                components: inv.packages.len() as u32,
            })?;
            Ok((body, Some(path)))
        }
        _ => Err(ErrorBody::new(ErrorCode::UnknownOp, "k3sec has no such op")),
    }
}

/// A random id per process, without a dependency: the kernel's uuid source.
fn rand_u64() -> u64 {
    std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .ok()
        .and_then(|u| u64::from_str_radix(&u.replace('-', "")[..16], 16).ok())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k3sec_core::Severity;

    /// Collects the frames the tool writes.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frames(sink: &Sink) -> Vec<ToolMsg> {
        std::thread::sleep(Duration::from_millis(100));
        let bytes = sink.0.lock().unwrap().clone();
        let mut r = bytes.as_slice();
        std::iter::from_fn(|| protocol::read::<ToolMsg>(&mut r).ok().flatten()).collect()
    }

    fn init(protocol: u16, settings: ciborium::Value) -> Vec<u8> {
        protocol::encode(&HostMsg::Init {
            protocol,
            settings,
            work_dir: std::env::temp_dir().to_string_lossy().into_owned(),
        })
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refuses_another_protocol_and_bad_settings() {
        let rt = Handle::current();
        let sink = Sink::default();
        let out = sink.clone();
        tokio::task::spawn_blocking(move || {
            serve_on(
                &rt,
                &mut init(2, ciborium::Value::Null).as_slice(),
                Box::new(out),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(&frames(&sink)[..], [ToolMsg::InitFailed { message }] if message.contains("protocol 2"))
        );

        let rt = Handle::current();
        let sink = Sink::default();
        let out = sink.clone();
        let bad = ciborium::Value::Map(vec![("surprise".into(), true.into())]);
        tokio::task::spawn_blocking(move || {
            serve_on(&rt, &mut init(1, bad).as_slice(), Box::new(out))
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(&frames(&sink)[..], [ToolMsg::InitFailed { message }] if message.contains("invalid [tools.k3sec.settings]"))
        );
    }

    #[test]
    fn filters_on_namespace_and_severity() {
        let eff = Effective {
            config: Config {
                min_severity: api::Severity::Warning,
                ..Config::default()
            },
            namespaces: vec!["prod".into()],
            rules_path: None,
        };
        let ev = |ns: Option<&str>, sev| {
            SecEvent::builder(k3sec_core::Source::Ebpf, chrono::Utc::now())
                .maybe_namespace(ns.map(String::from))
                .severity(sev)
                .build()
        };
        assert!(keeps(&eff, &ev(Some("prod"), Severity::Critical)));
        assert!(!keeps(&eff, &ev(Some("dev"), Severity::Critical)));
        assert!(!keeps(&eff, &ev(Some("prod"), Severity::Info)));
        assert!(keeps(&eff, &ev(None, Severity::Warning)));
    }

    #[test]
    fn no_argument_ops_accept_empty_or_null() {
        assert!(args::<Option<u8>>(&[]).is_ok());
        assert!(args::<api::EventsSince>(&[0xa0]).is_err());
    }
}
