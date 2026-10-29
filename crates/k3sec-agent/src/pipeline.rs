//! The sources one [`Effective`] config runs, as one restartable unit: a new
//! config stops this pipeline and starts another, inside the same process.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k3sec_api::SourceState;
use k3sec_core::{EventSink, EventSource, ScanRequest};
use k3sec_engine::{DetectionEngine, EngineConfig};
use k3sec_inventory::{
    check_root_access, Cache, ExecObservation, ImageInventory, LangLimits, VulnWatcher,
};
use k3sec_k8s::{K8sEventSource, K8sLogSource, NodePodResolver, PodNotify};
use k3sec_probe::{EbpfSource, KindFilter, ProbeConfig, ProbeKind};
use kube::Client;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Effective;

pub type States = Arc<Mutex<BTreeMap<String, SourceState>>>;

/// What every pipeline shares, for the life of the process.
#[derive(Clone)]
pub struct Deps {
    pub client: Client,
    pub node: String,
    /// Where every source sends its events.
    pub sink: EventSink,
    /// Where image inventories go (`inventory` op, `inventory_ready`).
    pub inventories: mpsc::Sender<ImageInventory>,
    pub states: States,
}

pub struct Pipeline {
    cancel: CancellationToken,
    handles: Vec<JoinHandle<()>>,
    /// Exec events for the inventory's dormant → loaded promotion.
    pub execs: Option<mpsc::Sender<ExecObservation>>,
}

fn set_state(states: &States, name: &str, state: &str, error: Option<String>) {
    if let Ok(mut s) = states.lock() {
        s.insert(
            name.to_string(),
            SourceState {
                name: name.to_string(),
                state: state.to_string(),
                error,
            },
        );
    }
}

impl Pipeline {
    pub fn start(deps: &Deps, eff: &Effective) -> Self {
        let cancel = CancellationToken::new();
        let src = &eff.config.sources;
        let mut handles = Vec::new();
        for (name, on) in [
            ("k8s_events", src.k8s_events),
            ("logs", src.logs),
            ("ebpf", src.ebpf),
            ("rules", src.rules),
            ("vulns", src.vulns),
        ] {
            if !on {
                set_state(&deps.states, name, "off", None);
            }
        }
        // One namespace: the API scopes the watch; several: the stream filters.
        let one_ns = (eff.namespaces.len() == 1).then(|| eff.namespaces[0].clone());

        let mut sources: Vec<(&'static str, Box<dyn EventSource>)> = Vec::new();
        if src.k8s_events {
            sources.push((
                "k8s_events",
                Box::new(K8sEventSource::new(
                    deps.client.clone(),
                    one_ns.clone(),
                    false,
                )),
            ));
        }
        if src.logs {
            sources.push((
                "logs",
                Box::new(K8sLogSource::new(deps.client.clone(), one_ns)),
            ));
        }

        let mut scan_tx = None;
        if src.rules {
            match eff.rules_path.as_deref().map(|p| {
                DetectionEngine::compile(
                    p,
                    EngineConfig::new(
                        EngineConfig::DEFAULT_MAX_SCAN_SIZE,
                        EngineConfig::default_workers(),
                    ),
                )
            }) {
                Some(Ok(engine)) => {
                    let (tx, rx) = mpsc::channel::<ScanRequest>(1024);
                    scan_tx = Some(tx);
                    let (sink, c, states) =
                        (deps.sink.clone(), cancel.clone(), deps.states.clone());
                    set_state(&states, "rules", "running", None);
                    handles.push(tokio::spawn(async move {
                        if let Err(e) = engine.run(rx, sink, c).await {
                            set_state(&states, "rules", "failed", Some(format!("{e:#}")));
                        }
                    }));
                }
                Some(Err(e)) => set_state(&deps.states, "rules", "failed", Some(format!("{e:#}"))),
                None => set_state(&deps.states, "rules", "failed", Some("no ruleset".into())),
            }
        }

        let mut execs = None;
        let mut notify = None;
        if src.vulns {
            match check_root_access() {
                Ok(()) => {
                    let (ctx, crx) = mpsc::channel(256);
                    let (etx, erx) = mpsc::channel::<ExecObservation>(1024);
                    // Inventory only: matching happens in mlab, never from the node.
                    let watcher = VulnWatcher::new(
                        None,
                        Cache::new(None, Duration::ZERO, false),
                        LangLimits::default(),
                    )
                    .with_inventory_sink(deps.inventories.clone());
                    let (sink, c, states) =
                        (deps.sink.clone(), cancel.clone(), deps.states.clone());
                    set_state(&states, "vulns", "running", None);
                    handles.push(tokio::spawn(async move {
                        if let Err(e) = watcher.run(crx, erx, sink, c).await {
                            set_state(&states, "vulns", "failed", Some(format!("{e:#}")));
                        }
                    }));
                    execs = Some(etx);
                    // The whole node is inventoried, not only pods started from now on.
                    notify = Some(PodNotify {
                        tx: ctx,
                        existing: true,
                        namespaces: eff.namespaces.clone(),
                    });
                }
                Err(e) => set_state(&deps.states, "vulns", "failed", Some(format!("{e:#}"))),
            }
        }
        if src.ebpf || notify.is_some() {
            let resolver = NodePodResolver::spawn_with_notify(
                deps.client.clone(),
                Some(deps.node.clone()),
                notify,
                cancel.clone(),
            );
            if src.ebpf {
                let kinds = eff
                    .config
                    .kinds
                    .iter()
                    .filter_map(|k| <ProbeKind as clap::ValueEnum>::from_str(k, true).ok())
                    .collect();
                let config = ProbeConfig {
                    kinds: KindFilter::new(kinds),
                };
                sources.push(("ebpf", Box::new(EbpfSource::new(config, resolver, scan_tx))));
            }
        }

        for (name, source) in sources {
            let (sink, c, states) = (deps.sink.clone(), cancel.clone(), deps.states.clone());
            set_state(&states, name, "running", None);
            handles.push(tokio::spawn(async move {
                match source.run(sink, c).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!(source = name, "source failed: {e:#}");
                        set_state(&states, name, "failed", Some(format!("{e:#}")));
                    }
                }
            }));
        }
        Self {
            cancel,
            handles,
            execs,
        }
    }

    /// Stop every source (5 s at most).
    pub async fn stop(self) {
        self.cancel.cancel();
        let all = futures::future::join_all(self.handles);
        if tokio::time::timeout(Duration::from_secs(5), all)
            .await
            .is_err()
        {
            tracing::warn!("pipeline did not stop within 5s");
        }
    }
}
