//! Command-line surface and the `watch` orchestration.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use k3sec_core::{EventSource, OutputFormat, Printer, ScanRequest};
use k3sec_engine::{DetectionEngine, EngineConfig};
use k3sec_inventory::{check_root_access, ExecObservation, LangLimits, VulnWatcher};
use k3sec_k8s::{
    build_client, preflight, K8sEventSource, K8sLogSource, NodePodResolver, PodNotify,
};
use k3sec_probe::{EbpfSource, KindFilter, ProbeConfig, ProbeKind};

use crate::vulns::{InventoryArgs, MlabArgs, VulnsArgs};

/// k3sec, runtime security for k3s clusters.
#[derive(Debug, Parser)]
#[command(name = "k3sec", version, about, long_about = None)]
pub struct Cli {
    /// Path to a kubeconfig file (defaults to $KUBECONFIG or ~/.kube/config).
    #[arg(long, global = true, value_name = "PATH")]
    pub kubeconfig: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Stream cluster events, pod logs, and eBPF runtime events in real time.
    Watch(WatchArgs),
    /// Inventory the packages of every container running on this node, with
    /// their loaded/dormant reachability (one-shot; needs root).
    Inventory(InventoryArgs),
    /// Inventory + match vulnerabilities via vuln.mlab.sh, loaded code first
    /// (one-shot; needs root).
    Vulns(VulnsArgs),
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Only watch a single namespace (defaults to all namespaces).
    #[arg(short = 'n', long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Also follow logs from every pod container.
    #[arg(long)]
    pub logs: bool,

    /// Enable the eBPF probe (kernel exec/connect/file-write events).
    /// Requires root, or CAP_BPF + CAP_PERFMON.
    #[arg(long)]
    pub ebpf: bool,

    /// Restrict eBPF events to these kinds (comma-separated). Default: all.
    #[arg(long, value_enum, value_delimiter = ',', value_name = "KIND")]
    pub kind: Vec<ProbeKind>,

    /// Node name to scope pod resolution for --ebpf (defaults to $NODE_NAME,
    /// else all pods). Matched against `spec.nodeName`.
    #[arg(long, value_name = "NAME")]
    pub node: Option<String>,

    /// Replay the existing backlog (k8s events, sorted by time) before going
    /// live. Off by default: k3sec is realtime-only.
    #[arg(long)]
    pub rollback: bool,

    /// YARA rules: a `.yar`/`.yara` file or a directory (scanned recursively).
    /// Enables scanning of exec'd binaries and writes to sensitive paths.
    /// Requires --ebpf.
    #[arg(long, value_name = "PATH")]
    pub rules: Option<PathBuf>,

    /// Skip scanning artifacts larger than this many bytes.
    #[arg(long, value_name = "BYTES", default_value_t = EngineConfig::DEFAULT_MAX_SCAN_SIZE)]
    pub max_scan_size: u64,

    /// YARA scan worker threads (default: number of CPUs).
    #[arg(long, value_name = "N")]
    pub scan_workers: Option<usize>,

    /// Inventory + vulnerability-match each new pod image in the background,
    /// emitting `source: "vuln"` events (needs root). Existing pods only with
    /// --rollback. With --ebpf, exec'd binaries promote dormant packages.
    #[arg(long)]
    pub vulns: bool,

    #[command(flatten)]
    pub mlab: MlabArgs,

    /// Output format.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::default())]
    pub output: OutputFormat,
}

/// Entry point invoked by `main` after CLI parsing.
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Watch(args) => watch(cli.kubeconfig, args).await,
        Command::Inventory(args) => crate::vulns::inventory(cli.kubeconfig, args).await,
        Command::Vulns(args) => crate::vulns::vulns(cli.kubeconfig, args).await,
    }
}

async fn watch(kubeconfig: Option<PathBuf>, args: WatchArgs) -> Result<()> {
    if !args.kind.is_empty() && !args.ebpf {
        tracing::warn!("--kind has no effect without --ebpf; ignoring it");
    }
    if args.rules.is_some() && !args.ebpf {
        tracing::warn!("--rules has no effect without --ebpf; scanning is driven by eBPF events");
    }

    // Established up-front so shutdown (and the pod resolver) share one signal.
    let cancel = CancellationToken::new();

    // Compile the YARA ruleset FIRST (local, cheap): a bad ruleset must fail
    // fast before we touch the cluster. `scan_tx` is handed to the probe; the
    // engine (in `engine_slot`) is spawned once the printer sink exists.
    let mut engine_slot: Option<(DetectionEngine, mpsc::Receiver<ScanRequest>)> = None;
    let scan_tx = if args.ebpf && args.rules.is_some() {
        let rules_path = args.rules.clone().expect("checked is_some");
        let workers = args
            .scan_workers
            .unwrap_or_else(EngineConfig::default_workers);
        let engine =
            DetectionEngine::compile(&rules_path, EngineConfig::new(args.max_scan_size, workers))?;
        let (stx, srx) = mpsc::channel::<ScanRequest>(1024);
        engine_slot = Some((engine, srx));
        Some(stx)
    } else {
        None
    };

    // Same fail-fast for --vulns: privileges and a valid --mlab-url.
    let vuln_client = if args.vulns {
        check_root_access()?;
        Some(args.mlab.client()?)
    } else {
        None
    };

    // Establish and validate the connection up-front so kubeconfig/RBAC errors
    // are reported clearly before any long-running watch starts.
    let client = build_client(kubeconfig.as_deref()).await?;
    preflight(&client).await?;

    // Assemble the active sources. The output pipeline treats them uniformly.
    let mut sources: Vec<Box<dyn EventSource>> = Vec::new();
    sources.push(Box::new(K8sEventSource::new(
        client.clone(),
        args.namespace.clone(),
        args.rollback,
    )));
    if args.logs {
        sources.push(Box::new(K8sLogSource::new(
            client.clone(),
            args.namespace.clone(),
        )));
    }
    let node = args
        .node
        .clone()
        .or_else(|| std::env::var("NODE_NAME").ok());
    // --vulns learns about new containers from the resolver's pod watch.
    let mut vuln_slot = None;
    let notify = vuln_client.map(|client| {
        let (ctx, crx) = mpsc::channel(256);
        let (etx, erx) = mpsc::channel::<ExecObservation>(1024);
        let watcher = VulnWatcher::new(
            Some(std::sync::Arc::new(client)),
            args.mlab.cache(),
            LangLimits::default(),
        );
        vuln_slot = Some((watcher, crx, erx, etx));
        PodNotify {
            tx: ctx,
            existing: args.rollback,
            namespaces: args.namespace.clone().into_iter().collect(),
        }
    });
    let resolver = (args.ebpf || args.vulns)
        .then(|| NodePodResolver::spawn_with_notify(client.clone(), node, notify, cancel.clone()));
    if let Some(resolver) = resolver.filter(|_| args.ebpf) {
        // The resolver watches pods (scoped to this node) so kernel events can
        // be tagged with pod/namespace context.
        let config = ProbeConfig {
            kinds: KindFilter::new(args.kind.clone()),
        };
        sources.push(Box::new(EbpfSource::new(config, resolver, scan_tx)));
    }

    tracing::info!(
        namespace = args.namespace.as_deref().unwrap_or("<all>"),
        logs = args.logs,
        ebpf = args.ebpf,
        rules = args.rules.is_some(),
        vulns = args.vulns,
        rollback = args.rollback,
        output = ?args.output,
        sources = sources.len(),
        "connected to cluster, starting watch",
    );

    // One bounded channel funnels every producer into a single printer, so
    // concurrent events and log lines never interleave mid-line.
    let (tx, mut rx) = mpsc::channel(1024);
    let printer = Printer::new(args.output);

    // Exec events also feed --vulns reachability (best effort, never blocks).
    let exec_tx = vuln_slot.as_ref().map(|(_, _, _, etx)| etx.clone());
    let printer_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Some((etx, obs)) = exec_tx.as_ref().zip(ExecObservation::from_event(&event)) {
                let _ = etx.try_send(obs);
            }
            printer.emit(&event);
        }
    });

    let vuln_handle = vuln_slot.map(|(watcher, crx, erx, _)| {
        let tx = tx.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = watcher.run(crx, erx, tx, cancel).await {
                tracing::error!("vuln watcher failed: {e:#}");
            }
        })
    });

    // Spawn the YARA engine (if enabled): it drains scan requests and emits
    // detection events into the same sink.
    let engine_handle = engine_slot.map(|(engine, scan_rx)| {
        let tx = tx.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.run(scan_rx, tx, cancel).await {
                tracing::error!("detection engine failed: {e:#}");
            }
        })
    });

    // Run every source concurrently into the shared sink.
    let mut source_handles = Vec::with_capacity(sources.len());
    for source in sources {
        let name = source.name();
        let tx = tx.clone();
        let cancel = cancel.clone();
        source_handles.push(tokio::spawn(async move {
            if let Err(e) = source.run(tx, cancel).await {
                tracing::error!(source = name, "source failed: {e:#}");
            }
        }));
    }

    // Drop our own sender so the printer stops once all producers are gone.
    drop(tx);

    // Run until Ctrl+C, then cancel and drain.
    tokio::signal::ctrl_c().await?;
    tracing::info!("received Ctrl+C, shutting down gracefully");
    cancel.cancel();

    let shutdown = async {
        for handle in source_handles {
            let _ = handle.await;
        }
        // Sources are gone (probe dropped its scan sender); the engine drains and exits.
        if let Some(handle) = engine_handle {
            let _ = handle.await;
        }
        if let Some(handle) = vuln_handle {
            let _ = handle.await;
        }
        // Remaining sender clones are now dropped; the printer drains and returns.
        let _ = printer_handle.await;
    };
    if tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .is_err()
    {
        tracing::warn!("shutdown timed out; exiting anyway");
    }

    Ok(())
}
