//! Command-line surface and the `watch` orchestration.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use k3sec_core::{EventSource, OutputFormat, Printer};
use k3sec_k8s::{build_client, preflight, K8sEventSource, K8sLogSource, NodePodResolver};
use k3sec_probe::{EbpfSource, KindFilter, ProbeConfig, ProbeKind};

/// k3sec — runtime security for k3s clusters.
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

    /// Output format.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::default())]
    pub output: OutputFormat,
}

/// Entry point invoked by `main` after CLI parsing.
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Watch(args) => watch(cli.kubeconfig, args).await,
    }
}

async fn watch(kubeconfig: Option<PathBuf>, args: WatchArgs) -> Result<()> {
    if !args.kind.is_empty() && !args.ebpf {
        tracing::warn!("--kind has no effect without --ebpf; ignoring it");
    }

    // Established up-front so shutdown (and the pod resolver) share one signal.
    let cancel = CancellationToken::new();

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
    if args.ebpf {
        // The resolver watches pods (scoped to this node) so kernel events can
        // be tagged with pod/namespace context.
        let node = args
            .node
            .clone()
            .or_else(|| std::env::var("NODE_NAME").ok());
        let resolver = NodePodResolver::spawn(client.clone(), node, cancel.clone());
        let config = ProbeConfig {
            kinds: KindFilter::new(args.kind.clone()),
        };
        sources.push(Box::new(EbpfSource::new(config, resolver)));
    }

    tracing::info!(
        namespace = args.namespace.as_deref().unwrap_or("<all>"),
        logs = args.logs,
        ebpf = args.ebpf,
        rollback = args.rollback,
        output = ?args.output,
        sources = sources.len(),
        "connected to cluster, starting watch",
    );

    // One bounded channel funnels every producer into a single printer, so
    // concurrent events and log lines never interleave mid-line.
    let (tx, mut rx) = mpsc::channel(1024);
    let printer = Printer::new(args.output);

    let printer_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            printer.emit(&event);
        }
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
