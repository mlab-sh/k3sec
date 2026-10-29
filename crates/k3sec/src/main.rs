//! k3sec, runtime security CLI for k3s clusters.
//!
//! Connects to a cluster and streams normalized security events to the terminal
//! (pretty or NDJSON): Kubernetes events, pod logs (`--logs`), and kernel-level
//! runtime activity from the eBPF probe (`--ebpf`). All sources share the
//! [`k3sec_core::SecEvent`] envelope, so detection (M3) can plug in downstream.

mod cli;
mod vulns;

use clap::Parser;

#[tokio::main]
async fn main() {
    init_tracing();

    let cli = cli::Cli::parse();
    if let Err(err) = cli::run(cli).await {
        // Print the full error chain (anyhow) to stderr; stdout is reserved for
        // event/log output so JSON piping stays clean.
        tracing::error!("{err:#}");
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

/// Initialize internal logging on stderr. Level is controlled by `RUST_LOG`
/// (e.g. `RUST_LOG=k3sec=debug`); defaults to `info`.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
