//! `k3sec inventory` and `k3sec vulns`: one-shot, runtime-aware inventory and
//! vulnerability matching of the containers running on this node.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;

use k3sec_core::{NodeVersions, OutputFormat};
use k3sec_inventory::render::{self, Filter};
use k3sec_inventory::{
    check_root_access, group_by_image, match_images, node_inventory, pids_by_container, scan_image,
    Cache, ImageInventory, LangLimits, MlabClient, VulnSeverity,
};
use k3sec_k8s::{build_client, list_node_containers, node_versions, preflight};

/// What to inventory (shared by `inventory` and `vulns`).
#[derive(Debug, Args)]
pub struct ScopeArgs {
    /// Only one namespace (defaults to all namespaces).
    #[arg(short = 'n', long, value_name = "NS")]
    pub namespace: Option<String>,

    /// This node's name (defaults to $NODE_NAME; else every pod is listed and
    /// those without a process on this host are skipped).
    #[arg(long, value_name = "NAME")]
    pub node: Option<String>,

    /// Also match the node kernel by CPE against NVD. Off by default: NVD
    /// ignores distro backports, so this yields thousands of hits.
    #[arg(long)]
    pub match_kernel: bool,

    /// Output format.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::default())]
    pub output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct InventoryArgs {
    #[command(flatten)]
    pub scope: ScopeArgs,

    /// Write one CycloneDX JSON SBOM per image digest into this directory.
    #[arg(long, value_name = "DIR")]
    pub sbom: Option<PathBuf>,
}

/// vuln.mlab.sh connection + cache (shared by `vulns` and `watch --vulns`).
#[derive(Debug, Args)]
pub struct MlabArgs {
    /// vuln.mlab.sh base URL (or an on-prem mlab). API key: $MLAB_API_KEY.
    #[arg(long, value_name = "URL", default_value = MlabClient::DEFAULT_URL)]
    pub mlab_url: String,

    /// Ignore cached results (fresh results still refresh the cache).
    #[arg(long)]
    pub no_cache: bool,

    /// How long cached results per image digest stay valid, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = Cache::DEFAULT_TTL.as_secs())]
    pub cache_ttl: u64,
}

impl MlabArgs {
    pub fn client(&self) -> Result<MlabClient> {
        MlabClient::new(&self.mlab_url, std::env::var("MLAB_API_KEY").ok())
    }

    pub fn cache(&self) -> Cache {
        Cache::new(
            Cache::default_dir(),
            Duration::from_secs(self.cache_ttl),
            !self.no_cache,
        )
    }
}

#[derive(Debug, Args)]
pub struct VulnsArgs {
    #[command(flatten)]
    pub scope: ScopeArgs,

    #[command(flatten)]
    pub mlab: MlabArgs,

    /// Hide findings below this severity.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    pub min_severity: Option<VulnSeverity>,

    /// Only vulns in code that is loaded in memory.
    #[arg(long)]
    pub only_loaded: bool,

    /// Only vulns in CISA / EU KEV (known exploited).
    #[arg(long)]
    pub kev_only: bool,
}

pub async fn inventory(kubeconfig: Option<PathBuf>, args: InventoryArgs) -> Result<()> {
    let (node, images) = collect(kubeconfig, &args.scope).await?;
    if let Some(dir) = &args.sbom {
        for inv in images.iter().filter(|i| !i.containers.is_empty()) {
            let path = k3sec_inventory::sbom::write(dir, inv)?;
            tracing::info!(image = %inv.image, path = %path.display(), "wrote SBOM");
        }
    }
    let out = match args.scope.output {
        OutputFormat::Pretty => render::inventory_pretty(node.as_ref(), &images, color()),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&render::inventory_json(node.as_ref(), &images))? + "\n"
        }
    };
    print(&out)
}

pub async fn vulns(kubeconfig: Option<PathBuf>, args: VulnsArgs) -> Result<()> {
    let client = args.mlab.client()?;
    let (node, mut images) = collect(kubeconfig, &args.scope).await?;
    if let Some(n) = &node {
        images.push(node_inventory(n, args.scope.match_kernel));
    }
    let vulns = match_images(&client, &args.mlab.cache(), &images).await;
    let results: Vec<_> = images.iter().zip(vulns.iter()).collect();
    let filter = Filter {
        min_severity: args.min_severity,
        only_loaded: args.only_loaded,
        kev_only: args.kev_only,
    };
    let out = match args.scope.output {
        OutputFormat::Pretty => render::vulns_pretty(node.as_ref(), &results, &filter, color()),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&render::vulns_json(node.as_ref(), &results, &filter))?
                + "\n"
        }
    };
    print(&out)
}

/// List this node's containers, then inventory each image once.
async fn collect(
    kubeconfig: Option<PathBuf>,
    scope: &ScopeArgs,
) -> Result<(Option<NodeVersions>, Vec<ImageInventory>)> {
    // Local and cheap: fail on missing privileges before touching the cluster.
    check_root_access()?;
    let client = build_client(kubeconfig.as_deref()).await?;
    preflight(&client).await?;

    let node_name = scope
        .node
        .clone()
        .or_else(|| std::env::var("NODE_NAME").ok());
    let containers =
        list_node_containers(&client, node_name.as_deref(), scope.namespace.as_deref()).await?;
    let node = match node_versions(&client, node_name.as_deref()).await {
        Ok(n) => Some(n),
        Err(e) => {
            tracing::warn!("node versions unavailable, node stack not matched: {e:#}");
            None
        }
    };

    let total = containers.len();
    let images = tokio::task::spawn_blocking(move || {
        let pids = pids_by_container();
        tracing::debug!(containers_with_pids = pids.len(), "scanned /proc");
        group_by_image(containers)
            .into_iter()
            .filter_map(|group| scan_image(group, &pids, &LangLimits::default()))
            .map(|s| s.inventory)
            .collect::<Vec<_>>()
    })
    .await
    .context("inventory task failed")?;
    let local: usize = images.iter().map(|i| i.containers.len()).sum();
    tracing::info!(
        images = images.len(),
        containers = local,
        skipped = total - local.min(total),
        "inventoried running containers (skipped = no process on this host)"
    );
    Ok((node, images))
}

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn print(s: &str) -> Result<()> {
    match std::io::stdout().lock().write_all(s.as_bytes()) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}
