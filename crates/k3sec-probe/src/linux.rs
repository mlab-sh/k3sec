//! Linux eBPF probe implementation (aya).
//!
//! Placeholder scaffolding — the aya loader, ring-buffer reader, and
//! cgroup→pod enrichment land in M2/Phase 1. Compiled only under
//! `cfg(all(target_os = "linux", feature = "ebpf"))`.

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use k3sec_core::EventSink;

use crate::ProbeConfig;

pub async fn run(_config: ProbeConfig, _sink: EventSink, _cancel: CancellationToken) -> Result<()> {
    anyhow::bail!("eBPF probe: Linux implementation not wired yet (Phase 1)")
}
