//! k3sec-probe — the eBPF runtime [`EventSource`].
//!
//! Observes what processes actually do inside containers — `execve`, outbound
//! `connect`, and writes to sensitive paths — straight from the kernel, then
//! enriches each event with the pod/namespace it came from and emits a
//! [`SecEvent`](k3sec_core::SecEvent).
//!
//! The real probe (aya + a BPF ring buffer) is Linux-only and gated behind the
//! `ebpf` cargo feature. This crate always *compiles* — on macOS, or without the
//! feature, [`EbpfSource::run`] returns a clear error instead of failing to
//! build — so the rest of the workspace stays buildable everywhere.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use k3sec_core::{ContainerResolver, EventSink, EventSource};

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux;

/// A kind of kernel event the probe can emit.
///
/// The string forms (`exec`, `connect`, `file_write`) are exactly the
/// [`SecEvent::kind`](k3sec_core::SecEvent) values the probe produces, so
/// `--kind` filtering lines up 1:1 with what appears in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum ProbeKind {
    /// Process execution (`execve` / `execveat`).
    Exec,
    /// Outbound TCP connect (v4/v6).
    Connect,
    /// Write-open of a file under a sensitive path.
    FileWrite,
}

impl ProbeKind {
    /// The canonical `SecEvent.kind` string for this event kind.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeKind::Exec => "exec",
            ProbeKind::Connect => "connect",
            ProbeKind::FileWrite => "file_write",
        }
    }
}

/// Which [`ProbeKind`]s to emit. An empty filter means "all kinds".
#[derive(Debug, Clone, Default)]
pub struct KindFilter {
    kinds: Vec<ProbeKind>,
}

impl KindFilter {
    /// Build a filter from an explicit list. Empty ⇒ all kinds allowed.
    pub fn new(kinds: Vec<ProbeKind>) -> Self {
        Self { kinds }
    }

    /// Whether `kind` should be emitted.
    pub fn allows(&self, kind: ProbeKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }

    /// True when no kind is filtered out.
    pub fn allows_all(&self) -> bool {
        self.kinds.is_empty()
    }
}

/// Runtime configuration for the eBPF probe.
#[derive(Debug, Clone, Default)]
pub struct ProbeConfig {
    /// Which kinds of kernel events to surface.
    pub kinds: KindFilter,
}

/// The eBPF [`EventSource`]. See the module docs for platform/feature gating.
pub struct EbpfSource {
    config: ProbeConfig,
    resolver: Arc<dyn ContainerResolver>,
}

impl EbpfSource {
    /// `resolver` attaches pod/namespace context to each kernel event.
    pub fn new(config: ProbeConfig, resolver: Arc<dyn ContainerResolver>) -> Self {
        Self { config, resolver }
    }
}

#[async_trait]
impl EventSource for EbpfSource {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    async fn run(self: Box<Self>, sink: EventSink, cancel: CancellationToken) -> Result<()> {
        run_probe(self.config, self.resolver, sink, cancel).await
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn run_probe(
    config: ProbeConfig,
    resolver: Arc<dyn ContainerResolver>,
    sink: EventSink,
    cancel: CancellationToken,
) -> Result<()> {
    linux::run(config, resolver, sink, cancel).await
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
async fn run_probe(
    _config: ProbeConfig,
    _resolver: Arc<dyn ContainerResolver>,
    _sink: EventSink,
    _cancel: CancellationToken,
) -> Result<()> {
    anyhow::bail!(
        "eBPF probe unavailable: this binary was built without eBPF support. \
         Build on Linux with `--features ebpf`, and run as root (or with CAP_BPF+CAP_PERFMON)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_allows_everything() {
        let f = KindFilter::default();
        assert!(f.allows_all());
        assert!(f.allows(ProbeKind::Exec));
        assert!(f.allows(ProbeKind::Connect));
        assert!(f.allows(ProbeKind::FileWrite));
    }

    #[test]
    fn explicit_filter_restricts() {
        let f = KindFilter::new(vec![ProbeKind::Exec, ProbeKind::Connect]);
        assert!(!f.allows_all());
        assert!(f.allows(ProbeKind::Exec));
        assert!(f.allows(ProbeKind::Connect));
        assert!(!f.allows(ProbeKind::FileWrite));
    }

    #[test]
    fn kind_strings_match_secevent_contract() {
        assert_eq!(ProbeKind::Exec.as_str(), "exec");
        assert_eq!(ProbeKind::Connect.as_str(), "connect");
        assert_eq!(ProbeKind::FileWrite.as_str(), "file_write");
    }
}
