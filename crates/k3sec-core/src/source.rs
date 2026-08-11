//! The [`EventSource`] abstraction.
//!
//! A source is anything that produces [`SecEvent`]s over time: the Kubernetes
//! events watch, the pod-log follower, or the eBPF probe. Each one runs its own
//! collection loop and pushes events into a shared [`EventSink`]; a single
//! printer task drains that sink. This keeps the output pipeline completely
//! source-agnostic, adding a new source never touches rendering.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::event::SecEvent;

/// The channel producers use to hand events to the printer task.
///
/// A single bounded channel funnels every source into one printer so that
/// concurrent producers never interleave a half-written line.
pub type EventSink = mpsc::Sender<SecEvent>;

/// A producer of [`SecEvent`]s.
///
/// Implementations own their reconnection / retry strategy and run until
/// `cancel` fires. Returning `Ok(())` means a clean shutdown; `Err` means the
/// source failed to start or hit an unrecoverable error (the CLI logs it and
/// keeps the other sources running).
#[async_trait::async_trait]
pub trait EventSource: Send {
    /// Stable short name, used in logs (e.g. `"k8s-events"`, `"ebpf"`).
    fn name(&self) -> &'static str;

    /// Run the source to completion, emitting into `sink` until `cancel` fires.
    async fn run(self: Box<Self>, sink: EventSink, cancel: CancellationToken)
        -> anyhow::Result<()>;
}
