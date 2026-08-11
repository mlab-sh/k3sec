//! k3sec-core — the shared foundation every k3sec crate builds on.
//!
//! * [`event`] — the generic [`SecEvent`] envelope (the cross-source contract).
//! * [`source`] — the [`EventSource`] trait every collector implements.
//! * [`output`] — pretty / NDJSON rendering, decoupled from any source.
//!
//! The output pipeline consumes [`SecEvent`]s and knows nothing about where they
//! came from: Kubernetes events, pod logs, or (from M2) the eBPF probe.

pub mod event;
pub mod output;
pub mod source;

pub use event::{SecEvent, SecEventBuilder, Severity, Source};
pub use output::{OutputFormat, Printer};
pub use source::{EventSink, EventSource};
