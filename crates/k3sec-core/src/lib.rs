//! k3sec-core, the shared foundation every k3sec crate builds on.
//!
//! * [`event`], the generic [`SecEvent`] envelope (the cross-source contract).
//! * [`source`], the [`EventSource`] trait every collector implements.
//! * [`output`], pretty / NDJSON rendering, decoupled from any source.
//!
//! The output pipeline consumes [`SecEvent`]s and knows nothing about where they
//! came from: Kubernetes events, pod logs, or (from M2) the eBPF probe.

pub mod cgroup;
pub mod event;
pub mod output;
pub mod resolver;
pub mod scan;
pub mod source;
pub mod workload;

#[cfg(target_os = "linux")]
pub use cgroup::container_id_of_cgroup;
pub use cgroup::{container_id_from_cgroup, container_id_of_pid};
pub use event::{SecEvent, SecEventBuilder, Severity, Source};
pub use output::{OutputFormat, Printer};
pub use resolver::{ContainerInfo, ContainerResolver};
pub use scan::{ScanRequest, ScanRequestSink, ScanTrigger};
pub use source::{EventSink, EventSource};
pub use workload::{NodeVersions, PodContainer};
