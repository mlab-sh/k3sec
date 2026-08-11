//! The probe → scan-engine bridge type.
//!
//! The eBPF probe observes activity but must never block on scanning. When a
//! scannable event occurs (a process exec, a write to a sensitive file), the
//! probe pushes a lightweight [`ScanRequest`] into a queue; the detection engine
//! (crate `k3sec-engine`) drains it asynchronously, reads the artifact bytes, and
//! runs YARA. The request carries only *references* (a pid, a path) plus the pod
//! context, never the bytes, so enqueuing is cheap.
//!
//! Defined in core so the probe can produce requests and the engine can consume
//! them without either depending on the other.

use tokio::sync::mpsc;

use crate::resolver::ContainerInfo;

/// What triggered a scan; determines which artifact the engine reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTrigger {
    /// A process exec, scan the executed binary (`/proc/<pid>/exe`).
    Exec,
    /// A write to a sensitive file, scan the file after it settles.
    FileWrite,
}

impl ScanTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanTrigger::Exec => "exec",
            ScanTrigger::FileWrite => "file_write",
        }
    }
}

/// A request to scan an artifact, with the pod context to attach to any hit.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub trigger: ScanTrigger,
    /// The process that produced the event, used to reach the artifact via
    /// `/proc/<pid>/…` inside the container's mount namespace.
    pub pid: u32,
    /// For [`ScanTrigger::FileWrite`], the in-container path that was written.
    pub path: Option<String>,
    /// Pod/namespace/container context, if it was resolved (`None` = unresolved).
    pub container: Option<ContainerInfo>,
    /// The originating process `comm`, for readable detection messages.
    pub comm: String,
}

/// Channel the probe uses to hand scan requests to the engine.
pub type ScanRequestSink = mpsc::Sender<ScanRequest>;
