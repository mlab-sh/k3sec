//! k3sec-engine, the YARA (yara-x) detection engine.
//!
//! Consumes [`ScanRequest`](k3sec_core::ScanRequest)s produced by the eBPF probe,
//! reads the referenced artifact (an executed binary, a written file), scans it
//! with a compiled ruleset, and emits a detection [`SecEvent`](k3sec_core::SecEvent)
//! for every match, all off the probe's critical path.
//!
//! Depends only on `k3sec-core` (plus `yara-x`); it knows nothing about
//! Kubernetes or eBPF.

pub mod detection;
pub mod engine;
pub mod rules;

use std::time::Duration;

pub use detection::{detection_event, scan_bytes, RuleHit};
pub use engine::DetectionEngine;
pub use rules::RuleSet;

/// Scan configuration.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Artifacts larger than this (bytes) are skipped.
    pub max_scan_size: u64,
    /// Number of scan worker threads.
    pub workers: usize,
    /// How long a written file must be quiet before it's scanned.
    pub debounce: Duration,
}

impl EngineConfig {
    /// Default max scan size: 32 MiB.
    pub const DEFAULT_MAX_SCAN_SIZE: u64 = 32 * 1024 * 1024;

    /// Build a config, clamping `workers` to at least 1.
    pub fn new(max_scan_size: u64, workers: usize) -> Self {
        Self {
            max_scan_size,
            workers: workers.max(1),
            debounce: Duration::from_millis(500),
        }
    }

    /// A sensible default worker count: the machine's parallelism.
    pub fn default_workers() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}
