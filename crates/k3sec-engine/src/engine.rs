//! The detection engine: async dispatch + a bounded pool of scan workers.
//!
//! Scanning must never sit on the probe's critical path, so the flow is:
//!
//! ```text
//! probe ──ScanRequest──▶ dispatcher ──▶ [bounded queue] ──▶ worker threads ──▶ sink
//! ```
//!
//! * The dispatcher (async) forwards `exec` scans immediately and debounces
//!   `file_write` scans (coalescing rapid writes to the same file).
//! * Workers are OS threads (scanning is CPU-bound and `yara_x::Scanner` is not
//!   `Send`), each owning one `Scanner` over the shared compiled rules.
//! * Reading the artifact is best-effort: too-big → skip, vanished pid → skip,
//!   any error → skip. A worker never panics on artifact data.

use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};
use tokio_util::sync::CancellationToken;
use yara_x::{Rules, Scanner};

use k3sec_core::{EventSink, ScanRequest, ScanTrigger};

use crate::detection::{detection_event, scan_bytes};
use crate::rules::RuleSet;
use crate::EngineConfig;

/// Scan outcome counters, logged on shutdown.
#[derive(Default)]
struct ScanStats {
    scanned: AtomicU64,
    hits: AtomicU64,
    clean: AtomicU64,
    too_big: AtomicU64,
    gone: AtomicU64,
    errors: AtomicU64,
}

/// The compiled ruleset plus scan configuration.
pub struct DetectionEngine {
    ruleset: RuleSet,
    config: EngineConfig,
}

impl DetectionEngine {
    /// Compile the ruleset (fail-fast) and prepare the engine.
    pub fn compile(rules_path: &Path, config: EngineConfig) -> Result<Self> {
        let ruleset = RuleSet::compile(rules_path)?;
        tracing::info!(
            rules = ruleset.rule_count(),
            files = ruleset.file_count(),
            workers = config.workers,
            "compiled YARA ruleset",
        );
        Ok(Self { ruleset, config })
    }

    pub fn rule_count(&self) -> usize {
        self.ruleset.rule_count()
    }

    /// Drain scan requests until `cancel`, scanning on the worker pool and
    /// emitting detection events into `sink`.
    pub async fn run(
        self,
        mut scan_rx: mpsc::Receiver<ScanRequest>,
        sink: EventSink,
        cancel: CancellationToken,
    ) -> Result<()> {
        let stats = Arc::new(ScanStats::default());
        let (work_tx, work_rx) = flume::bounded::<ScanRequest>(self.config.workers * 4);

        // Worker threads, each with its own Scanner over the shared rules.
        let mut workers = Vec::with_capacity(self.config.workers);
        for _ in 0..self.config.workers {
            let rules = self.ruleset.rules();
            let rx = work_rx.clone();
            let sink = sink.clone();
            let stats = stats.clone();
            let max = self.config.max_scan_size;
            workers.push(std::thread::spawn(move || {
                worker_loop(rules, rx, sink, stats, max)
            }));
        }
        drop(work_rx);

        // Dispatch: exec immediately, file_write debounced.
        let debounce = self.config.debounce;
        let mut pending: HashMap<String, (Instant, ScanRequest)> = HashMap::new();
        let mut ticker = interval((debounce / 2).max(Duration::from_millis(50)));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                maybe = scan_rx.recv() => match maybe {
                    Some(req) => match req.trigger {
                        ScanTrigger::Exec => {
                            if work_tx.send_async(req).await.is_err() {
                                break;
                            }
                        }
                        ScanTrigger::FileWrite => {
                            pending.insert(debounce_key(&req), (Instant::now(), req));
                        }
                    },
                    None => break, // probe gone
                },
                _ = ticker.tick() => {
                    let now = Instant::now();
                    let due: Vec<String> = pending
                        .iter()
                        .filter(|(_, (t, _))| now.duration_since(*t) >= debounce)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in due {
                        if let Some((_, req)) = pending.remove(&k) {
                            if work_tx.send_async(req).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Flush whatever is still pending, then let workers finish and join.
        for (_, (_, req)) in pending.drain() {
            let _ = work_tx.send_async(req).await;
        }
        drop(work_tx);
        for w in workers {
            let _ = w.join();
        }
        report_stats(&stats);
        Ok(())
    }
}

fn worker_loop(
    rules: Arc<Rules>,
    rx: flume::Receiver<ScanRequest>,
    sink: EventSink,
    stats: Arc<ScanStats>,
    max_scan_size: u64,
) {
    // Reused across every job on this thread, rules are never recompiled.
    let mut scanner = Scanner::new(&rules);

    while let Ok(req) = rx.recv() {
        let Some(artifact) = artifact_path(&req) else {
            continue;
        };
        match read_capped(&artifact, max_scan_size) {
            Ok(Some(bytes)) => {
                stats.scanned.fetch_add(1, Ordering::Relaxed);
                let hits = scan_bytes(&mut scanner, &bytes);
                if hits.is_empty() {
                    stats.clean.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.hits.fetch_add(1, Ordering::Relaxed);
                    let ev = detection_event(&hits, &req, &artifact.to_string_lossy());
                    if sink.blocking_send(ev).is_err() {
                        break; // printer gone
                    }
                }
            }
            Ok(None) => {
                stats.too_big.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Process/file vanished before we could read it, expected race.
                stats.gone.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Host-visible path of the artifact to scan, inside the container's mount ns.
fn artifact_path(req: &ScanRequest) -> Option<PathBuf> {
    match req.trigger {
        // The executed binary, readable even if unlinked, while the pid lives.
        ScanTrigger::Exec => Some(PathBuf::from(format!("/proc/{}/exe", req.pid))),
        // The written file, resolved within the container's root.
        ScanTrigger::FileWrite => {
            let path = req.path.as_ref()?;
            let rel = path.trim_start_matches('/');
            Some(PathBuf::from(format!("/proc/{}/root/{rel}", req.pid)))
        }
    }
}

/// Read up to `max` bytes; `Ok(None)` if the artifact exceeds the cap.
fn read_capped(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut file = File::open(path)?;
    if let Ok(meta) = file.metadata() {
        if meta.len() > max {
            return Ok(None);
        }
    }
    let mut buf = Vec::new();
    file.by_ref().take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// Debounce key: coalesce rapid writes to the same file within one container.
fn debounce_key(req: &ScanRequest) -> String {
    let scope = req
        .container
        .as_ref()
        .map(|c| format!("{}/{}", c.namespace, c.pod))
        .unwrap_or_else(|| format!("pid{}", req.pid));
    format!("{scope}:{}", req.path.as_deref().unwrap_or(""))
}

fn report_stats(stats: &ScanStats) {
    tracing::info!(
        scanned = stats.scanned.load(Ordering::Relaxed),
        hits = stats.hits.load(Ordering::Relaxed),
        clean = stats.clean.load(Ordering::Relaxed),
        too_big = stats.too_big.load(Ordering::Relaxed),
        gone = stats.gone.load(Ordering::Relaxed),
        errors = stats.errors.load(Ordering::Relaxed),
        "YARA engine scan counters",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use k3sec_core::ScanTrigger;

    fn req(trigger: ScanTrigger, pid: u32, path: Option<&str>) -> ScanRequest {
        ScanRequest {
            trigger,
            pid,
            path: path.map(String::from),
            container: None,
            comm: "x".into(),
        }
    }

    #[test]
    fn exec_artifact_is_proc_exe() {
        let p = artifact_path(&req(ScanTrigger::Exec, 42, None)).unwrap();
        assert_eq!(p, PathBuf::from("/proc/42/exe"));
    }

    #[test]
    fn file_write_artifact_is_under_proc_root() {
        let p = artifact_path(&req(ScanTrigger::FileWrite, 42, Some("/etc/passwd"))).unwrap();
        assert_eq!(p, PathBuf::from("/proc/42/root/etc/passwd"));
    }

    #[test]
    fn read_capped_rejects_oversized() {
        let dir = std::env::temp_dir().join(format!("k3sec-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("big.bin");
        std::fs::write(&f, vec![0u8; 100]).unwrap();
        assert!(read_capped(&f, 10).unwrap().is_none());
        assert_eq!(read_capped(&f, 1000).unwrap().unwrap().len(), 100);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_capped_missing_file_is_not_found() {
        let err = read_capped(Path::new("/proc/nonexistent-pid-999999/exe"), 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}
