//! `watch --vulns`: inventory + match each new image in the background and
//! stream the results as `source: "vuln"` events.
//!
//! ```text
//! pod watch ──PodContainer──▶ VulnWatcher ──spawn──▶ scan + match (bounded) ──▶ sink
//! probe exec ──ExecObservation──▶ VulnWatcher: dormant → loaded ──────────────▶ sink
//! ```
//!
//! Each digest is inventoried once. With `--ebpf`, every exec of a binary
//! owned by a dormant package flips it to loaded and emits its vulns then:
//! the "it's running now" moment is the one worth alerting on.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use k3sec_core::{EventSink, PodContainer};

use crate::cache::Cache;
use crate::events::{finding_event, summary_event};
use crate::inventory::{scan_image, ImageScan};
use crate::lang::LangLimits;
use crate::model::Reachability;
use crate::procfs::pids_by_container;
use crate::reach::mark_loaded;
use crate::rootfs::Rootfs;
use crate::vuln::{match_images, ImageVulns, VulnSource};

/// Let a just-started container map its libraries before the snapshot.
const SETTLE: Duration = Duration::from_secs(3);
const SCAN_ATTEMPTS: u32 = 3;
/// Images inventoried at once (each one reads a whole rootfs).
const MAX_PARALLEL_SCANS: usize = 2;

/// A process exec seen by the eBPF probe.
#[derive(Debug, Clone)]
pub struct ExecObservation {
    /// Full container runtime id.
    pub container_id: String,
    pub pid: u32,
    /// The exec'd path, as passed to `execve`.
    pub path: String,
}

pub struct VulnWatcher {
    source: Arc<dyn VulnSource>,
    cache: Cache,
    limits: LangLimits,
}

struct Tracked {
    scan: ImageScan,
    vulns: ImageVulns,
}

type Done = (String, Option<(ImageScan, ImageVulns)>);

impl VulnWatcher {
    pub fn new(source: Arc<dyn VulnSource>, cache: Cache, limits: LangLimits) -> Self {
        Self {
            source,
            cache,
            limits,
        }
    }

    pub async fn run(
        self,
        mut containers: mpsc::Receiver<PodContainer>,
        mut execs: mpsc::Receiver<ExecObservation>,
        sink: EventSink,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut images: HashMap<String, Tracked> = HashMap::new();
        let mut by_container: HashMap<String, String> = HashMap::new();
        // Containers waiting on an in-flight scan of their image.
        let mut pending: HashMap<String, Vec<PodContainer>> = HashMap::new();
        let (done_tx, mut done_rx) = mpsc::channel::<Done>(16);
        let permits = Arc::new(Semaphore::new(MAX_PARALLEL_SCANS));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                Some(c) = containers.recv() => {
                    let key = c.image_key().to_string();
                    if let Some(t) = images.get_mut(&key) {
                        by_container.insert(c.container_id.clone(), key);
                        t.scan.inventory.containers.push(c);
                    } else if let Some(waiting) = pending.get_mut(&key) {
                        waiting.push(c);
                    } else {
                        pending.insert(key.clone(), Vec::new());
                        tokio::spawn(scan_task(
                            key,
                            c,
                            self.source.clone(),
                            self.cache.clone(),
                            self.limits.clone(),
                            permits.clone(),
                            done_tx.clone(),
                        ));
                    }
                }
                Some((key, result)) = done_rx.recv() => {
                    let waiting = pending.remove(&key).unwrap_or_default();
                    let Some((mut scan, vulns)) = result else { continue };
                    scan.inventory.containers.extend(waiting);
                    for c in &scan.inventory.containers {
                        by_container.insert(c.container_id.clone(), key.clone());
                    }
                    let inv = &scan.inventory;
                    let mut events = vec![summary_event(inv, &vulns)];
                    events.extend(
                        vulns.findings.iter()
                            .filter(|f| f.reachability == Reachability::Loaded)
                            .map(|f| finding_event(inv, f)),
                    );
                    for ev in events {
                        if sink.send(ev).await.is_err() {
                            return Ok(()); // printer gone
                        }
                    }
                    images.insert(key, Tracked { scan, vulns });
                }
                Some(e) = execs.recv() => {
                    let Some(t) = by_container.get(&e.container_id).and_then(|k| images.get_mut(k)) else {
                        continue;
                    };
                    for ev in on_exec(t, &e) {
                        if sink.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                else => return Ok(()),
            }
        }
    }
}

/// Promote the packages owning the exec'd binary; events for their vulns.
fn on_exec(t: &mut Tracked, e: &ExecObservation) -> Vec<k3sec_core::SecEvent> {
    // The kernel's view of the binary (already canonical), else the argv path.
    let path = std::fs::read_link(format!("/proc/{}/exe", e.pid))
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .unwrap_or_else(|_| e.path.clone());
    if !path.starts_with('/') {
        return Vec::new();
    }
    let fs = Rootfs::of_pid(e.pid);
    let inv = &mut t.scan.inventory;
    let changed = mark_loaded(&mut inv.packages, &t.scan.index, &fs, [path.as_str()]);
    let mut events = Vec::new();
    for i in changed {
        let purl = &inv.packages[i].purl;
        for f in t.vulns.findings.iter_mut().filter(|f| &f.purl == purl) {
            f.reachability = Reachability::Loaded;
            events.push(finding_event(inv, f));
        }
    }
    events
}

async fn scan_task(
    key: String,
    first: PodContainer,
    source: Arc<dyn VulnSource>,
    cache: Cache,
    limits: LangLimits,
    permits: Arc<Semaphore>,
    done: mpsc::Sender<Done>,
) {
    let Ok(_permit) = permits.acquire_owned().await else {
        return;
    };
    tokio::time::sleep(SETTLE).await;
    let mut scan = None;
    for attempt in 1..=SCAN_ATTEMPTS {
        let c = first.clone();
        let limits = limits.clone();
        scan =
            tokio::task::spawn_blocking(move || scan_image(vec![c], &pids_by_container(), &limits))
                .await
                .ok()
                .flatten();
        if scan.is_some() || attempt == SCAN_ATTEMPTS {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let result = match scan {
        Some(scan) => {
            let vulns = match_images(
                source.as_ref(),
                &cache,
                std::slice::from_ref(&scan.inventory),
            )
            .await
            .pop()
            .unwrap_or_default();
            Some((scan, vulns))
        }
        None => {
            tracing::debug!(image = %key, pod = %first.pod, "no local process for container; not inventoried");
            None
        }
    };
    let _ = done.send((key, result)).await;
}
