//! Live multi-pod log following.
//!
//! A pod watcher discovers pods (in one namespace or all). For every container
//! that has started, we spawn a task that follows its log stream and forwards
//! each line as a [`SecEvent`]. Tasks dedupe on `namespace/pod/container` so a
//! container is only ever followed once at a time; when its stream ends (the
//! container stopped) or the command is cancelled, the task exits and the slot
//! frees up so a restart can be picked up again.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::{AsyncBufReadExt, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::LogParams;
use kube::runtime::watcher;
use kube::runtime::watcher::Event as WatchEvent;
use kube::{Api, Client};
use tokio_util::sync::CancellationToken;

use crate::client::Backoff;
use k3sec_core::{EventSink, EventSource, SecEvent, Severity, Source};

/// Follows logs from every started container across one namespace or all of them.
///
/// Logs are always realtime (only new lines, no historical replay), `--rollback`
/// affects Kubernetes events, not logs.
pub struct K8sLogSource {
    client: Client,
    namespace: Option<String>,
}

impl K8sLogSource {
    pub fn new(client: Client, namespace: Option<String>) -> Self {
        Self { client, namespace }
    }
}

#[async_trait]
impl EventSource for K8sLogSource {
    fn name(&self) -> &'static str {
        "k8s-logs"
    }

    async fn run(self: Box<Self>, sink: EventSink, cancel: CancellationToken) -> Result<()> {
        follow(self.client, self.namespace, sink, cancel).await
    }
}

/// Discover pods and follow their container logs until `cancel` fires.
///
/// `namespace = None` follows pods across all namespaces.
async fn follow(
    client: Client,
    namespace: Option<String>,
    sink: EventSink,
    cancel: CancellationToken,
) -> Result<()> {
    let followed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut backoff = Backoff::default();

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        match discover_once(
            &client,
            namespace.as_deref(),
            &sink,
            &cancel,
            &followed,
            &mut backoff,
        )
        .await
        {
            Ok(()) => return Ok(()), // clean cancellation
            Err(e) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %e, "pod watch dropped, reconnecting in {delay:?}");
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

async fn discover_once(
    client: &Client,
    namespace: Option<&str>,
    sink: &EventSink,
    cancel: &CancellationToken,
    followed: &Arc<Mutex<HashSet<String>>>,
    backoff: &mut Backoff,
) -> Result<()> {
    let api: Api<Pod> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let mut stream = watcher(api, watcher::Config::default()).boxed();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            item = stream.next() => match item {
                Some(Ok(ev)) => {
                    backoff.reset();
                    match ev {
                        WatchEvent::Apply(pod) | WatchEvent::InitApply(pod) => {
                            spawn_container_tasks(client, &pod, sink, cancel, followed);
                        }
                        _ => {}
                    }
                }
                Some(Err(e)) => tracing::debug!(error = %e, "recoverable pod watcher error"),
                None => return Err(anyhow!("pod watch stream ended unexpectedly")),
            }
        }
    }
}

/// For each started container of `pod` not already followed, spawn a follow task.
fn spawn_container_tasks(
    client: &Client,
    pod: &Pod,
    sink: &EventSink,
    cancel: &CancellationToken,
    followed: &Arc<Mutex<HashSet<String>>>,
) {
    let Some(ns) = pod.metadata.namespace.clone() else {
        return;
    };
    let Some(pod_name) = pod.metadata.name.clone() else {
        return;
    };

    for container in started_containers(pod) {
        let key = format!("{ns}/{pod_name}/{container}");

        // Atomically claim the slot; skip if already being followed.
        {
            let mut set = followed.lock().expect("followed set poisoned");
            if !set.insert(key.clone()) {
                continue;
            }
        }

        let task = FollowTask {
            api: Api::namespaced(client.clone(), &ns),
            namespace: ns.clone(),
            pod: pod_name.clone(),
            container,
            key,
            sink: sink.clone(),
            cancel: cancel.clone(),
            followed: followed.clone(),
        };
        tokio::spawn(task.run());
    }
}

/// The state a single container-follow task needs to run and clean up after itself.
struct FollowTask {
    api: Api<Pod>,
    namespace: String,
    pod: String,
    container: String,
    key: String,
    sink: EventSink,
    cancel: CancellationToken,
    followed: Arc<Mutex<HashSet<String>>>,
}

impl FollowTask {
    async fn run(self) {
        let mut backoff = Backoff::new(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(15),
        );
        let mut transient_failures = 0u32;

        loop {
            if self.cancel.is_cancelled() {
                break;
            }

            match self.stream_once().await {
                // Stream ended cleanly: the container stopped. Nothing more to tail.
                Ok(()) => break,
                Err(e) => {
                    transient_failures += 1;
                    if transient_failures > 5 {
                        tracing::debug!(pod = %self.pod, container = %self.container, error = %e,
                            "giving up on container logs after repeated failures");
                        break;
                    }
                    let delay = backoff.next_delay();
                    tracing::debug!(pod = %self.pod, container = %self.container, error = %e,
                        "log stream error, retrying in {delay:?}");
                    tokio::select! {
                        _ = self.cancel.cancelled() => break,
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }

        // Release the slot so a future restart of this container can be followed.
        self.followed
            .lock()
            .expect("followed set poisoned")
            .remove(&self.key);
    }

    /// Open one follow stream and forward lines until it ends or errors.
    async fn stream_once(&self) -> Result<()> {
        let params = LogParams {
            container: Some(self.container.clone()),
            follow: true,
            // Live tail: don't replay historical logs, only stream new lines.
            tail_lines: Some(0),
            timestamps: true,
            ..Default::default()
        };

        let reader = self.api.log_stream(&self.pod, &params).await?;
        let mut lines = reader.lines();

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return Ok(()),
                next = lines.next() => match next {
                    Some(Ok(line)) => {
                        let ev = build_log_event(&self.namespace, &self.pod, &self.container, &line);
                        if self.sink.send(ev).await.is_err() {
                            return Ok(()); // printer gone
                        }
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()), // container stopped / stream closed
                }
            }
        }
    }
}

/// Build a [`SecEvent`] from one raw (timestamped) log line.
fn build_log_event(namespace: &str, pod: &str, container: &str, raw: &str) -> SecEvent {
    let (timestamp, message) = split_log_timestamp(raw);
    SecEvent::builder(Source::K8sLog, timestamp)
        .kind("log")
        .severity(Severity::Info)
        .namespace(namespace.to_string())
        .object(format!("{pod}/{container}"))
        .message(message)
        .meta("pod", pod.to_string())
        .meta("container", container.to_string())
        .build()
}

/// Container names whose logs exist yet (started or already terminated).
///
/// Skipping pending/never-started containers avoids churning follow tasks that
/// would only fail against `ContainerCreating`.
fn started_containers(pod: &Pod) -> Vec<String> {
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };
    status
        .container_statuses
        .iter()
        .flatten()
        .filter(|cs| {
            cs.started == Some(true)
                || cs
                    .state
                    .as_ref()
                    .map(|s| s.running.is_some() || s.terminated.is_some())
                    .unwrap_or(false)
        })
        .map(|cs| cs.name.clone())
        .collect()
}

/// Split a `--timestamps` log line into `(timestamp, message)`.
///
/// Kubernetes prefixes each line with an RFC3339 timestamp and a space. If the
/// prefix is missing or unparseable, fall back to now and keep the whole line.
fn split_log_timestamp(line: &str) -> (DateTime<Utc>, String) {
    if let Some((ts, rest)) = line.split_once(' ') {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
            return (parsed.with_timezone(&Utc), rest.to_string());
        }
    }
    (Utc::now(), line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateRunning, ContainerStateWaiting, ContainerStatus, PodStatus,
    };

    #[test]
    fn split_timestamp_parses_rfc3339_prefix() {
        let (ts, msg) = split_log_timestamp("2026-08-11T18:30:05.123456789Z hello world");
        assert_eq!(
            ts.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "2026-08-11T18:30:05"
        );
        assert_eq!(msg, "hello world");
    }

    #[test]
    fn split_timestamp_falls_back_on_plain_line() {
        let (_, msg) = split_log_timestamp("no timestamp here");
        assert_eq!(msg, "no timestamp here");
    }

    fn running_status(name: &str) -> ContainerStatus {
        ContainerStatus {
            name: name.to_string(),
            started: Some(true),
            state: Some(ContainerState {
                running: Some(ContainerStateRunning { started_at: None }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn started_containers_includes_running_skips_waiting() {
        let pod = Pod {
            status: Some(PodStatus {
                container_statuses: Some(vec![
                    running_status("nginx"),
                    ContainerStatus {
                        name: "sidecar".to_string(),
                        started: Some(false),
                        state: Some(ContainerState {
                            waiting: Some(ContainerStateWaiting {
                                reason: Some("ContainerCreating".to_string()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(started_containers(&pod), vec!["nginx".to_string()]);
    }

    #[test]
    fn started_containers_empty_without_status() {
        assert!(started_containers(&Pod::default()).is_empty());
    }

    #[test]
    fn line_event_carries_prefix_and_metadata() {
        let ev = build_log_event(
            "default",
            "nginx-abc",
            "nginx",
            "2026-08-11T18:30:05Z GET /healthz 200",
        );
        assert_eq!(ev.source, Source::K8sLog);
        assert_eq!(ev.location(), "default/nginx-abc/nginx");
        assert_eq!(ev.message, "GET /healthz 200");
        assert_eq!(
            ev.metadata.get("container").map(String::as_str),
            Some("nginx")
        );
        assert_eq!(
            ev.metadata.get("pod").map(String::as_str),
            Some("nginx-abc")
        );
    }
}
