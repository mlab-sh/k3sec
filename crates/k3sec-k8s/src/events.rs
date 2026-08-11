//! Live watch of core/v1 `Event` objects, as an [`EventSource`].
//!
//! Uses the Kubernetes watch API (via `kube::runtime::watcher`), no polling.
//! The watcher recovers from dropped connections on its own; we wrap it in an
//! additional backoff loop so a hard failure reconnects instead of aborting.
//!
//! **Realtime by default.** k3sec is a detection tool, not a history viewer, so
//! the initial `LIST` backlog the watcher replays is *dropped*, only changes
//! that happen after we connect are emitted. With `rollback = true` the existing
//! backlog is replayed once (sorted by timestamp) before switching to live.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Event as K8sEvent;
use kube::runtime::watcher;
use kube::runtime::watcher::Event as WatchEvent;
use kube::{Api, Client};
use tokio_util::sync::CancellationToken;

use crate::client::Backoff;
use k3sec_core::{EventSink, EventSource, SecEvent, Severity, Source};

/// Watches core/v1 `Event`s across one namespace or all of them.
pub struct K8sEventSource {
    client: Client,
    namespace: Option<String>,
    rollback: bool,
}

impl K8sEventSource {
    /// `namespace = None` watches all namespaces. `rollback` replays the
    /// existing backlog once before going live (default: realtime only).
    pub fn new(client: Client, namespace: Option<String>, rollback: bool) -> Self {
        Self {
            client,
            namespace,
            rollback,
        }
    }
}

#[async_trait]
impl EventSource for K8sEventSource {
    fn name(&self) -> &'static str {
        "k8s-events"
    }

    async fn run(self: Box<Self>, sink: EventSink, cancel: CancellationToken) -> Result<()> {
        watch(self.client, self.namespace, self.rollback, sink, cancel).await
    }
}

async fn watch(
    client: Client,
    namespace: Option<String>,
    rollback: bool,
    sink: EventSink,
    cancel: CancellationToken,
) -> Result<()> {
    let mut backoff = Backoff::default();
    // Persist across reconnects: the backlog (if any) is replayed only on the
    // first successful sync, never re-dumped on a later re-list.
    let mut first_sync_done = false;

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        match run_once(
            &client,
            namespace.as_deref(),
            rollback,
            &sink,
            &cancel,
            &mut backoff,
            &mut first_sync_done,
        )
        .await
        {
            Ok(()) => return Ok(()), // clean cancellation
            Err(e) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %e, "event watch dropped, reconnecting in {delay:?}");
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_once(
    client: &Client,
    namespace: Option<&str>,
    rollback: bool,
    sink: &EventSink,
    cancel: &CancellationToken,
    backoff: &mut Backoff,
    first_sync_done: &mut bool,
) -> Result<()> {
    let api: Api<K8sEvent> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let mut stream = watcher(api, watcher::Config::default().any_semantic()).boxed();

    // Only populated while replaying backlog (rollback && first sync).
    let mut backlog: Vec<SecEvent> = Vec::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            item = stream.next() => match item {
                Some(Ok(ev)) => {
                    backoff.reset();
                    match ev {
                        // Live change after the initial sync: always emitted.
                        WatchEvent::Apply(e) => {
                            if sink.send(to_sec_event(&e)).await.is_err() {
                                return Ok(()); // printer gone
                            }
                        }
                        // Part of the initial LIST backlog.
                        WatchEvent::InitApply(e) => {
                            if rollback && !*first_sync_done {
                                backlog.push(to_sec_event(&e));
                            }
                            // Realtime-only (or already synced): drop it.
                        }
                        WatchEvent::InitDone => {
                            if rollback && !*first_sync_done {
                                backlog.sort_by_key(|e| e.timestamp);
                                for ev in backlog.drain(..) {
                                    if sink.send(ev).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                            *first_sync_done = true;
                        }
                        _ => {}
                    }
                }
                // The watcher yields recoverable errors and keeps going.
                Some(Err(e)) => tracing::debug!(error = %e, "recoverable watcher error"),
                None => return Err(anyhow!("event watch stream ended unexpectedly")),
            }
        }
    }
}

/// Normalize a Kubernetes `Event` into the generic [`SecEvent`] envelope.
pub fn to_sec_event(e: &K8sEvent) -> SecEvent {
    let type_ = e.type_.as_deref().unwrap_or("Normal");
    let severity = Severity::from_k8s_type(type_);
    let reason = e.reason.clone().unwrap_or_default();
    let message = e.message.clone().unwrap_or_default();

    let namespace = e
        .metadata
        .namespace
        .clone()
        .or_else(|| e.involved_object.namespace.clone());

    let object = involved_object_ref(e);
    let timestamp = event_timestamp(e);

    let component = e
        .source
        .as_ref()
        .and_then(|s| s.component.clone())
        .or_else(|| e.reporting_component.clone())
        .unwrap_or_default();

    let mut builder = SecEvent::builder(Source::K8sEvent, timestamp)
        .kind(if reason.is_empty() {
            "Event".to_string()
        } else {
            reason.clone()
        })
        .severity(severity)
        .maybe_namespace(namespace)
        .message(message)
        .meta("type", type_)
        .meta("reason", reason)
        .meta("component", component);

    if let Some(obj) = object {
        builder = builder.object(obj);
    }
    if let Some(count) = e.count {
        builder = builder.meta("count", count.to_string());
    }
    if let Some(host) = e.source.as_ref().and_then(|s| s.host.clone()) {
        builder = builder.meta("host", host);
    }

    if let Ok(raw) = serde_json::to_value(e) {
        builder = builder.payload(raw);
    }

    builder.build()
}

/// `kind/name` for the involved object, kubectl-style (`pod/nginx`).
fn involved_object_ref(e: &K8sEvent) -> Option<String> {
    let name = e.involved_object.name.as_deref()?;
    let kind = e
        .involved_object
        .kind
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_else(|| "object".to_string());
    Some(format!("{kind}/{name}"))
}

/// Best available timestamp: last seen → event time → first seen → creation.
///
/// k8s-openapi's `Time`/`MicroTime` wrap a `jiff::Timestamp`; we normalize onto
/// chrono, which the rest of the codebase uses.
fn event_timestamp(e: &K8sEvent) -> DateTime<Utc> {
    e.last_timestamp
        .as_ref()
        .and_then(|t| jiff_to_chrono(t.0))
        .or_else(|| e.event_time.as_ref().and_then(|t| jiff_to_chrono(t.0)))
        .or_else(|| e.first_timestamp.as_ref().and_then(|t| jiff_to_chrono(t.0)))
        .or_else(|| {
            e.metadata
                .creation_timestamp
                .as_ref()
                .and_then(|t| jiff_to_chrono(t.0))
        })
        .unwrap_or_else(Utc::now)
}

/// Convert a `jiff::Timestamp` (as used by k8s-openapi 0.28+) to chrono UTC.
fn jiff_to_chrono(ts: k8s_openapi::jiff::Timestamp) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(ts.as_second(), ts.subsec_nanosecond() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        Event as K8sEvent, EventSource as K8sEventSrc, ObjectReference,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    fn fixed_time() -> Time {
        // 2026-08-11T18:30:05Z
        Time(k8s_openapi::jiff::Timestamp::from_second(1_786_559_405).unwrap())
    }

    fn base_event() -> K8sEvent {
        K8sEvent {
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                name: Some("academy.abc123".to_string()),
                ..Default::default()
            },
            involved_object: ObjectReference {
                kind: Some("Pod".to_string()),
                name: Some("academy-mlab-sh-85bc95d9b8-vpf4g".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            reason: Some("Failed".to_string()),
            message: Some("Error: ImagePullBackOff".to_string()),
            type_: Some("Warning".to_string()),
            count: Some(5),
            last_timestamp: Some(fixed_time()),
            source: Some(K8sEventSrc {
                component: Some("kubelet".to_string()),
                host: Some("rpi-01".to_string()),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn warning_event_maps_all_core_fields() {
        let sec = to_sec_event(&base_event());
        assert_eq!(sec.source, Source::K8sEvent);
        assert_eq!(sec.severity, Severity::Warning);
        assert_eq!(sec.kind, "Failed");
        assert_eq!(sec.namespace.as_deref(), Some("default"));
        assert_eq!(
            sec.object.as_deref(),
            Some("pod/academy-mlab-sh-85bc95d9b8-vpf4g")
        );
        assert_eq!(sec.message, "Error: ImagePullBackOff");
        assert_eq!(
            sec.metadata.get("reason").map(String::as_str),
            Some("Failed")
        );
        assert_eq!(sec.metadata.get("count").map(String::as_str), Some("5"));
        assert_eq!(
            sec.metadata.get("component").map(String::as_str),
            Some("kubelet")
        );
        assert_eq!(sec.metadata.get("host").map(String::as_str), Some("rpi-01"));
        assert!(!sec.payload.is_null());
    }

    #[test]
    fn normal_event_defaults_gracefully() {
        let mut e = base_event();
        e.type_ = Some("Normal".to_string());
        e.reason = None;
        e.count = None;
        let sec = to_sec_event(&e);
        assert_eq!(sec.severity, Severity::Normal);
        assert_eq!(sec.kind, "Event");
        assert!(!sec.metadata.contains_key("count"));
    }

    #[test]
    fn ndjson_roundtrips_for_a_real_event() {
        let sec = to_sec_event(&base_event());
        let line = sec.to_ndjson().unwrap();
        let back: SecEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(back.object, sec.object);
        assert_eq!(back.severity, sec.severity);
    }
}
