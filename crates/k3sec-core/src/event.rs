//! Generic security-event envelope.
//!
//! Every observation k3sec makes, a Kubernetes `Event`, a pod log line, and
//! later an eBPF syscall alert, is normalized into a [`SecEvent`]. The schema
//! is intentionally source-agnostic:
//!
//! ```text
//! source     where it came from        (k8s-event | k8s-log | ebpf | ...)
//! timestamp  when it happened          (RFC3339, UTC)
//! kind       short type discriminator  (event reason, "log", syscall name, ...)
//! severity   normalized severity       (info | normal | warning | error | critical)
//! namespace  k8s namespace, if any
//! object     the subject               ("pod/foo", "pod/foo/nginx", ...)
//! message    human-readable text
//! metadata   flat string key/values    (source-specific, stable-ish)
//! payload    raw source object         (opaque JSON, for downstream consumers)
//! ```
//!
//! The detection engine (future milestone) will consume the NDJSON produced from
//! this struct, so treat the field names as a public contract.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where a [`SecEvent`] originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// A Kubernetes `Event` object (from the events watch).
    K8sEvent,
    /// A single log line streamed from a pod container.
    K8sLog,
    /// An eBPF-sourced runtime event (exec / connect / file write).
    Ebpf,
    /// A YARA detection produced by the scan engine.
    Yara,
}

/// Normalized severity, comparable across sources.
///
/// Kubernetes only distinguishes `Normal`/`Warning`; the extra levels exist so
/// log lines and future eBPF alerts map onto the same scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Normal,
    Warning,
    Error,
    Critical,
}

impl Severity {
    /// Map a Kubernetes event `type` string onto a [`Severity`].
    pub fn from_k8s_type(t: &str) -> Self {
        match t {
            "Warning" => Severity::Warning,
            "Normal" => Severity::Normal,
            _ => Severity::Info,
        }
    }

    /// Short uppercase label used by the pretty renderer.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Normal => "NORMAL",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
            Severity::Critical => "CRIT",
        }
    }
}

/// The normalized event envelope. See the module docs for the field contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecEvent {
    pub source: Source,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
    pub severity: Severity,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,

    pub message: String,

    /// Flat, stable-ish structured fields. `BTreeMap` keeps NDJSON key order
    /// deterministic, which makes downstream diffing and tests reliable.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,

    /// The raw source object, opaque to k3sec. Omitted from JSON when null.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

impl SecEvent {
    /// Start building an event for `source` at `timestamp`.
    pub fn builder(source: Source, timestamp: DateTime<Utc>) -> SecEventBuilder {
        SecEventBuilder {
            inner: SecEvent {
                source,
                timestamp,
                kind: String::new(),
                severity: Severity::Info,
                namespace: None,
                object: None,
                message: String::new(),
                metadata: BTreeMap::new(),
                payload: serde_json::Value::Null,
            },
        }
    }

    /// `namespace/object` if both are present, else whichever exists.
    ///
    /// For a log line whose `object` is `pod/container`, this yields the
    /// `namespace/pod/container` prefix the CLI advertises.
    pub fn location(&self) -> String {
        match (&self.namespace, &self.object) {
            (Some(ns), Some(obj)) => format!("{ns}/{obj}"),
            (Some(ns), None) => ns.clone(),
            (None, Some(obj)) => obj.clone(),
            (None, None) => "-".to_string(),
        }
    }

    /// Serialize to a single NDJSON line (no trailing newline).
    pub fn to_ndjson(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// Ergonomic builder for [`SecEvent`]. Every setter is optional except the
/// `source`/`timestamp` passed to [`SecEvent::builder`].
pub struct SecEventBuilder {
    inner: SecEvent,
}

impl SecEventBuilder {
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.inner.kind = kind.into();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.inner.severity = severity;
        self
    }

    pub fn namespace(mut self, ns: impl Into<String>) -> Self {
        self.inner.namespace = Some(ns.into());
        self
    }

    pub fn maybe_namespace(mut self, ns: Option<String>) -> Self {
        self.inner.namespace = ns.filter(|s| !s.is_empty());
        self
    }

    pub fn object(mut self, object: impl Into<String>) -> Self {
        self.inner.object = Some(object.into());
        self
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.inner.message = message.into();
        self
    }

    /// Insert one metadata key/value. Empty values are dropped to keep NDJSON tidy.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        if !value.is_empty() {
            self.inner.metadata.insert(key.into(), value);
        }
        self
    }

    pub fn payload(mut self, payload: serde_json::Value) -> Self {
        self.inner.payload = payload;
        self
    }

    pub fn build(self) -> SecEvent {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 18, 30, 5).unwrap()
    }

    #[test]
    fn severity_maps_from_k8s_type() {
        assert_eq!(Severity::from_k8s_type("Warning"), Severity::Warning);
        assert_eq!(Severity::from_k8s_type("Normal"), Severity::Normal);
        assert_eq!(Severity::from_k8s_type("Weird"), Severity::Info);
    }

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Normal < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    #[test]
    fn location_joins_namespace_and_object() {
        let ev = SecEvent::builder(Source::K8sLog, ts())
            .namespace("default")
            .object("pod/nginx")
            .build();
        assert_eq!(ev.location(), "default/pod/nginx");
    }

    #[test]
    fn location_falls_back_when_missing() {
        let ev = SecEvent::builder(Source::Ebpf, ts()).build();
        assert_eq!(ev.location(), "-");
    }

    #[test]
    fn ndjson_has_stable_schema_and_omits_empties() {
        let ev = SecEvent::builder(Source::K8sEvent, ts())
            .kind("Pulling")
            .severity(Severity::Warning)
            .namespace("default")
            .object("pod/academy")
            .message("Pulling image")
            .meta("reason", "Pulling")
            .meta("count", "3")
            .build();

        let line = ev.to_ndjson().unwrap();
        // Round-trips.
        let back: SecEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(back.kind, "Pulling");
        assert_eq!(back.severity, Severity::Warning);
        assert_eq!(back.namespace.as_deref(), Some("default"));

        // Stable field presence + kebab source + omitted null payload.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["source"], "k8s-event");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["metadata"]["count"], "3");
        assert!(v.get("payload").is_none(), "null payload must be omitted");
    }

    #[test]
    fn empty_metadata_is_omitted() {
        let ev = SecEvent::builder(Source::K8sLog, ts())
            .message("hi")
            .build();
        let v: serde_json::Value = serde_json::from_str(&ev.to_ndjson().unwrap()).unwrap();
        assert!(v.get("metadata").is_none());
        assert!(v.get("namespace").is_none());
    }
}
