//! Scanning bytes and turning YARA matches into [`SecEvent`]s.

use std::collections::BTreeSet;

use k3sec_core::{ScanRequest, SecEvent, Severity, Source};
use yara_x::Scanner;

/// A single matched rule, flattened from a scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub identifier: String,
    pub namespace: String,
    pub tags: Vec<String>,
}

/// Scan `data` with `scanner`, returning every matched rule.
///
/// A scan error (not a "no match") is logged and treated as no hits, a broken
/// scan must never take the worker down.
pub fn scan_bytes(scanner: &mut Scanner, data: &[u8]) -> Vec<RuleHit> {
    match scanner.scan(data) {
        Ok(results) => results
            .matching_rules()
            .map(|rule| RuleHit {
                identifier: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "yara scan failed");
            Vec::new()
        }
    }
}

/// Build one detection [`SecEvent`] summarizing all `hits` on `artifact`.
///
/// The pod/namespace context is inherited from the triggering [`ScanRequest`].
pub fn detection_event(hits: &[RuleHit], req: &ScanRequest, artifact: &str) -> SecEvent {
    let rules: Vec<&str> = hits.iter().map(|h| h.identifier.as_str()).collect();
    let rules_joined = rules.join(",");

    let namespaces: BTreeSet<&str> = hits.iter().map(|h| h.namespace.as_str()).collect();
    let tags: BTreeSet<&str> = hits
        .iter()
        .flat_map(|h| h.tags.iter().map(String::as_str))
        .collect();

    let mut builder = SecEvent::builder(Source::Yara, chrono::Utc::now())
        .kind("detection")
        .severity(Severity::Critical)
        .message(format!("YARA match [{rules_joined}] on {artifact}"))
        .meta("rules", rules_joined)
        .meta(
            "rule_namespace",
            namespaces.into_iter().collect::<Vec<_>>().join(","),
        )
        .meta("tags", tags.iter().copied().collect::<Vec<_>>().join(","))
        .meta("artifact", artifact.to_string())
        .meta("trigger", req.trigger.as_str())
        .meta("pid", req.pid.to_string())
        .meta("comm", req.comm.clone());

    if let Some(c) = &req.container {
        builder = builder
            .namespace(c.namespace.clone())
            .object(format!("{}/{}", c.pod, c.container))
            .meta("pod", c.pod.clone())
            .meta("container", c.container.clone());
    }

    let matches: Vec<serde_json::Value> = hits
        .iter()
        .map(|h| {
            serde_json::json!({
                "rule": h.identifier,
                "namespace": h.namespace,
                "tags": h.tags,
            })
        })
        .collect();
    builder = builder.payload(serde_json::json!({
        "artifact": artifact,
        "trigger": req.trigger.as_str(),
        "pid": req.pid,
        "matches": matches,
    }));

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k3sec_core::{ContainerInfo, ScanTrigger};
    use yara_x::Compiler;

    fn scanner_for(src: &str) -> (yara_x::Rules, ()) {
        let mut c = Compiler::new();
        c.add_source(src).unwrap();
        (c.build(), ())
    }

    #[test]
    fn scan_reports_matching_rule() {
        let (rules, _) =
            scanner_for(r#"rule marker : test { strings: $a = "K3SEC_YARA_TEST" condition: $a }"#);
        let mut scanner = Scanner::new(&rules);
        let hits = scan_bytes(&mut scanner, b"junk K3SEC_YARA_TEST junk");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].identifier, "marker");
        assert_eq!(hits[0].tags, vec!["test".to_string()]);
    }

    #[test]
    fn scan_reports_nothing_when_no_match() {
        let (rules, _) = scanner_for(r#"rule marker { strings: $a = "NOPE" condition: $a }"#);
        let mut scanner = Scanner::new(&rules);
        let hits = scan_bytes(&mut scanner, b"clean bytes");
        assert!(hits.is_empty());
    }

    #[test]
    fn detection_event_carries_context_and_rules() {
        let req = ScanRequest {
            trigger: ScanTrigger::Exec,
            pid: 4242,
            path: None,
            container_id: None,
            container: Some(ContainerInfo {
                namespace: "default".to_string(),
                pod: "evil-pod".to_string(),
                container: "app".to_string(),
            }),
            comm: "evil".to_string(),
        };
        let hits = vec![RuleHit {
            identifier: "reverse_shell".to_string(),
            namespace: "default".to_string(),
            tags: vec!["shell".to_string(), "critical".to_string()],
        }];

        let ev = detection_event(&hits, &req, "/proc/4242/exe");
        assert_eq!(ev.source, Source::Yara);
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.kind, "detection");
        assert_eq!(ev.location(), "default/evil-pod/app");
        assert_eq!(ev.metadata.get("rules").unwrap(), "reverse_shell");
        assert_eq!(ev.metadata.get("artifact").unwrap(), "/proc/4242/exe");
        assert_eq!(ev.metadata.get("trigger").unwrap(), "exec");
        assert_eq!(ev.metadata.get("tags").unwrap(), "critical,shell");
        assert!(ev.message.contains("reverse_shell"));

        // NDJSON stays well-formed with the nested payload.
        let v: serde_json::Value = serde_json::from_str(&ev.to_ndjson().unwrap()).unwrap();
        assert_eq!(v["source"], "yara");
        assert_eq!(v["payload"]["matches"][0]["rule"], "reverse_shell");
    }
}
