//! Vulnerability findings as [`SecEvent`]s (`source: "vuln"`), for `watch --vulns`.

use k3sec_core::{SecEvent, Severity, Source};

use crate::model::{ImageInventory, Reachability};
use crate::vuln::{Finding, ImageVulns, VulnSeverity};

/// CVSS band → event severity; a loaded KEV is always critical.
pub fn event_severity(f: &Finding) -> Severity {
    if f.is_kev() && f.reachability == Reachability::Loaded {
        return Severity::Critical;
    }
    match f.severity {
        VulnSeverity::Critical => Severity::Critical,
        VulnSeverity::High => Severity::Error,
        VulnSeverity::Medium => Severity::Warning,
        VulnSeverity::Low => Severity::Normal,
        VulnSeverity::Unknown => Severity::Info,
    }
}

fn located(
    mut b: k3sec_core::SecEventBuilder,
    inv: &ImageInventory,
) -> k3sec_core::SecEventBuilder {
    b = b.meta("image", inv.image.clone());
    if let Some(d) = &inv.digest {
        b = b.meta("digest", d.clone());
    }
    if let Some(c) = inv.containers.first() {
        b = b
            .namespace(c.namespace.clone())
            .object(format!("{}/{}", c.pod, c.container))
            .meta("pod", c.pod.clone())
            .meta("container", c.container.clone());
    }
    b
}

/// One `kind: "vulnerability"` event for a finding.
pub fn finding_event(inv: &ImageInventory, f: &Finding) -> SecEvent {
    let mut tags = vec![f.reachability.as_str().to_string()];
    if f.is_kev() {
        tags.push("KEV".into());
    }
    if let Some(c) = f.cvss {
        tags.push(format!("CVSS {c:.1}"));
    }
    let fixed = f
        .fixed
        .as_deref()
        .map(|v| format!(", fixed in {v}"))
        .unwrap_or_default();
    let b = SecEvent::builder(Source::Vuln, chrono::Utc::now())
        .kind("vulnerability")
        .severity(event_severity(f))
        .message(format!(
            "{} in {} {} ({}){fixed}",
            f.id,
            f.package,
            f.version,
            tags.join(", ")
        ))
        .meta("cve", f.id.clone())
        .meta("package", f.package.clone())
        .meta("version", f.version.clone())
        .meta("purl", f.purl.clone())
        .meta(
            "vuln_severity",
            format!("{:?}", f.severity).to_ascii_lowercase(),
        )
        .meta(
            "cvss",
            f.cvss.map(|c| format!("{c:.1}")).unwrap_or_default(),
        )
        .meta(
            "kev",
            f.kev
                .map(|k| k.to_string())
                .unwrap_or_else(|| "unknown".into()),
        )
        .meta("fixed", f.fixed.clone().unwrap_or_default())
        .meta("reachability", f.reachability.as_str());
    located(b, inv)
        .payload(serde_json::to_value(f).unwrap_or_default())
        .build()
}

/// One `kind: "vuln_summary"` event per image.
pub fn summary_event(inv: &ImageInventory, v: &ImageVulns) -> SecEvent {
    let loaded: Vec<&Finding> = v
        .findings
        .iter()
        .filter(|f| f.reachability == Reachability::Loaded)
        .collect();
    let kev = loaded.iter().filter(|f| f.is_kev()).count();
    let severity = loaded
        .iter()
        .map(|f| event_severity(f))
        .max()
        .unwrap_or(Severity::Info);
    let message = match &v.error {
        Some(e) => format!(
            "{}: inventoried, vulnerability matching unavailable ({e})",
            inv.image
        ),
        None => format!(
            "{}: {} vulns, {} loaded ({kev} KEV loaded), {} packages",
            inv.image,
            v.findings.len(),
            loaded.len(),
            inv.packages.len()
        ),
    };
    let b = SecEvent::builder(Source::Vuln, chrono::Utc::now())
        .kind("vuln_summary")
        .severity(severity)
        .message(message)
        .meta("vulns", v.findings.len().to_string())
        .meta("loaded", loaded.len().to_string())
        .meta("kev_loaded", kev.to_string())
        .meta("packages", inv.packages.len().to_string())
        .meta("unscanned", v.unscanned.to_string())
        .meta("error", v.error.clone().unwrap_or_default());
    located(b, inv)
        .payload(serde_json::json!({
            "image": inv.image,
            "digest": inv.digest,
            "containers": inv.containers,
            "loaded": inv.count(Reachability::Loaded),
            "dormant": inv.count(Reachability::Dormant),
            "unknown": inv.count(Reachability::Unknown),
        }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k3sec_core::PodContainer;

    fn f(r: Reachability, kev: bool, sev: VulnSeverity) -> Finding {
        Finding {
            id: "CVE-2024-6387".into(),
            advisories: vec![],
            package: "openssh-server".into(),
            version: "1:9.2p1-2".into(),
            purl: "pkg:deb/debian/openssh-server@1:9.2p1-2".into(),
            severity: sev,
            cvss: Some(8.1),
            kev: Some(kev),
            fixed: Some("1:9.2p1-2+deb12u3".into()),
            summary: String::new(),
            reachability: r,
        }
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(
            event_severity(&f(Reachability::Loaded, true, VulnSeverity::Medium)),
            Severity::Critical
        );
        assert_eq!(
            event_severity(&f(Reachability::Dormant, true, VulnSeverity::High)),
            Severity::Error
        );
        assert_eq!(
            event_severity(&f(Reachability::Loaded, false, VulnSeverity::Medium)),
            Severity::Warning
        );
    }

    #[test]
    fn events_carry_pod_context_and_schema() {
        let inv = ImageInventory {
            image: "sshd:1".into(),
            digest: Some("sha256:1".into()),
            os: None,
            containers: vec![PodContainer {
                namespace: "default".into(),
                pod: "sshd-0".into(),
                container: "sshd".into(),
                image: "sshd:1".into(),
                image_digest: Some("sha256:1".into()),
                container_id: "c".into(),
            }],
            packages: vec![],
            mapped_files: 0,
            warnings: vec![],
        };
        let finding = f(Reachability::Loaded, true, VulnSeverity::High);
        let ev = finding_event(&inv, &finding);
        let v: serde_json::Value = serde_json::from_str(&ev.to_ndjson().unwrap()).unwrap();
        assert_eq!(v["source"], "vuln");
        assert_eq!(v["kind"], "vulnerability");
        assert_eq!(v["severity"], "critical");
        assert_eq!(v["object"], "sshd-0/sshd");
        assert_eq!(v["metadata"]["kev"], "true");
        assert_eq!(v["metadata"]["reachability"], "loaded");
        assert_eq!(v["payload"]["fixed"], "1:9.2p1-2+deb12u3");

        let sum = summary_event(
            &inv,
            &ImageVulns {
                findings: vec![finding],
                ..Default::default()
            },
        );
        assert_eq!(sum.kind, "vuln_summary");
        assert_eq!(sum.severity, Severity::Critical);
        assert_eq!(sum.metadata["kev_loaded"], "1");
    }
}
