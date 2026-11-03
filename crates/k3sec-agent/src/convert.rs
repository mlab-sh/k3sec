//! k3sec's internal types → the frozen `k3sec-api` v1 wire types.

use k3sec_api as api;
use k3sec_core::{NodeVersions, SecEvent, Severity, Source};
use k3sec_inventory::{Coordinate, ImageInventory, PackageKind};

pub fn event(ev: &SecEvent) -> api::SecEvent {
    let (metadata, payload) = trimmed(ev);
    api::SecEvent {
        source: match ev.source {
            Source::K8sEvent => api::Source::K8sEvent,
            Source::K8sLog => api::Source::K8sLog,
            Source::Ebpf => api::Source::Ebpf,
            Source::Yara => api::Source::Yara,
            Source::Vuln => api::Source::Vuln,
            // The v1 wire is frozen: an audit detection travels as a
            // Kubernetes event, told apart by its kind (`audit`).
            Source::K8sAudit => api::Source::K8sEvent,
        },
        timestamp: ev.timestamp.timestamp_millis(),
        kind: ev.kind.clone(),
        severity: severity(ev.severity),
        namespace: ev.namespace.clone(),
        object: ev.object.clone(),
        message: ev.message.clone(),
        metadata,
        payload,
    }
}

/// Metadata and payload without what the event already says elsewhere: on
/// the wire every byte is paid once per event.
fn trimmed(
    ev: &SecEvent,
) -> (
    std::collections::BTreeMap<String, String>,
    serde_json::Value,
) {
    let mut metadata = ev.metadata.clone();
    // `pod` and `container` are the object.
    if let (Some(pod), Some(container)) = (metadata.get("pod"), metadata.get("container")) {
        if ev.object.as_deref() == Some(&format!("{pod}/{container}")) {
            metadata.remove("pod");
            metadata.remove("container");
        }
    }
    let mut payload = ev.payload.clone();
    let dupes: &[&str] = match ev.source {
        // pid, uid, comm are in the metadata, namespace / pod / container the
        // event's own; the kernel's cgroup id is meaningless off the node.
        Source::Ebpf => {
            if payload.get("container_id").is_some() {
                metadata.remove("container_id"); // its short form
            }
            &[
                "pid",
                "uid",
                "comm",
                "namespace",
                "pod",
                "container",
                "cgroup_id",
            ]
        }
        Source::Yara => &["artifact", "trigger", "pid"],
        _ => &[],
    };
    if let Some(obj) = payload.as_object_mut() {
        for k in dupes {
            obj.remove(*k);
        }
    }
    (metadata, payload)
}

pub fn severity(s: Severity) -> api::Severity {
    match s {
        Severity::Info => api::Severity::Info,
        Severity::Normal => api::Severity::Normal,
        Severity::Warning => api::Severity::Warning,
        Severity::Error => api::Severity::Error,
        Severity::Critical => api::Severity::Critical,
    }
}

pub fn node_versions(v: &NodeVersions) -> api::NodeVersions {
    api::NodeVersions {
        kubelet: v.kubelet.clone(),
        container_runtime: v.container_runtime.clone(),
        kernel: v.kernel.clone(),
        os_image: v.os_image.clone(),
    }
}

pub fn image(inv: &ImageInventory) -> api::ImageInventory {
    api::ImageInventory {
        image: inv.image.clone(),
        digest: inv.digest.clone(),
        os: inv.os.as_ref().map(|o| api::inventory::Os {
            id: o.id.clone(),
            version_id: o.version_id.clone(),
            pretty_name: o.pretty_name.clone(),
        }),
        containers: inv
            .containers
            .iter()
            .map(|c| api::inventory::Container {
                namespace: c.namespace.clone(),
                pod: c.pod.clone(),
                container: c.container.clone(),
                container_id: c.container_id.clone(),
            })
            .collect(),
        packages: inv
            .packages
            .iter()
            .map(|p| api::Package {
                name: p.name.clone(),
                version: p.version.clone(),
                kind: match p.kind {
                    PackageKind::Os => "os",
                    PackageKind::Lang => "lang",
                    PackageKind::Node => "node",
                }
                .into(),
                purl: p.purl.clone(),
                source: p.source.clone(),
                location: p.location.clone(),
                reachability: p.reachability.as_str().into(),
                coordinate: p.coordinate.as_ref().map(coordinate),
            })
            .collect(),
        mapped_files: inv.mapped_files as u32,
        warnings: inv.warnings.clone(),
    }
}

fn coordinate(c: &Coordinate) -> api::Coordinate {
    let mut out = api::Coordinate {
        ecosystem: None,
        name: None,
        version: None,
        purl: None,
        cpe: None,
    };
    match c {
        Coordinate::Eco {
            ecosystem,
            name,
            version,
        } => {
            out.ecosystem = Some(ecosystem.clone());
            out.name = Some(name.clone());
            out.version = Some(version.clone());
        }
        Coordinate::Purl { purl } => out.purl = Some(purl.clone()),
        Coordinate::Cpe { cpe } => out.cpe = Some(cpe.clone()),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use k3sec_inventory::{Package, Reachability};

    #[test]
    fn ebpf_event_without_duplicates() {
        let ev = SecEvent::builder(Source::Ebpf, chrono::Utc::now())
            .kind("exec")
            .namespace("cvss")
            .object("writer/writer")
            .message("exec /bin/sh (sh)")
            .meta("pid", "7")
            .meta("comm", "sh")
            .meta("pod", "writer")
            .meta("container", "writer")
            .meta("container_id", "af282058b353")
            .payload(
                serde_json::json!({"pid": 7, "uid": 0, "comm": "sh", "cgroup_id": 9,
                "container_id": "af282058b353e345", "path": "/bin/sh",
                "namespace": "cvss", "pod": "writer", "container": "writer"}),
            )
            .build();
        let w = event(&ev);
        assert_eq!(
            w.metadata.keys().collect::<Vec<_>>(),
            ["comm", "pid"],
            "pod/container are the object, the short id the payload's"
        );
        assert_eq!(
            w.payload,
            serde_json::json!({"container_id": "af282058b353e345", "path": "/bin/sh"})
        );
        // Off the eBPF path nothing of the payload goes.
        let log = SecEvent::builder(Source::K8sLog, chrono::Utc::now())
            .object("web/app")
            .meta("pod", "other")
            .meta("container", "app")
            .payload(serde_json::json!({"pid": 1}))
            .build();
        let w = event(&log);
        assert_eq!(w.metadata["pod"], "other", "not the object: kept");
        assert_eq!(w.payload["pid"], 1);
    }

    #[test]
    fn event_keeps_every_field() {
        let ts = chrono::Utc
            .with_ymd_and_hms(2026, 10, 29, 12, 0, 0)
            .unwrap();
        let ev = SecEvent::builder(Source::Yara, ts)
            .kind("detection")
            .severity(Severity::Critical)
            .namespace("demo")
            .object("web-0/app")
            .message("YARA match")
            .meta("rules", "r")
            .meta("pid", "1")
            .payload(serde_json::json!({"pid": 1, "matches": [{"rule": "r"}]}))
            .build();
        let w = event(&ev);
        assert_eq!(w.source, api::Source::Yara);
        assert_eq!(w.timestamp, ts.timestamp_millis());
        assert_eq!(w.severity, api::Severity::Critical);
        assert_eq!(w.metadata["rules"], "r");
        assert_eq!(w.payload, serde_json::json!({"matches": [{"rule": "r"}]}));
    }

    #[test]
    fn package_coordinates_and_reachability() {
        let mut p = Package::new(
            "libssl3",
            "3.0.11",
            PackageKind::Os,
            "pkg:deb/debian/libssl3@3.0.11".into(),
        );
        p.coordinate = Some(Coordinate::eco("Debian:12", "openssl", "3.0.11"));
        p.reachability = Reachability::Loaded;
        let inv = ImageInventory {
            image: "nginx".into(),
            digest: Some("sha256:1".into()),
            os: None,
            containers: vec![],
            packages: vec![p],
            mapped_files: 3,
            warnings: vec![],
        };
        let w = image(&inv);
        assert_eq!(w.packages[0].reachability, "loaded");
        assert_eq!(w.packages[0].kind, "os");
        let c = w.packages[0].coordinate.as_ref().unwrap();
        assert_eq!(
            (c.ecosystem.as_deref(), c.name.as_deref()),
            (Some("Debian:12"), Some("openssl"))
        );
    }
}
