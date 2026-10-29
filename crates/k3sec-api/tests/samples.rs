//! Fixed sample values of the v1 contract, shared by the tests and the
//! golden generator. Changing one changes the frozen bytes: don't, for v1.

#![allow(dead_code)]

use std::collections::BTreeMap;

use k3sec_api::inventory::{Container, Os, INVENTORY_FORMAT};
use k3sec_api::*;

pub fn yara_event() -> SecEvent {
    SecEvent {
        source: Source::Yara,
        timestamp: 1_793_000_000_000,
        kind: "detection".into(),
        severity: Severity::Critical,
        namespace: Some("demo".into()),
        object: Some("web-0/app".into()),
        message: "YARA match [reverse_shell_indicators] on /proc/4242/exe".into(),
        metadata: BTreeMap::from([
            ("rules".to_string(), "reverse_shell_indicators".to_string()),
            ("pod".to_string(), "web-0".to_string()),
        ]),
        payload: serde_json::json!({"pid": 4242, "trigger": "exec"}),
    }
}

pub fn batch() -> Batch {
    Batch {
        api_version: API_VERSION,
        boot_id: "b-0123456789abcdef".into(),
        seq: 7,
        node: "node-1".into(),
        events: vec![yara_event()],
        dropped: 3,
        urgent: true,
    }
}

pub fn status() -> Status {
    Status {
        api_version: API_VERSION,
        k3sec_version: "1.4.0".into(),
        boot_id: "b-0123456789abcdef".into(),
        started_at: 1_793_000_000_000,
        node: "node-1".into(),
        cluster_id: Some("5d1c3e0a-0000-4000-8000-000000000001".into()),
        node_versions: Some(NodeVersions {
            kubelet: "v1.33.5+k3s1".into(),
            container_runtime: "containerd://2.1.4-k3s1".into(),
            kernel: "6.8.0-45-generic".into(),
            os_image: "Ubuntu 24.04.1 LTS".into(),
        }),
        config: Config::default(),
        allow: Settings::default().allow,
        allowed_namespaces: vec![],
        rulesets: vec!["default".into()],
        allow_remote_rules: false,
        sources: vec![SourceState {
            name: "ebpf".into(),
            state: "running".into(),
            error: None,
        }],
        counters: Counters {
            events: 120,
            dropped: 3,
            last_seq: 7,
        },
        images: 4,
    }
}

pub fn inventory() -> Inventory {
    Inventory {
        format: INVENTORY_FORMAT.into(),
        api_version: API_VERSION,
        generated_at: 1_793_000_000_000,
        node: "node-1".into(),
        cluster_id: None,
        node_versions: None,
        images: vec![ImageInventory {
            image: "docker.io/library/nginx:1.25.3".into(),
            digest: Some("sha256:c7a6".into()),
            os: Some(Os {
                id: "debian".into(),
                version_id: "12".into(),
                pretty_name: "Debian GNU/Linux 12 (bookworm)".into(),
            }),
            containers: vec![Container {
                namespace: "demo".into(),
                pod: "nginx-0".into(),
                container: "nginx".into(),
                container_id: "8ebc3b63".into(),
            }],
            packages: vec![Package {
                name: "libssl3".into(),
                version: "3.0.11-1~deb12u2".into(),
                kind: "os".into(),
                purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl".into(),
                source: Some("openssl".into()),
                location: None,
                reachability: "loaded".into(),
                coordinate: Some(Coordinate {
                    ecosystem: Some("Debian:12".into()),
                    name: Some("openssl".into()),
                    version: Some("3.0.11-1~deb12u2".into()),
                    purl: None,
                    cpe: None,
                }),
            }],
            mapped_files: 10,
            warnings: vec![],
        }],
    }
}

pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("batch-v1", to_cbor(&batch()).unwrap()),
        ("status-v1", to_cbor(&status()).unwrap()),
        ("config-v1", to_cbor(&Config::default()).unwrap()),
        ("inventory-v1", inventory().encode().unwrap()),
    ]
}
