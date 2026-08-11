//! Kubernetes-backed [`ContainerResolver`].
//!
//! Watches pods (optionally only those on the local node) and keeps an in-memory
//! map from **container runtime ID** → pod identity. The eBPF probe extracts the
//! container ID from a process's cgroup path and looks it up here to attach
//! `namespace/pod/container` context to each kernel event.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher;
use kube::runtime::watcher::Event as WatchEvent;
use kube::{Api, Client};
use tokio_util::sync::CancellationToken;

use crate::client::Backoff;
use k3sec_core::{ContainerInfo, ContainerResolver};

/// A live, node-scoped map of container runtime IDs to their owning pod.
#[derive(Default)]
pub struct NodePodResolver {
    map: RwLock<HashMap<String, ContainerInfo>>,
}

impl NodePodResolver {
    /// Create an empty resolver and spawn a background task that keeps it in
    /// sync by watching pods (filtered to `node` when given).
    ///
    /// Returns the shared resolver immediately; the map fills in as the watch
    /// syncs. Lookups before the first sync simply miss (no pod context yet).
    pub fn spawn(client: Client, node: Option<String>, cancel: CancellationToken) -> Arc<Self> {
        let resolver = Arc::new(Self::default());
        let bg = resolver.clone();
        tokio::spawn(async move { bg.run(client, node, cancel).await });
        resolver
    }

    async fn run(&self, client: Client, node: Option<String>, cancel: CancellationToken) {
        let mut backoff = Backoff::default();
        loop {
            if cancel.is_cancelled() {
                return;
            }
            match self.watch_once(&client, node.as_deref(), &cancel).await {
                Ok(()) => return,
                Err(e) => {
                    let delay = backoff.next_delay();
                    tracing::warn!(error = %e, "pod resolver watch dropped, reconnecting in {delay:?}");
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
    }

    async fn watch_once(
        &self,
        client: &Client,
        node: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let api: Api<Pod> = Api::all(client.clone());
        let mut config = watcher::Config::default();
        if let Some(node) = node {
            config = config.fields(&format!("spec.nodeName={node}"));
        }
        let mut stream = watcher(api, config).boxed();

        while let Some(item) = tokio::select! {
            _ = cancel.cancelled() => None,
            item = stream.next() => Some(item),
        } {
            match item {
                Some(Ok(WatchEvent::Apply(pod))) | Some(Ok(WatchEvent::InitApply(pod))) => {
                    self.index_pod(&pod)
                }
                Some(Ok(WatchEvent::Delete(pod))) => self.forget_pod(&pod),
                Some(Ok(_)) => {}
                Some(Err(e)) => tracing::debug!(error = %e, "recoverable resolver watcher error"),
                None => return Ok(()), // stream ended or cancelled
            }
        }
        Ok(())
    }

    /// Insert every container of `pod` (by runtime ID) into the map.
    fn index_pod(&self, pod: &Pod) {
        let (Some(namespace), Some(pod_name)) =
            (pod.metadata.namespace.clone(), pod.metadata.name.clone())
        else {
            return;
        };
        let Some(status) = pod.status.as_ref() else {
            return;
        };

        let mut map = self.map.write().expect("resolver map poisoned");
        let all = status
            .container_statuses
            .iter()
            .flatten()
            .chain(status.init_container_statuses.iter().flatten());
        for cs in all {
            if let Some(id) = cs.container_id.as_deref().and_then(strip_runtime_scheme) {
                map.insert(
                    id,
                    ContainerInfo {
                        namespace: namespace.clone(),
                        pod: pod_name.clone(),
                        container: cs.name.clone(),
                    },
                );
            }
        }
    }

    /// Drop every entry belonging to `pod`.
    fn forget_pod(&self, pod: &Pod) {
        let (Some(namespace), Some(pod_name)) = (
            pod.metadata.namespace.as_deref(),
            pod.metadata.name.as_deref(),
        ) else {
            return;
        };
        let mut map = self.map.write().expect("resolver map poisoned");
        map.retain(|_, info| !(info.namespace == namespace && info.pod == pod_name));
    }

    /// Number of indexed containers (for diagnostics / tests).
    pub fn len(&self) -> usize {
        self.map.read().expect("resolver map poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl ContainerResolver for NodePodResolver {
    async fn by_container_id(&self, container_id: &str) -> Option<ContainerInfo> {
        self.map
            .read()
            .expect("resolver map poisoned")
            .get(container_id)
            .cloned()
    }
}

/// Strip a `runtime://` scheme from a `containerStatus.containerID`, returning
/// the bare id (`containerd://abcd…` → `abcd…`).
fn strip_runtime_scheme(container_id: &str) -> Option<String> {
    container_id
        .split_once("://")
        .map(|(_, id)| id.to_string())
        .filter(|id| !id.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ContainerStatus, PodStatus};
    use kube::api::ObjectMeta;

    const CID: &str = "3f9a1b2c4d5e6f7089abcdef0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn strips_runtime_scheme() {
        assert_eq!(
            strip_runtime_scheme(&format!("containerd://{CID}")).as_deref(),
            Some(CID)
        );
        assert_eq!(strip_runtime_scheme("containerd://"), None);
        assert_eq!(strip_runtime_scheme("garbage"), None);
    }

    fn pod_with_container(ns: &str, name: &str, container: &str, cid: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                namespace: Some(ns.to_string()),
                name: Some(name.to_string()),
                ..Default::default()
            },
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    name: container.to_string(),
                    container_id: Some(format!("containerd://{cid}")),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn index_and_resolve_roundtrip() {
        let resolver = NodePodResolver::default();
        resolver.index_pod(&pod_with_container("default", "nginx-abc", "nginx", CID));

        let info = resolver.by_container_id(CID).await.expect("should resolve");
        assert_eq!(info.namespace, "default");
        assert_eq!(info.pod, "nginx-abc");
        assert_eq!(info.container, "nginx");
        assert_eq!(resolver.len(), 1);
    }

    #[tokio::test]
    async fn forget_pod_removes_entries() {
        let resolver = NodePodResolver::default();
        let pod = pod_with_container("default", "nginx-abc", "nginx", CID);
        resolver.index_pod(&pod);
        assert_eq!(resolver.len(), 1);
        resolver.forget_pod(&pod);
        assert_eq!(resolver.len(), 0);
        assert!(resolver.by_container_id(CID).await.is_none());
    }

    #[tokio::test]
    async fn unknown_container_resolves_to_none() {
        let resolver = NodePodResolver::default();
        assert!(resolver.by_container_id("deadbeef").await.is_none());
    }
}
