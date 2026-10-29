//! Node workload listing for the inventory: running containers and the node's
//! own version stack, as [`PodContainer`] / [`NodeVersions`] core types.

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::ListParams;
use kube::{Api, Client};

use k3sec_core::{NodeVersions, PodContainer};

use crate::resolver::strip_runtime_scheme;

/// Every running container of the pods on `node` (all nodes when `None`),
/// optionally restricted to `namespace`.
pub async fn list_node_containers(
    client: &Client,
    node: Option<&str>,
    namespace: Option<&str>,
) -> Result<Vec<PodContainer>> {
    let api: Api<Pod> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let mut params = ListParams::default();
    if let Some(node) = node {
        params = params.fields(&format!("spec.nodeName={node}"));
    }
    let pods = api
        .list(&params)
        .await
        .context("failed to list pods (check RBAC: list pods)")?;
    Ok(pods.items.iter().flat_map(pod_containers).collect())
}

/// The running containers of `pod` (those with a runtime id; init containers
/// that already exited have no PIDs to inspect and are skipped).
pub fn pod_containers(pod: &Pod) -> Vec<PodContainer> {
    let (Some(namespace), Some(name)) = (&pod.metadata.namespace, &pod.metadata.name) else {
        return Vec::new();
    };
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref());
    statuses
        .into_iter()
        .flatten()
        .filter(|cs| cs.state.as_ref().is_none_or(|s| s.running.is_some()))
        .filter_map(|cs| {
            Some(PodContainer {
                namespace: namespace.clone(),
                pod: name.clone(),
                container: cs.name.clone(),
                image: cs.image.clone(),
                image_digest: digest_of(&cs.image_id),
                container_id: cs.container_id.as_deref().and_then(strip_runtime_scheme)?,
            })
        })
        .collect()
}

/// `docker.io/library/nginx@sha256:abc…` → `sha256:abc…`.
fn digest_of(image_id: &str) -> Option<String> {
    image_id
        .rsplit_once('@')
        .map(|(_, d)| d)
        .or_else(|| image_id.starts_with("sha256:").then_some(image_id))
        .map(str::to_string)
}

/// Versions of `node`'s stack. Without a node name, the only node of a
/// single-node cluster is used; otherwise the node must be named.
pub async fn node_versions(client: &Client, node: Option<&str>) -> Result<NodeVersions> {
    let api: Api<Node> = Api::all(client.clone());
    let node = match node {
        Some(name) => api
            .get(name)
            .await
            .with_context(|| format!("failed to get node {name} (check RBAC: get nodes)"))?,
        None => {
            let mut nodes = api
                .list(&ListParams::default())
                .await
                .context("failed to list nodes (check RBAC: list nodes)")?
                .items;
            if nodes.len() != 1 {
                anyhow::bail!(
                    "cluster has {} nodes: pass --node (or set $NODE_NAME) to pick this one",
                    nodes.len()
                );
            }
            nodes.remove(0)
        }
    };
    let info = node.status.and_then(|s| s.node_info).unwrap_or_default();
    Ok(NodeVersions {
        node: node.metadata.name.unwrap_or_default(),
        kubelet: info.kubelet_version,
        container_runtime: info.container_runtime_version,
        kernel: info.kernel_version,
        os_image: info.os_image,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateRunning, ContainerStateTerminated, ContainerStatus, PodStatus,
    };
    use kube::api::ObjectMeta;

    const CID: &str = "3f9a1b2c4d5e6f7089abcdef0123456789abcdef0123456789abcdef01234567";

    fn status(name: &str, running: bool) -> ContainerStatus {
        ContainerStatus {
            name: name.into(),
            image: "nginx:1.27".into(),
            image_id: "docker.io/library/nginx@sha256:beef".into(),
            container_id: Some(format!("containerd://{CID}")),
            state: Some(if running {
                ContainerState {
                    running: Some(ContainerStateRunning::default()),
                    ..Default::default()
                }
            } else {
                ContainerState {
                    terminated: Some(ContainerStateTerminated::default()),
                    ..Default::default()
                }
            }),
            ..Default::default()
        }
    }

    #[test]
    fn running_containers_only_with_digest() {
        let pod = Pod {
            metadata: ObjectMeta {
                namespace: Some("default".into()),
                name: Some("web".into()),
                ..Default::default()
            },
            status: Some(PodStatus {
                container_statuses: Some(vec![status("nginx", true), status("done", false)]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cs = pod_containers(&pod);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].container, "nginx");
        assert_eq!(cs[0].container_id, CID);
        assert_eq!(cs[0].image_key(), "sha256:beef");
    }

    #[test]
    fn digest_parsing() {
        assert_eq!(digest_of("a/b@sha256:1").as_deref(), Some("sha256:1"));
        assert_eq!(digest_of("sha256:2").as_deref(), Some("sha256:2"));
        assert_eq!(digest_of(""), None);
    }
}
