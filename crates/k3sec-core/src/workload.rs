//! Workload inventory types, shared by `k3sec-k8s` (which lists them from the
//! API) and `k3sec-inventory` (which inspects them on the node), so neither
//! crate depends on the other.

use serde::Serialize;

/// One running container of a pod scheduled on this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PodContainer {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    /// The image reference from the pod spec/status (`nginx:1.27`).
    pub image: String,
    /// `sha256:…` from `containerStatus.imageID`, when the runtime reported it.
    pub image_digest: Option<String>,
    /// Bare runtime id (no `containerd://` scheme), as found in cgroup paths.
    pub container_id: String,
}

impl PodContainer {
    /// The key images are deduplicated on: the digest, else the image ref.
    pub fn image_key(&self) -> &str {
        self.image_digest.as_deref().unwrap_or(&self.image)
    }
}

/// Versions of the node's own stack, from `node.status.nodeInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NodeVersions {
    pub node: String,
    /// `v1.33.5+k3s1`.
    pub kubelet: String,
    /// `containerd://2.1.4-k3s1`.
    pub container_runtime: String,
    /// `6.8.0-45-generic`.
    pub kernel: String,
    pub os_image: String,
}
