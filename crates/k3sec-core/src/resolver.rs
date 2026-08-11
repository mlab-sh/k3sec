//! Container → pod resolution.
//!
//! The eBPF probe observes kernel events tagged with a pid / cgroup, but a raw
//! pid is nearly useless for security triage — the value is knowing *which pod*
//! did it. A [`ContainerResolver`] maps a container runtime ID (the 64-hex id
//! that appears in a cgroup path) to the pod that owns it.
//!
//! The trait lives in core so the probe crate can depend on it without pulling
//! in `kube`; the Kubernetes-backed implementation lives in `k3sec-k8s`.

/// Identity of the pod/container an event came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub namespace: String,
    pub pod: String,
    pub container: String,
}

/// Resolves a container runtime ID to the pod that owns it.
#[async_trait::async_trait]
pub trait ContainerResolver: Send + Sync {
    /// Look up by container runtime ID (bare 64-hex, no `containerd://` prefix).
    ///
    /// Returns `None` if the id is unknown (not yet synced, host process, or a
    /// container that already exited) — callers must treat that as "no pod
    /// context" and never block on it.
    async fn by_container_id(&self, container_id: &str) -> Option<ContainerInfo>;
}
