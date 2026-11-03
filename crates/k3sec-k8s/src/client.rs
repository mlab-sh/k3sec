//! Kubernetes connectivity and the reconnection backoff shared by the sources.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Node;
use kube::api::{Api, ListParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};

/// Build a [`Client`], either from an explicit kubeconfig path or the ambient
/// configuration (`$KUBECONFIG`, `~/.kube/config`, or in-cluster).
///
/// Errors are wrapped with actionable context rather than surfaced raw, so a
/// missing file or unreachable API server reads clearly instead of panicking.
pub async fn build_client(kubeconfig: Option<&Path>) -> Result<Client> {
    match kubeconfig {
        Some(path) => {
            let kubeconfig = Kubeconfig::read_from(path)
                .with_context(|| format!("failed to read kubeconfig at {}", path.display()))?;
            let config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                .await
                .with_context(|| format!("invalid kubeconfig at {}", path.display()))?;
            Client::try_from(config).context("failed to construct Kubernetes client")
        }
        None => Client::try_default().await.context(
            "failed to load Kubernetes configuration (is $KUBECONFIG or ~/.kube/config set?)",
        ),
    }
}

/// Build a [`Client`] from the pod's service account, reaching the API server
/// by DNS (`kubernetes.default.svc`). Unlike [`build_client`], it needs no
/// `KUBERNETES_SERVICE_*` variables: a tool started by mlab-agent runs with an
/// empty environment.
pub fn build_incluster_client() -> Result<Client> {
    let config = Config::incluster_dns()
        .context("no in-cluster service account (set `kubeconfig` in the tool settings)")?;
    Client::try_from(config).context("failed to construct Kubernetes client")
}

/// Perform a trivial API call so connection/RBAC problems surface up-front with
/// a readable message, before we start long-running watches.
pub async fn preflight(client: &Client) -> Result<()> {
    client.apiserver_version().await.context(
        "cannot reach the Kubernetes API server (check your kubeconfig, network, and RBAC)",
    )?;
    // Best effort: a missing `list nodes` permission only skips the hint.
    if let Ok(nodes) = Api::<Node>::all(client.clone())
        .list(&ListParams::default())
        .await
    {
        let serverless: Vec<String> = nodes
            .items
            .iter()
            .filter(|n| is_serverless(n.metadata.labels.as_ref()))
            .filter_map(|n| n.metadata.name.clone())
            .collect();
        if !serverless.is_empty() {
            tracing::warn!(
                nodes = %serverless.join(", "),
                "serverless nodes (EKS Fargate, virtual kubelet): k3sec cannot run there \
                 (no hostPID), their pods are not inspected"
            );
        }
    }
    Ok(())
}

/// A node with no host to run k3sec on: EKS Fargate, a virtual kubelet (AKS
/// virtual nodes, ACI). GKE Autopilot refuses `hostPID` without such a label.
pub fn is_serverless(labels: Option<&BTreeMap<String, String>>) -> bool {
    labels.is_some_and(|l| {
        l.get("eks.amazonaws.com/compute-type")
            .is_some_and(|v| v == "fargate")
            || l.get("type").is_some_and(|v| v == "virtual-kubelet")
    })
}

/// Exponential backoff with a ceiling, used to space out watch reconnections.
///
/// Starts at 1s and doubles up to 30s. [`reset`](Backoff::reset) is called after
/// a successful (re)connection so transient blips don't accumulate delay.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
    initial: Duration,
    max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            current: initial,
            initial,
            max,
        }
    }

    /// Return the current delay, then double it (saturating at `max`).
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * 2).min(self.max);
        delay
    }

    /// Reset back to the initial delay after a healthy connection.
    pub fn reset(&mut self) {
        self.current = self.initial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serverless_node_labels() {
        let labels = |k: &str, v: &str| BTreeMap::from([(k.to_string(), v.to_string())]);
        assert!(is_serverless(Some(&labels(
            "eks.amazonaws.com/compute-type",
            "fargate"
        ))));
        assert!(is_serverless(Some(&labels("type", "virtual-kubelet"))));
        assert!(!is_serverless(Some(&labels(
            "eks.amazonaws.com/compute-type",
            "ec2"
        ))));
        assert!(!is_serverless(Some(&labels(
            "node-role.kubernetes.io/control-plane",
            ""
        ))));
        assert!(!is_serverless(None));
    }

    #[test]
    fn backoff_doubles_then_saturates() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }
}
