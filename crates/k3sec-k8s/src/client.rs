//! Kubernetes connectivity and the reconnection backoff shared by the sources.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
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
    Ok(())
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
