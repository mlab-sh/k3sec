//! k3sec-k8s — Kubernetes-backed [`EventSource`](k3sec_core::EventSource)s.
//!
//! * [`events::K8sEventSource`] — watches core/v1 `Event`s (no polling).
//! * [`logs::K8sLogSource`] — follows pod container logs.
//!
//! [`build_client`] / [`preflight`] handle connection setup and up-front,
//! readable error reporting for kubeconfig / connectivity / RBAC problems.

pub mod client;
pub mod events;
pub mod logs;

pub use client::{build_client, preflight, Backoff};
pub use events::K8sEventSource;
pub use logs::K8sLogSource;
