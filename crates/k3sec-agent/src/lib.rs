//! k3sec-agent, k3sec as a tool of the mlab workspace agent (`k3sec serve`).
//!
//! The agent starts `k3sec serve` as a child process pinned to its SHA-256
//! and talks to it on stdin/stdout ([`protocol`]). k3sec holds no mlab key
//! and opens no connection to mlab: it captures, batches ([`stream`]) and
//! answers the ops of the `k3sec-api` contract, under a config mlab picks
//! within the local policy ([`config`]). Spec: `docs/tool-api.md`.

pub mod config;
pub mod convert;
pub mod hash;
pub mod pipeline;
pub mod protocol;
pub mod serve;
pub mod stream;

pub use serve::serve;
