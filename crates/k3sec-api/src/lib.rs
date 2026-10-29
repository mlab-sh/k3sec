//! What mlab can ask the `k3sec` tool, through the workspace agent
//! (`mlab-agent`), and what the tool sends on its own: op names, their CBOR
//! arguments and answers, events, and the frozen v1 wire schema of
//! [`SecEvent`]s, inventories and SBOM descriptors. Spec: `docs/tool-api.md`.
//!
//! The agent routes these as opaque bytes; only mlab and `k3sec serve`
//! decode them. This crate depends on nothing of k3sec so the mlab backend
//! can import it alone.
//!
//! **Compatibility.** Every struct refuses unknown fields. Adding a field is
//! a new [`API_VERSION`]; mlab must accept the versions it knows and refuse
//! the others ([`check_version`]).

#![forbid(unsafe_code)]

pub mod inventory;

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use inventory::{Coordinate, ImageInventory, Inventory, NodeVersions, Package, SbomInfo};

/// The tool name in `Request.tool`.
pub const TOOL: &str = "k3sec";

/// Version of this contract (ops, events, every type below).
pub const API_VERSION: u16 = 1;

/// Largest encoded [`Batch`]: an event must fit the agent's 1 MiB envelope
/// with room for the envelope, HPKE and the `Event {tool, name}` wrapper.
pub const MAX_BATCH_BYTES: usize = 768 * 1024;

/// Most events in one [`Batch`].
pub const MAX_BATCH_EVENTS: usize = 2_000;

/// Batches `events_since` returns at most in one answer.
pub const MAX_BATCHES_PER_ANSWER: u32 = 1;

pub mod op {
    /// No arguments. Answer: [`super::Status`].
    pub const STATUS: &str = "status";
    /// Arguments: [`super::Config`]. Answer: [`super::Configured`]. The
    /// config is clamped to the local policy ([`super::Settings`]).
    pub const CONFIGURE: &str = "configure";
    /// Arguments: [`super::EventsSince`]. Answer: [`super::Backlog`]. To fill
    /// the gaps of best-effort `batch` events.
    pub const EVENTS_SINCE: &str = "events_since";
    /// Arguments: [`super::InventoryRequest`] + upload target. Answer: a blob
    /// (the CBOR [`super::Inventory`]) and an [`super::InventoryInfo`] body.
    pub const INVENTORY: &str = "inventory";
    /// Arguments: [`super::ImageRef`] + upload target. Answer: a blob (the
    /// CycloneDX 1.5 JSON) and a [`super::SbomInfo`] body.
    pub const SBOM: &str = "sbom";

    pub const ALL: [&str; 5] = [STATUS, CONFIGURE, EVENTS_SINCE, INVENTORY, SBOM];
}

pub mod event {
    /// Body: [`super::Batch`]. Runtime events, in order, best effort.
    pub const BATCH: &str = "batch";
    /// Body: [`super::Status`]. Heartbeat, every minute and on change.
    pub const STATUS: &str = "status";
    /// Body: [`super::InventoryReady`]. An image was (re)inventoried: fetch
    /// it with `inventory` / `sbom`.
    pub const INVENTORY_READY: &str = "inventory_ready";
}

/// Encode a contract value as CBOR.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ApiError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| ApiError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode a contract value from CBOR (unknown fields are refused).
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    ciborium::from_reader(bytes).map_err(|e| ApiError::Decode(e.to_string()))
}

/// Refuse a document from a contract version this build doesn't know.
pub fn check_version(version: u16) -> Result<(), ApiError> {
    if version == API_VERSION {
        Ok(())
    } else {
        Err(ApiError::UnsupportedVersion(version))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    Encode(String),
    Decode(String),
    UnsupportedVersion(u16),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Encode(e) => write!(f, "k3sec-api encode: {e}"),
            ApiError::Decode(e) => write!(f, "k3sec-api decode: {e}"),
            ApiError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "k3sec-api version {v} unsupported (this build: {API_VERSION})"
                )
            }
        }
    }
}

impl std::error::Error for ApiError {}

// ---------------------------------------------------------------------------
// SecEvent v1

/// Where an event comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    K8sEvent,
    K8sLog,
    Ebpf,
    Yara,
    Vuln,
}

/// Normalized severity, ordered `info < normal < warning < error < critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Normal,
    Warning,
    Error,
    Critical,
}

/// One security event, frozen v1 of k3sec's `SecEvent` (the same fields as
/// its NDJSON output, `timestamp` in Unix milliseconds instead of RFC 3339).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecEvent {
    pub source: Source,
    /// Unix milliseconds, UTC.
    pub timestamp: i64,
    /// `exec`, `connect`, `file_write`, `detection`, `vulnerability`,
    /// `vuln_summary`, `log`, or a k8s event reason.
    pub kind: String,
    pub severity: Severity,
    pub namespace: Option<String>,
    /// `pod/<name>`, `<pod>/<container>`, ...
    pub object: Option<String>,
    pub message: String,
    /// Flat source-specific fields (see `docs/tool-api.md`).
    pub metadata: BTreeMap<String, String>,
    /// Raw source detail; `null` when none.
    pub payload: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Events stream

/// A run of events. `seq` increases by one per batch within a `boot_id` (one
/// `k3sec serve` process); a gap means lost batches, recovered with
/// `events_since`. A new `boot_id` starts again at 1: what the previous
/// process didn't deliver is gone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub api_version: u16,
    pub boot_id: String,
    pub seq: u64,
    /// The node the events were seen on.
    pub node: String,
    pub events: Vec<SecEvent>,
    /// Events dropped (buffer full) since the previous batch. Never silent.
    pub dropped: u64,
    /// Flushed early because it holds a critical event.
    pub urgent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSince {
    pub boot_id: String,
    /// The last `seq` mlab has; answers start at `after_seq + 1`.
    pub after_seq: u64,
}

/// What `events_since` answers. With another `boot_id` than asked (the
/// tool restarted), `batches` start the new run and the old one is lost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backlog {
    pub boot_id: String,
    /// At most [`MAX_BATCHES_PER_ANSWER`]; ask again from the last `seq`.
    pub batches: Vec<Batch>,
    /// Oldest `seq` still held (older ones were evicted: lost).
    pub oldest_seq: u64,
    /// Last `seq` built.
    pub last_seq: u64,
}

// ---------------------------------------------------------------------------
// Config

/// Which sources run. Each is also capped by the local policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub k8s_events: bool,
    pub logs: bool,
    pub ebpf: bool,
    /// YARA scanning of exec'd binaries and written files (needs `ebpf`).
    pub rules: bool,
    /// Inventory of new pod images (reachability, SBOM).
    pub vulns: bool,
}

/// What mlab chooses (`configure`), within the local policy's [`Settings`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub sources: Sources,
    /// eBPF kinds (`exec`, `connect`, `file_write`); empty = all.
    pub kinds: Vec<String>,
    /// Empty = every namespace the policy allows.
    pub namespaces: Vec<String>,
    /// Events below are not sent (k8s events and logs are `normal` / `info`).
    pub min_severity: Severity,
    /// A ruleset name from the policy's `rulesets`.
    pub ruleset: Option<String>,
    /// YARA source sent by mlab, used instead of `ruleset` (only when the
    /// policy sets `allow_remote_rules`).
    pub rules_source: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sources: Sources {
                k8s_events: true,
                logs: false,
                ebpf: true,
                rules: false,
                vulns: true,
            },
            kinds: Vec::new(),
            namespaces: Vec::new(),
            min_severity: Severity::Info,
            ruleset: None,
            rules_source: None,
        }
    }
}

/// Largest `rules_source` accepted.
pub const MAX_RULES_SOURCE: usize = 1024 * 1024;

/// `configure`'s answer: what is in force now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configured {
    pub config: Config,
    /// What the local policy cut, in words (`logs not allowed by policy`).
    pub clamped: Vec<String>,
}

/// The tool's table in the agent's local policy (`[tools.k3sec.settings]`),
/// written by the host admin, never by mlab: the ceiling of every [`Config`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// Sources mlab may turn on.
    pub allow: Sources,
    /// Namespaces mlab may watch; empty = all.
    pub namespaces: Vec<String>,
    /// Named YARA rule files or directories on the host.
    pub rulesets: BTreeMap<String, String>,
    pub allow_remote_rules: bool,
    /// This node's name (`$NODE_NAME` otherwise).
    pub node: Option<String>,
    /// Kubeconfig path; in-cluster config otherwise.
    pub kubeconfig: Option<String>,
    /// Events held for `events_since` (memory bound).
    pub backlog_events: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow: Sources {
                k8s_events: true,
                logs: false,
                ebpf: true,
                rules: true,
                vulns: true,
            },
            namespaces: Vec::new(),
            rulesets: BTreeMap::new(),
            allow_remote_rules: false,
            node: None,
            kubeconfig: None,
            backlog_events: 50_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Status

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub api_version: u16,
    pub k3sec_version: String,
    pub boot_id: String,
    /// Unix milliseconds.
    pub started_at: i64,
    pub node: String,
    /// UID of the cluster's `kube-system` namespace: a stable cluster id.
    pub cluster_id: Option<String>,
    pub node_versions: Option<NodeVersions>,
    pub config: Config,
    /// The policy ceiling, as mlab may show it (ruleset names, no paths).
    pub allow: Sources,
    pub allowed_namespaces: Vec<String>,
    pub rulesets: Vec<String>,
    pub allow_remote_rules: bool,
    pub sources: Vec<SourceState>,
    pub counters: Counters,
    /// Images inventoried so far.
    pub images: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceState {
    /// `k8s_events`, `logs`, `ebpf`, `rules`, `vulns`.
    pub name: String,
    /// `running`, `off` (config or policy), `failed`.
    pub state: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    /// Events put in batches.
    pub events: u64,
    /// Events dropped because the buffer was full.
    pub dropped: u64,
    /// Last batch `seq` built.
    pub last_seq: u64,
}

// ---------------------------------------------------------------------------
// Inventory / SBOM ops

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRequest {
    /// One image digest, or every image inventoried on the node.
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    pub digest: String,
}

/// Body of an `inventory` answer, next to the blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryInfo {
    pub images: u32,
    pub packages: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryReady {
    pub digest: String,
    pub image: String,
    pub packages: u32,
    /// Packages tagged loaded.
    pub loaded: u32,
}
