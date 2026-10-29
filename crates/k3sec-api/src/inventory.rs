//! The inventory document (`inventory` blob): what runs on a node, per image,
//! with each package's reachability and the coordinate to match it with.
//! Vulnerability matching happens on the mlab side, from these coordinates.

use serde::{Deserialize, Serialize};

use crate::ApiError;

pub const INVENTORY_FORMAT: &str = "k3sec-inventory";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// [`INVENTORY_FORMAT`].
    pub format: String,
    pub api_version: u16,
    /// Unix milliseconds.
    pub generated_at: i64,
    pub node: String,
    pub cluster_id: Option<String>,
    pub node_versions: Option<NodeVersions>,
    pub images: Vec<ImageInventory>,
}

impl Inventory {
    pub fn encode(&self) -> Result<Vec<u8>, ApiError> {
        crate::to_cbor(self)
    }

    /// Decode, refusing another format or contract version.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApiError> {
        let inv: Inventory = crate::from_cbor(bytes)?;
        if inv.format != INVENTORY_FORMAT {
            return Err(ApiError::Decode(format!(
                "not a k3sec inventory: {}",
                inv.format
            )));
        }
        crate::check_version(inv.api_version)?;
        Ok(inv)
    }
}

/// From the node's `status.nodeInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeVersions {
    pub kubelet: String,
    pub container_runtime: String,
    pub kernel: String,
    pub os_image: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageInventory {
    pub image: String,
    pub digest: Option<String>,
    /// os-release `ID`, `VERSION_ID`, `PRETTY_NAME`.
    pub os: Option<Os>,
    pub containers: Vec<Container>,
    pub packages: Vec<Package>,
    pub mapped_files: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Os {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub container_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// `os`, `lang` or `node`.
    pub kind: String,
    pub purl: String,
    /// Source package, when it differs from `name`.
    pub source: Option<String>,
    /// Lockfile or binary a language dependency was read from.
    pub location: Option<String>,
    /// `loaded`, `dormant` or `unknown`.
    pub reachability: String,
    /// What to ask vuln.mlab.sh `/api/v2/scan` for; `None` = not matchable.
    pub coordinate: Option<Coordinate>,
}

/// A vuln.mlab.sh `ScanCoordinate`, as k3sec builds it (distro packages by
/// source package and version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
}

/// Body of an `sbom` answer, next to the CycloneDX blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomInfo {
    pub digest: String,
    pub components: u32,
}
