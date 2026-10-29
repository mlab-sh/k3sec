//! Inventory data model: packages, their reachability, and per-image results.

use serde::{Deserialize, Serialize};

use k3sec_core::PodContainer;

use crate::os::OsRelease;

/// Whether a package's code is actually in memory on the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reachability {
    /// At least one of its files is mapped by (or was exec'd in) a container process.
    Loaded,
    /// An OS package none of whose files is mapped or executed.
    Dormant,
    /// Not determinable (language dependencies).
    Unknown,
}

impl Reachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Reachability::Loaded => "loaded",
            Reachability::Dormant => "dormant",
            Reachability::Unknown => "unknown",
        }
    }
}

/// Where a package comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageKind {
    /// OS package manager (dpkg / apk / rpm).
    Os,
    /// Language dependency (lockfile or Go binary build info).
    Lang,
    /// The node's own stack (k3s, containerd, kernel).
    Node,
}

/// A coordinate in the shape `POST /api/v2/scan` takes (`ScanCoordinate`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Coordinate {
    Eco {
        ecosystem: String,
        name: String,
        version: String,
    },
    Purl {
        purl: String,
    },
    Cpe {
        cpe: String,
    },
}

impl Coordinate {
    pub fn eco(ecosystem: impl Into<String>, name: &str, version: &str) -> Self {
        Coordinate::Eco {
            ecosystem: ecosystem.into(),
            name: name.to_string(),
            version: version.to_string(),
        }
    }
}

/// One installed package or dependency.
#[derive(Debug, Clone, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub kind: PackageKind,
    pub purl: String,
    /// Source package, when it differs from `name` (dpkg `Source`, apk origin).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Lockfile or binary a language dependency was read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub reachability: Reachability,
    /// Files owned by the package (in-container paths), for the loaded tag.
    #[serde(skip)]
    pub files: Vec<String>,
    /// How to match it against vulns; `None` = ecosystem not covered.
    #[serde(skip)]
    pub coordinate: Option<Coordinate>,
}

impl Package {
    pub fn new(name: &str, version: &str, kind: PackageKind, purl: String) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            kind,
            purl,
            source: None,
            location: None,
            reachability: match kind {
                PackageKind::Os => Reachability::Dormant,
                PackageKind::Lang => Reachability::Unknown,
                PackageKind::Node => Reachability::Loaded,
            },
            files: Vec::new(),
            coordinate: None,
        }
    }
}

/// The inventory of one image (deduplicated by digest across pods).
#[derive(Debug, Clone, Serialize)]
pub struct ImageInventory {
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsRelease>,
    /// Every running container using this image.
    pub containers: Vec<PodContainer>,
    pub packages: Vec<Package>,
    /// Distinct files mapped by the containers' processes.
    pub mapped_files: usize,
    /// Non-fatal problems (unsupported package db, unreadable lockfile, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ImageInventory {
    /// The deduplication / cache key: digest, else image ref.
    pub fn key(&self) -> &str {
        self.digest.as_deref().unwrap_or(&self.image)
    }

    pub fn count(&self, r: Reachability) -> usize {
        self.packages.iter().filter(|p| p.reachability == r).count()
    }
}
