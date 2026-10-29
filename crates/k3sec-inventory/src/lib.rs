//! k3sec-inventory, runtime-aware vulnerability inventory.
//!
//! For every container running on the node: read its live filesystem through
//! `/proc/<pid>/root`, inventory OS packages (dpkg / apk / rpm) and language
//! dependencies, emit a CycloneDX SBOM per image digest, and tag each package
//! **loaded** (one of its files is mapped by a container process), **dormant**
//! (OS package, nothing mapped) or **unknown** (language deps). Vulnerabilities
//! are then matched through a [`VulnSource`] (vuln.mlab.sh by default).
//!
//! Depends only on `k3sec-core`: pods come in as [`PodContainer`]s listed by
//! the caller (the CLI, via `k3sec-k8s`).
//!
//! [`PodContainer`]: k3sec_core::PodContainer

pub mod cache;
pub mod inventory;
pub mod lang;
pub mod mlab;
pub mod model;
pub mod os;
pub mod pkgdb;
pub mod procfs;
pub mod purl;
pub mod reach;
pub mod rootfs;
pub mod sbom;
pub mod vuln;

pub use cache::Cache;
pub use inventory::{group_by_image, node_inventory, scan_image, ImageScan};
pub use lang::LangLimits;
pub use mlab::MlabClient;
pub use model::{Coordinate, ImageInventory, Package, PackageKind, Reachability};
pub use procfs::{check_root_access, pids_by_container};
pub use vuln::{match_images, Finding, ImageVulns, VulnSeverity, VulnSource};
