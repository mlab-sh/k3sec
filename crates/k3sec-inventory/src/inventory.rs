//! Inventory orchestration: containers → images (dedup by digest) → packages
//! with reachability, plus the node's own stack.

use std::collections::{BTreeSet, HashMap};

use k3sec_core::{NodeVersions, PodContainer};

use crate::lang::{self, LangLimits};
use crate::model::{Coordinate, ImageInventory, Package, PackageKind};
use crate::os::OsRelease;
use crate::pkgdb;
use crate::procfs;
use crate::purl;
use crate::reach::{mark_loaded, FileIndex};
use crate::rootfs::Rootfs;

/// An inventoried image plus what's needed to re-tag it later (exec events).
pub struct ImageScan {
    pub inventory: ImageInventory,
    pub index: FileIndex,
    pub rootfs: Rootfs,
}

/// Group containers by image key (digest), keeping first-seen order.
pub fn group_by_image(containers: Vec<PodContainer>) -> Vec<Vec<PodContainer>> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<PodContainer>> = HashMap::new();
    for c in containers {
        let key = c.image_key().to_string();
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(c);
    }
    order
        .into_iter()
        .filter_map(|k| groups.remove(&k))
        .collect()
}

/// Inventory one image from the live processes of its `containers`.
/// `None` when none of them has a process on this host.
pub fn scan_image(
    containers: Vec<PodContainer>,
    pids_by_container: &HashMap<String, Vec<u32>>,
    limits: &LangLimits,
) -> Option<ImageScan> {
    // Pods of other nodes (no --node given) have no process here.
    let containers: Vec<PodContainer> = containers
        .into_iter()
        .filter(|c| pids_by_container.contains_key(&c.container_id))
        .collect();
    let pids: Vec<u32> = containers
        .iter()
        .filter_map(|c| pids_by_container.get(&c.container_id))
        .flatten()
        .copied()
        .collect();
    // Containers of one image share its content; any live root will do.
    let rootfs = pids
        .iter()
        .map(|&pid| Rootfs::of_pid(pid))
        .find(|fs| std::fs::read_dir(fs.root()).is_ok())?;
    let first = containers.first()?;

    let os = OsRelease::read(&rootfs);
    let (mut packages, mut warnings) = pkgdb::read(&rootfs, os.as_ref());
    if packages.is_empty() && warnings.is_empty() {
        warnings.push("no OS package database found (scratch or distroless-static image?)".into());
    }
    let index = FileIndex::build(&rootfs, &packages);

    let mapped: BTreeSet<String> = pids.iter().flat_map(|&p| procfs::mapped_files(p)).collect();
    mark_loaded(
        &mut packages,
        &index,
        &rootfs,
        mapped.iter().map(String::as_str),
    );

    let exes: Vec<String> = pids
        .iter()
        .filter_map(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok())
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .collect();
    let mut lang = lang::scan(&rootfs, &exes, limits);
    crate::reach::mark_running_binaries(&mut lang, &exes);
    packages.extend(lang);

    let inventory = ImageInventory {
        image: first.image.clone(),
        digest: first.image_digest.clone(),
        os,
        containers,
        packages,
        mapped_files: mapped.len(),
        warnings,
    };
    Some(ImageScan {
        inventory,
        index,
        rootfs,
    })
}

/// The node's k3s / containerd (and, opt-in, kernel) as a pseudo-image.
///
/// The kernel is matched by CPE against NVD, which knows nothing of distro
/// backports: thousands of hits for any version, hence `match_kernel`.
pub fn node_inventory(v: &NodeVersions, match_kernel: bool) -> ImageInventory {
    let mut packages = Vec::new();
    let go = |module: &str, version: &str| {
        let mut p = Package::new(
            module.rsplit('/').next().unwrap_or(module),
            version,
            PackageKind::Node,
            purl::lang("Go", module, version),
        );
        p.coordinate = Some(Coordinate::eco("Go", module, version));
        p
    };

    if !v.kubelet.is_empty() {
        let mut p = if v.kubelet.contains("+k3s") {
            go("github.com/k3s-io/k3s", &v.kubelet)
        } else {
            // k0s ships upstream kubelet: `v1.33.4+k0s` is matched as `v1.33.4`.
            go(
                "k8s.io/kubernetes",
                v.kubelet.split("+k0s").next().unwrap_or(&v.kubelet),
            )
        };
        p.name = if v.kubelet.contains("+k3s") {
            "k3s"
        } else if v.kubelet.contains("+k0s") {
            "k0s"
        } else {
            "kubernetes"
        }
        .into();
        p.version = v.kubelet.clone();
        packages.push(p);
    }
    if let Some(ver) = v.container_runtime.strip_prefix("containerd://") {
        // k3s ships `2.1.4-k3s1`: advisories are filed against upstream `v2.1.4`.
        let upstream = format!("v{}", ver.split("-k3s").next().unwrap_or(ver));
        let module = if upstream.starts_with("v1.") {
            "github.com/containerd/containerd"
        } else {
            "github.com/containerd/containerd/v2"
        };
        let mut p = go(module, &upstream);
        p.name = "containerd".into();
        p.version = ver.to_string();
        packages.push(p);
    }
    if !v.kernel.is_empty() {
        let upstream: String = v
            .kernel
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .next()
            .unwrap_or("")
            .to_string();
        let mut p = Package::new(
            "linux",
            &v.kernel,
            PackageKind::Node,
            purl::build("generic", None, "linux", &v.kernel, &[]),
        );
        if match_kernel && !upstream.is_empty() {
            p.coordinate = Some(Coordinate::Cpe {
                cpe: format!("cpe:2.3:o:linux:linux_kernel:{upstream}:*:*:*:*:*:*:*"),
            });
        }
        packages.push(p);
    }

    ImageInventory {
        image: format!("node/{}", v.node),
        digest: None,
        os: Some(OsRelease {
            id: "node".into(),
            version_id: String::new(),
            pretty_name: v.os_image.clone(),
        }),
        containers: Vec::new(),
        packages,
        mapped_files: 0,
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(pod: &str, digest: &str) -> PodContainer {
        PodContainer {
            namespace: "default".into(),
            pod: pod.into(),
            container: "app".into(),
            image: "nginx:1.27".into(),
            image_digest: Some(digest.into()),
            container_id: format!("{pod}-cid"),
        }
    }

    #[test]
    fn images_dedup_by_digest() {
        let groups = group_by_image(vec![
            container("a", "sha256:1"),
            container("b", "sha256:2"),
            container("c", "sha256:1"),
        ]);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[0][1].pod, "c");
    }

    #[test]
    fn containers_without_local_pids_are_skipped() {
        let scan = scan_image(
            vec![container("a", "sha256:1")],
            &HashMap::new(),
            &LangLimits::default(),
        );
        assert!(scan.is_none());
    }

    #[test]
    fn node_stack_coordinates() {
        let inv = node_inventory(
            &NodeVersions {
                node: "n1".into(),
                kubelet: "v1.33.5+k3s1".into(),
                container_runtime: "containerd://2.1.4-k3s1".into(),
                kernel: "6.8.0-45-generic".into(),
                os_image: "Ubuntu".into(),
            },
            false,
        );
        let by = |n: &str| inv.packages.iter().find(|p| p.name == n).unwrap();
        assert_eq!(
            by("k3s").coordinate,
            Some(Coordinate::eco(
                "Go",
                "github.com/k3s-io/k3s",
                "v1.33.5+k3s1"
            ))
        );
        assert_eq!(
            by("containerd").coordinate,
            Some(Coordinate::eco(
                "Go",
                "github.com/containerd/containerd/v2",
                "v2.1.4"
            ))
        );
        assert_eq!(by("linux").coordinate, None, "kernel matching is opt-in");

        let k0s = node_inventory(
            &NodeVersions {
                kubelet: "v1.33.4+k0s".into(),
                container_runtime: "containerd://1.7.27".into(),
                ..Default::default()
            },
            false,
        );
        let by = |n: &str| k0s.packages.iter().find(|p| p.name == n).unwrap();
        assert_eq!(by("k0s").version, "v1.33.4+k0s");
        assert_eq!(
            by("k0s").coordinate,
            Some(Coordinate::eco("Go", "k8s.io/kubernetes", "v1.33.4"))
        );
        assert_eq!(
            by("containerd").coordinate,
            Some(Coordinate::eco(
                "Go",
                "github.com/containerd/containerd",
                "v1.7.27"
            ))
        );

        let with_kernel = node_inventory(
            &NodeVersions {
                kernel: "6.8.0-45-generic".into(),
                ..Default::default()
            },
            true,
        );
        assert_eq!(
            with_kernel.packages[0].coordinate,
            Some(Coordinate::Cpe {
                cpe: "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".into()
            })
        );
    }
}
