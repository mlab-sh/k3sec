//! From the `k3sec-api` v1 inventory (what `k3sec serve` uploads) back to
//! this crate's model, so the mlab backend runs the same matching as the CLI
//! (`match_images`) on what it received.

use k3sec_api as api;
use k3sec_core::PodContainer;

use crate::model::{Coordinate, ImageInventory, Package, PackageKind, Reachability};
use crate::os::OsRelease;

pub fn from_api(img: &api::ImageInventory) -> ImageInventory {
    ImageInventory {
        image: img.image.clone(),
        digest: img.digest.clone(),
        os: img.os.as_ref().map(|o| OsRelease {
            id: o.id.clone(),
            version_id: o.version_id.clone(),
            pretty_name: o.pretty_name.clone(),
        }),
        containers: img
            .containers
            .iter()
            .map(|c| PodContainer {
                namespace: c.namespace.clone(),
                pod: c.pod.clone(),
                container: c.container.clone(),
                image: img.image.clone(),
                image_digest: img.digest.clone(),
                container_id: c.container_id.clone(),
            })
            .collect(),
        packages: img.packages.iter().map(package).collect(),
        mapped_files: img.mapped_files as usize,
        warnings: img.warnings.clone(),
    }
}

fn package(p: &api::Package) -> Package {
    let kind = match p.kind.as_str() {
        "lang" => PackageKind::Lang,
        "node" => PackageKind::Node,
        _ => PackageKind::Os,
    };
    let mut out = Package::new(&p.name, &p.version, kind, p.purl.clone());
    out.reachability = match p.reachability.as_str() {
        "loaded" => Reachability::Loaded,
        "dormant" => Reachability::Dormant,
        _ => Reachability::Unknown,
    };
    out.source = p.source.clone();
    out.location = p.location.clone();
    out.coordinate = p.coordinate.as_ref().and_then(coordinate);
    out
}

fn coordinate(c: &api::Coordinate) -> Option<Coordinate> {
    match (&c.ecosystem, &c.name, &c.version, &c.purl, &c.cpe) {
        (Some(e), Some(n), Some(v), _, _) => Some(Coordinate::eco(e.clone(), n, v)),
        (_, _, _, Some(purl), _) => Some(Coordinate::Purl { purl: purl.clone() }),
        (_, _, _, _, Some(cpe)) => Some(Coordinate::Cpe { cpe: cpe.clone() }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates_and_reachability_survive() {
        let img = api::ImageInventory {
            image: "nginx".into(),
            digest: Some("sha256:1".into()),
            os: None,
            containers: vec![api::inventory::Container {
                namespace: "demo".into(),
                pod: "web".into(),
                container: "nginx".into(),
                container_id: "c1".into(),
            }],
            packages: vec![api::Package {
                name: "libssl3".into(),
                version: "3.0.11".into(),
                kind: "os".into(),
                purl: "pkg:deb/debian/libssl3@3.0.11".into(),
                source: Some("openssl".into()),
                location: None,
                reachability: "loaded".into(),
                coordinate: Some(api::Coordinate {
                    ecosystem: Some("Debian:12".into()),
                    name: Some("openssl".into()),
                    version: Some("3.0.11".into()),
                    purl: None,
                    cpe: None,
                }),
            }],
            mapped_files: 4,
            warnings: vec![],
        };
        let inv = from_api(&img);
        assert_eq!(inv.key(), "sha256:1");
        assert_eq!(inv.containers[0].pod, "web");
        let p = &inv.packages[0];
        assert_eq!(p.reachability, Reachability::Loaded);
        assert_eq!(
            p.coordinate,
            Some(Coordinate::eco("Debian:12", "openssl", "3.0.11"))
        );
    }
}
