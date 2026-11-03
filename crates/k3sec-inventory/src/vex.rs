//! OpenVEX: a vendor's statements that a CVE does not affect, or is fixed in,
//! a package of its images (Docker Hardened Images publish theirs in
//! `github.com/docker-hardened-images/advisories`, `vex/`). Findings so
//! stated are dropped; `under_investigation` and `affected` keep them.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::ImageInventory;
use crate::rootfs::read_file_limited;
use crate::vuln::ImageVulns;

/// A VEX document larger than this is refused.
const MAX_DOC: u64 = 64 * 1024 * 1024;

/// A package a statement names: purl type and name, and its version if given
/// (a product without one covers every version).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Product {
    ty: String,
    name: String,
    version: Option<String>,
}

/// CVE → the packages it is stated not to affect.
#[derive(Debug, Default)]
pub struct Vex {
    cleared: HashMap<String, Vec<Product>>,
}

#[derive(Deserialize)]
struct Doc {
    #[serde(default)]
    statements: Vec<Statement>,
}

#[derive(Deserialize)]
struct Statement {
    vulnerability: Vuln,
    status: String,
    #[serde(default)]
    products: Vec<Component>,
}

#[derive(Deserialize)]
struct Vuln {
    name: String,
}

#[derive(Deserialize)]
struct Component {
    #[serde(rename = "@id")]
    id: String,
    #[serde(default)]
    subcomponents: Vec<Component>,
}

impl Vex {
    /// An OpenVEX file, or every `*.json` under a directory (a clone of the
    /// DHI advisories' `vex/`). Files that are not OpenVEX are skipped.
    pub fn load(path: &Path) -> Result<Self> {
        let mut vex = Vex::default();
        let mut files = Vec::new();
        collect(path, &mut files).with_context(|| format!("cannot read {}", path.display()))?;
        for f in files {
            let bytes = read_file_limited(&f, MAX_DOC)
                .with_context(|| format!("cannot read {}", f.display()))?;
            if let Ok(doc) = serde_json::from_slice::<Doc>(&bytes) {
                vex.add(doc);
            }
        }
        Ok(vex)
    }

    fn add(&mut self, doc: Doc) {
        for s in doc.statements {
            if !matches!(s.status.as_str(), "not_affected" | "fixed") {
                continue;
            }
            let mut products = Vec::new();
            for p in &s.products {
                products.extend(parse_purl(&p.id));
                products.extend(p.subcomponents.iter().filter_map(|c| parse_purl(&c.id)));
            }
            self.cleared
                .entry(s.vulnerability.name)
                .or_default()
                .extend(products);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cleared.is_empty()
    }

    /// Drop the image's findings a statement clears; returns how many.
    pub fn apply(&self, inv: &ImageInventory, vulns: &mut ImageVulns) -> usize {
        let before = vulns.findings.len();
        vulns.findings.retain(|f| {
            let Some(products) = self.cleared.get(&f.id) else {
                return true;
            };
            let Some(pkg) = parse_purl(&f.purl) else {
                return true;
            };
            let source = inv
                .packages
                .iter()
                .find(|p| p.purl == f.purl)
                .and_then(|p| p.source.clone());
            !products.iter().any(|p| {
                p.ty == pkg.ty
                    && (p.name == pkg.name || Some(&p.name) == source.as_ref())
                    && p.version
                        .as_ref()
                        .is_none_or(|v| Some(v) == pkg.version.as_ref())
            })
        });
        before - vulns.findings.len()
    }
}

/// Docker Hardened Images say so in os-release (`ID=dhi` after their cutover).
pub fn is_hardened_image(inv: &ImageInventory) -> bool {
    inv.os
        .as_ref()
        .is_some_and(|o| o.id == "dhi" || o.pretty_name.starts_with("Docker Hardened Images"))
}

fn collect(path: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let p = entry?.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else if p.extension().is_some_and(|e| e == "json") {
            out.push(p);
        }
    }
    Ok(())
}

/// `pkg:deb/debian/libc6@2.41-12%2Bdhi1?arch=amd64` → (deb, libc6, 2.41-12+dhi1).
fn parse_purl(purl: &str) -> Option<Product> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next()?;
    let (ty, path) = rest.split_once('/')?;
    let (path, version) = match path.rsplit_once('@') {
        Some((p, v)) => (p, Some(decode(v))),
        None => (path, None),
    };
    let name = decode(path.rsplit('/').next()?);
    Some(Product {
        ty: ty.to_ascii_lowercase(),
        name,
        version,
    })
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| s.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Package, PackageKind, Reachability};
    use crate::os::OsRelease;
    use crate::vuln::{Finding, VulnSeverity};

    const DOC: &str = r#"{
      "@context": "https://openvex.dev/ns/v0.2.0",
      "statements": [
        {"vulnerability": {"name": "CVE-2026-1"}, "status": "not_affected",
         "products": [{"@id": "pkg:deb/debian/glibc@2.41-12%2Bdhi1?os_distro=trixie"}]},
        {"vulnerability": {"name": "CVE-2026-2"}, "status": "under_investigation",
         "products": [{"@id": "pkg:deb/debian/glibc"}]},
        {"vulnerability": {"name": "CVE-2026-3"}, "status": "fixed",
         "products": [{"@id": "pkg:docker/dhi/nginx", "subcomponents": [{"@id": "pkg:deb/debian/openssl"}]}]},
        {"vulnerability": {"name": "CVE-2026-4"}, "status": "not_affected",
         "products": [{"@id": "pkg:deb/debian/glibc@2.40-1"}]}
      ]
    }"#;

    fn finding(id: &str, name: &str, version: &str) -> Finding {
        Finding {
            id: id.into(),
            advisories: vec![],
            package: name.into(),
            version: version.into(),
            purl: format!(
                "pkg:deb/debian/{name}@{}?arch=amd64",
                version.replace('+', "%2B")
            ),
            severity: VulnSeverity::High,
            cvss: None,
            kev: Some(false),
            fixed: None,
            summary: String::new(),
            reachability: Reachability::Loaded,
        }
    }

    #[test]
    fn statements_clear_by_name_source_and_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("vex/nginx")).unwrap();
        std::fs::write(dir.path().join("vex/nginx/dhi-nginx.vex.json"), DOC).unwrap();
        std::fs::write(dir.path().join("vex/README.json"), b"[1, 2]").unwrap();
        let vex = Vex::load(&dir.path().join("vex")).unwrap();

        let libc = finding("CVE-2026-1", "libc6", "2.41-12+dhi1");
        let mut pkg = Package::new("libc6", "2.41-12+dhi1", PackageKind::Os, libc.purl.clone());
        pkg.source = Some("glibc".into());
        let inv = ImageInventory {
            image: "dhi.io/nginx:1.31.8-debian13".into(),
            digest: None,
            os: Some(OsRelease::parse(
                "ID=debian\nPRETTY_NAME=\"Docker Hardened Images/Debian GNU/Linux 13 (trixie)\"\n",
            )),
            containers: vec![],
            packages: vec![pkg],
            mapped_files: 0,
            warnings: vec![],
        };
        assert!(is_hardened_image(&inv));

        let mut v = ImageVulns {
            findings: vec![
                libc.clone(),                                   // cleared via its source
                finding("CVE-2026-2", "libc6", "2.41-12+dhi1"), // under investigation: kept
                finding("CVE-2026-3", "openssl", "3.5.4-1"),    // fixed, any version
                finding("CVE-2026-4", "libc6", "2.41-12+dhi1"), // other version: kept
                finding("CVE-2026-9", "libc6", "2.41-12+dhi1"), // no statement
            ],
            ..Default::default()
        };
        assert_eq!(vex.apply(&inv, &mut v), 2);
        let left: Vec<_> = v.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(left, ["CVE-2026-2", "CVE-2026-4", "CVE-2026-9"]);
    }
}
