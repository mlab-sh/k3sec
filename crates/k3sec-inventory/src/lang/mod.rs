//! Language dependencies, best effort: a bounded walk of the usual app
//! directories for lockfiles, plus Go build info from executables and Maven
//! coordinates from Java archives.

pub mod gobuild;
pub mod jar;
pub mod lockfiles;
pub mod npm;
pub mod python;
pub mod rust;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::model::{Coordinate, Package, PackageKind};
use crate::purl;
use crate::rootfs::{read_file_limited, Rootfs};

use lockfiles::Lockfile;

/// Where application code usually lives in an image.
const ROOTS: &[&str] = &[
    "/app",
    "/usr/src/app",
    "/srv",
    "/opt",
    "/home",
    "/root",
    "/var/www",
    "/workspace",
    "/code",
    "/usr/local/bin",
    "/usr/local/lib",
];
const SKIP_DIRS: &[&str] = &[".git", "__pycache__", ".cache", "proc", "sys", "dev"];

/// Bounds on the lockfile / binary walk.
#[derive(Debug, Clone)]
pub struct LangLimits {
    pub max_depth: usize,
    /// Directory entries visited across all roots.
    pub max_entries: usize,
    pub max_lockfile_size: u64,
    pub max_binary_size: u64,
    /// Executables and Java archives inspected (each is read whole).
    pub max_binaries: usize,
}

impl Default for LangLimits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            // Home Assistant's site-packages alone has ~150 000 entries.
            max_entries: 200_000,
            max_lockfile_size: 32 * 1024 * 1024,
            max_binary_size: 256 * 1024 * 1024,
            // A JVM keeps a few hundred jars open (Elasticsearch: ~250).
            max_binaries: 2048,
        }
    }
}

/// Collect language deps from lockfiles under [`ROOTS`], from Go build info
/// and Java archives in `executables` (in-container paths: the running
/// binaries and the jars processes hold open) and in those met during the walk.
///
/// `roots` are walked too: the working directories of the container's
/// processes, where an app lives when it is not under [`ROOTS`]
/// (`/var/lib/ghost`, `/usr/src/redmine`).
pub fn scan(
    fs: &Rootfs,
    executables: &[String],
    roots: &[String],
    limits: &LangLimits,
) -> Vec<Package> {
    let mut walk = Walk {
        fs,
        limits,
        visited: 0,
        lockfiles: Vec::new(),
        binaries: executables.to_vec(),
        python: Vec::new(),
        node_trees: Vec::new(),
    };
    let mut walked: Vec<String> = Vec::new();
    for root in ROOTS
        .iter()
        .copied()
        .chain(roots.iter().map(String::as_str))
    {
        let Some(canon) = fs.resolve(root) else {
            continue;
        };
        // `/` as a working directory would walk the whole image.
        if canon == "/"
            || walked
                .iter()
                .any(|w| canon.starts_with(&format!("{w}/")) || *w == canon)
        {
            continue;
        }
        walk.dir(&canon, 0);
        walked.push(canon);
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |eco: &str, name: &str, version: &str, location: &str, files: Vec<String>| {
        let purl = purl::lang(eco, name, version);
        if seen.insert(purl.clone()) {
            let mut p = Package::new(name, version, PackageKind::Lang, purl);
            p.coordinate = Some(Coordinate::eco(eco, name, version));
            p.location = Some(location.to_string());
            p.files = files;
            out.push(p);
        }
    };

    for (path, kind) in &walk.lockfiles {
        let Ok(content) = fs.read_string(path, limits.max_lockfile_size) else {
            continue;
        };
        for (name, version) in kind.parse(&content) {
            push(kind.ecosystem(), &name, &version, path, Vec::new());
        }
    }

    // node_modules trees with no hidden lockfile: each module's package.json.
    let mut budget = npm::MAX_PACKAGES;
    for tree in &walk.node_trees {
        for (name, version, at) in npm::modules(fs, tree, &mut budget) {
            push("npm", &name, &version, &at, Vec::new());
        }
    }

    // Installed Python distributions; a mapped C extension makes one loaded.
    for dist in &walk.python {
        let meta = ["METADATA", "PKG-INFO"]
            .iter()
            .find_map(|f| fs.read_string(&format!("{dist}/{f}"), 1024 * 1024).ok());
        let Some((name, version)) = meta.as_deref().and_then(python::metadata) else {
            continue;
        };
        let site = dist.rsplit_once('/').map_or("/", |(s, _)| s);
        let files = fs
            .read_string(&format!("{dist}/RECORD"), 16 * 1024 * 1024)
            .map(|r| python::shared_objects(&r, site))
            .unwrap_or_default();
        push("PyPI", &name, &version, dist, files);
    }

    // Running binaries come first, so the cap only ever drops walk finds.
    let mut seen_bins = HashSet::new();
    let bins = walk
        .binaries
        .into_iter()
        .filter(|b| seen_bins.insert(b.clone()));
    for path in &bins.take(limits.max_binaries).collect::<Vec<_>>() {
        let Some(host) = fs.host_path(path) else {
            continue;
        };
        // An ELF's build info section alone, whatever the binary's size.
        // A Rust binary built with cargo-auditable lists its crates.
        if let Some(deps) = gobuild::section(&host, ".dep-v0") {
            for (name, version) in rust::crates(&deps) {
                push("crates.io", &name, &version, path, Vec::new());
            }
            continue;
        }
        let bytes = match gobuild::section(&host, ".go.buildinfo") {
            Some(section) => section,
            None => match read_file_limited(&host, limits.max_binary_size) {
                Ok(b) => b,
                Err(_) => continue,
            },
        };
        if bytes.starts_with(b"PK\x03\x04") {
            for (name, version) in jar::parse(&bytes) {
                push("Maven", &name, &version, path, Vec::new());
            }
            continue;
        }
        if !bytes.starts_with(b"\x7fELF") && !bytes.starts_with(gobuild::MAGIC) {
            continue;
        }
        if let Some(info) = gobuild::parse(&bytes) {
            if !info.go_version.is_empty() {
                push("Go", "stdlib", &info.go_version, path, Vec::new());
            }
            for (module, version) in &info.deps {
                push("Go", module, version, path, Vec::new());
            }
        }
    }
    out
}

pub fn is_java_archive(path: &str) -> bool {
    path.ends_with(".jar") || path.ends_with(".war")
}

struct Walk<'a> {
    fs: &'a Rootfs,
    limits: &'a LangLimits,
    visited: usize,
    lockfiles: Vec<(String, Lockfile)>,
    binaries: Vec<String>,
    /// `*.dist-info` / `*.egg-info` directories.
    python: Vec<String>,
    /// `node_modules` directories without npm's hidden lockfile.
    node_trees: Vec<String>,
}

impl Walk<'_> {
    /// `path` is canonical; symlinks met inside are not followed (no loops,
    /// no escapes, and the target is usually covered by another root).
    fn dir(&mut self, path: &str, depth: usize) {
        if depth > self.limits.max_depth {
            return;
        }
        let host = self.fs.root().join(path.trim_start_matches('/'));
        let Ok(entries) = fs::read_dir(host) else {
            return;
        };
        for entry in entries.flatten() {
            self.visited += 1;
            if self.visited > self.limits.max_entries {
                return;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = format!("{}/{name}", path.trim_end_matches('/'));
            let Ok(meta) = entry.metadata() else {
                continue; // `DirEntry::metadata` does not follow symlinks
            };
            if meta.is_dir() {
                if name.ends_with(".dist-info") || name.ends_with(".egg-info") {
                    self.python.push(child);
                } else if name == "node_modules" {
                    // npm ≥ 7's hidden lockfile describes the whole tree.
                    let hidden = format!("{child}/.package-lock.json");
                    if self.fs.exists(&hidden) {
                        self.lockfiles.push((hidden, Lockfile::PackageLock));
                    } else {
                        self.node_trees.push(child);
                    }
                } else if !SKIP_DIRS.contains(&name.as_str()) {
                    self.dir(&child, depth + 1);
                }
            } else if meta.is_file() {
                if let Some(kind) = Lockfile::from_name(&name) {
                    self.lockfiles.push((child, kind));
                } else if meta.permissions().mode() & 0o111 != 0
                    || (is_java_archive(&name) && meta.len() <= self.limits.max_binary_size)
                {
                    self.binaries.push(child);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_distributions_from_site_packages() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("usr/local/lib/python3.12/site-packages");
        let dist = site.join("aiohttp-3.9.1.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            "Metadata-Version: 2.1\nName: aiohttp\nVersion: 3.9.1\n\n",
        )
        .unwrap();
        std::fs::write(
            dist.join("RECORD"),
            "aiohttp/_parser.cpython-312-x86_64-linux-gnu.so,sha256=x,1\naiohttp/web.py,,\n",
        )
        .unwrap();
        let egg = dir
            .path()
            .join("opt/app/venv/lib/python3.12/site-packages/six-1.16.0.egg-info");
        std::fs::create_dir_all(&egg).unwrap();
        std::fs::write(egg.join("PKG-INFO"), "Name: six\nVersion: 1.16.0\n").unwrap();

        let pkgs = scan(&Rootfs::new(dir.path()), &[], &[], &LangLimits::default());
        let aiohttp = pkgs.iter().find(|p| p.name == "aiohttp").unwrap();
        assert_eq!(aiohttp.purl, "pkg:pypi/aiohttp@3.9.1");
        assert_eq!(
            aiohttp.files,
            ["/usr/local/lib/python3.12/site-packages/aiohttp/_parser.cpython-312-x86_64-linux-gnu.so"]
        );
        assert!(pkgs.iter().any(|p| p.purl == "pkg:pypi/six@1.16.0"));
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn walk_finds_lockfiles_and_skips_node_modules_contents() {
        let dir = tempfile::tempdir().unwrap();
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lockfiles");
        let app = dir.path().join("app");
        std::fs::create_dir_all(app.join("node_modules/express")).unwrap();
        std::fs::copy(
            fx.join("v3/package-lock.json"),
            app.join("package-lock.json"),
        )
        .unwrap();
        // A lockfile inside node_modules must not be read (only the hidden one is).
        std::fs::copy(
            fx.join("v1/package-lock.json"),
            app.join("node_modules/express/package-lock.json"),
        )
        .unwrap();
        std::fs::copy(fx.join("Cargo.lock"), app.join("Cargo.lock")).unwrap();

        let pkgs = scan(&Rootfs::new(dir.path()), &[], &[], &LangLimits::default());
        assert!(pkgs.iter().any(
            |p| p.name == "express" && p.location.as_deref() == Some("/app/package-lock.json")
        ));
        assert!(pkgs.iter().any(|p| p.purl == "pkg:cargo/serde@1.0.197"));
        assert!(
            !pkgs.iter().any(|p| p.name == "lodash"),
            "node_modules not descended"
        );
        assert!(pkgs
            .iter()
            .all(|p| p.reachability == crate::model::Reachability::Unknown));
    }

    #[test]
    fn depth_limit_is_respected() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("app/a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("requirements.txt"), "Django==4.2.10\n").unwrap();
        let limits = LangLimits {
            max_depth: 1,
            ..LangLimits::default()
        };
        assert!(scan(&Rootfs::new(dir.path()), &[], &[], &limits).is_empty());
        assert_eq!(
            scan(&Rootfs::new(dir.path()), &[], &[], &LangLimits::default()).len(),
            1
        );
    }
}
