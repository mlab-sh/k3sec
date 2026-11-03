//! `node_modules` trees npm did not describe in a hidden lockfile (Yarn,
//! pnpm-less installs, npm's own global tree): every module's `package.json`,
//! scoped ones (`@scope/name`) and nested `node_modules` included.

use serde::Deserialize;

use crate::rootfs::Rootfs;

/// Modules read per image: Ghost has ~2 500, a monorepo can have far more.
pub const MAX_PACKAGES: usize = 20_000;
/// Nesting of `node_modules/x/node_modules/y/…` followed.
const MAX_NESTING: usize = 8;

#[derive(Deserialize)]
struct PackageJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

/// `(name, version, package.json path)` of the modules under `tree`, at most
/// `budget` more (it is decremented).
pub fn modules(fs: &Rootfs, tree: &str, budget: &mut usize) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut pending = vec![(tree.to_string(), 0)];
    while let Some((dir, depth)) = pending.pop() {
        for module in module_dirs(fs, &dir) {
            if *budget == 0 {
                return out;
            }
            let manifest = format!("{module}/package.json");
            if let Some(pkg) = fs
                .read_limited(&manifest, 1024 * 1024)
                .ok()
                .and_then(|b| serde_json::from_slice::<PackageJson>(&b).ok())
                .filter(|p| !p.name.is_empty() && !p.version.is_empty())
            {
                *budget -= 1;
                out.push((pkg.name, pkg.version, manifest));
            }
            let nested = format!("{module}/node_modules");
            if depth < MAX_NESTING && fs.exists(&nested) {
                pending.push((nested, depth + 1));
            }
        }
    }
    out
}

/// The module directories of one `node_modules`: `x`, and `@scope/y`.
fn module_dirs(fs: &Rootfs, node_modules: &str) -> Vec<String> {
    let list = |dir: &str| -> Vec<String> {
        let Some(canon) = fs.resolve(dir) else {
            return Vec::new();
        };
        std::fs::read_dir(fs.root().join(canon.trim_start_matches('/')))
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| !n.starts_with('.'))
                    .map(|n| format!("{}/{n}", dir.trim_end_matches('/')))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for d in list(node_modules) {
        if d.rsplit('/').next().is_some_and(|n| n.starts_with('@')) {
            out.extend(list(&d));
        } else {
            out.push(d);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(root: &std::path::Path, dir: &str, name: &str, version: &str) {
        let d = root.join(dir.trim_start_matches('/'));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}","dependencies":{{}}}}"#),
        )
        .unwrap();
    }

    #[test]
    fn reads_modules_scoped_and_nested_within_budget() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        module(r, "/app/node_modules/express", "express", "4.17.1");
        module(r, "/app/node_modules/@babel/core", "@babel/core", "7.24.0");
        module(
            r,
            "/app/node_modules/express/node_modules/qs",
            "qs",
            "6.7.0",
        );
        std::fs::create_dir_all(r.join("app/node_modules/.bin")).unwrap();
        std::fs::create_dir_all(r.join("app/node_modules/no-manifest")).unwrap();

        let fs = Rootfs::new(r);
        let mut budget = MAX_PACKAGES;
        let mut got: Vec<_> = modules(&fs, "/app/node_modules", &mut budget)
            .into_iter()
            .map(|(n, v, _)| format!("{n}@{v}"))
            .collect();
        got.sort();
        assert_eq!(got, ["@babel/core@7.24.0", "express@4.17.1", "qs@6.7.0"]);
        assert_eq!(budget, MAX_PACKAGES - 3);

        let mut small = 1;
        assert_eq!(modules(&fs, "/app/node_modules", &mut small).len(), 1);
    }
}
