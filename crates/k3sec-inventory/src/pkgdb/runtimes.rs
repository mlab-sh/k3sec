//! Language runtimes and servers no package manager owns: the official Docker
//! images build Python, Node.js, PHP, Ruby, Perl, Apache httpd and Redis from
//! source into `/usr/local`, and ship the JDK (`/opt/java/openjdk`) and the Go
//! toolchain (`/usr/local/go`) as tarballs. Their version is read from the
//! binary (the string it prints in `--version`) or from the release file next
//! to it, and matched by CPE (Go: as its `stdlib`).
//!
//! A file a package of the image owns is left to that package.

use std::sync::OnceLock;

use regex::bytes::Regex;

use crate::model::{Coordinate, Package, PackageKind};
use crate::purl;
use crate::rootfs::Rootfs;

/// Binaries are read whole to find their version string.
const MAX_BINARY: u64 = 256 * 1024 * 1024;

struct Probe {
    name: &'static str,
    /// `vendor:product` of the NVD CPE.
    cpe: &'static str,
    /// Where it lives: a file, or a directory and a file-name prefix.
    paths: &'static [&'static str],
    /// Version in the binary, as its first capture group.
    pattern: &'static str,
}

const PROBES: &[Probe] = &[
    Probe {
        name: "python",
        cpe: "python:python",
        paths: &["/usr/local/lib/libpython3.", "/opt/conda/lib/libpython3."],
        pattern: r"\x00(3\.\d{1,2}\.\d{1,3})\x00",
    },
    Probe {
        name: "node",
        cpe: "nodejs:node.js",
        paths: &["/usr/local/bin/node"],
        pattern: r"node\.js/v(\d+\.\d+\.\d+)",
    },
    Probe {
        name: "php",
        cpe: "php:php",
        paths: &[
            "/usr/local/bin/php",
            "/usr/local/sbin/php-fpm",
            "/usr/local/lib/libphp.",
            "/usr/lib/apache2/modules/libphp.",
        ],
        pattern: r"X-Powered-By: PHP/(\d+\.\d+\.\d+)",
    },
    Probe {
        name: "ruby",
        cpe: "ruby-lang:ruby",
        paths: &["/usr/local/lib/libruby.so."],
        pattern: r"ruby (\d+\.\d+\.\d+)",
    },
    Probe {
        name: "perl",
        cpe: "perl:perl",
        paths: &["/usr/local/bin/perl"],
        pattern: r"/perl5/(\d+\.\d+\.\d+)",
    },
    Probe {
        name: "httpd",
        cpe: "apache:http_server",
        paths: &["/usr/local/apache2/bin/httpd"],
        pattern: r"Apache/(\d+\.\d+\.\d+)",
    },
    Probe {
        name: "redis",
        cpe: "redis:redis",
        paths: &["/usr/local/bin/redis-server"],
        // shortcut: the version sits before the compiler's and `c11-builtin`; another build layout misses it
        pattern: r"\x00(\d+\.\d+\.\d+)\x00\d+\.\d+\.\d+\x00c11-builtin",
    },
];

/// JDKs and JREs shipped as tarballs: `<home>/release` says `JAVA_VERSION="21.0.13"`.
const JAVA_HOMES: &[&str] = &["/opt/java/openjdk", "/usr/local/openjdk-"];

/// The runtimes found in `fs` that `owned` (a package of the image) does not claim.
pub fn scan(fs: &Rootfs, owned: impl Fn(&str) -> bool) -> Vec<Package> {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        PROBES
            .iter()
            .map(|p| Regex::new(&format!("(?-u){}", p.pattern)).expect("probe pattern"))
            .collect()
    });
    let mut out = Vec::new();
    for (probe, re) in PROBES.iter().zip(patterns) {
        // Every file of the runtime (PHP: CLI, FPM, Apache module) counts for
        // the loaded tag; the first one with a version string names it.
        let found: Vec<(String, Option<String>)> = probe
            .paths
            .iter()
            .flat_map(|p| candidates(fs, p))
            .filter(|p| !owned(p))
            .map(|p| {
                let v = version_in(fs, &p, re);
                (p, v)
            })
            .filter(|(_, v)| v.is_some())
            .collect();
        let Some(version) = found.first().and_then(|(_, v)| v.clone()) else {
            continue;
        };
        let files = found.into_iter().map(|(p, _)| p).collect();
        out.push(runtime(probe.name, probe.cpe, &version, files));
    }
    for home in JAVA_HOMES.iter().flat_map(|h| candidates(fs, h)) {
        let release = format!("{home}/release");
        if owned(&release) {
            continue;
        }
        let Some(version) = fs
            .read_string(&release, 64 * 1024)
            .ok()
            .and_then(|r| release_field(&r, "JAVA_VERSION"))
        else {
            continue;
        };
        let files = ["bin/java", "lib/server/libjvm.so"]
            .iter()
            .filter_map(|f| fs.resolve(&format!("{home}/{f}")))
            .collect();
        out.push(runtime("openjdk", "oracle:openjdk", &version, files));
    }
    if let Some(go) = fs
        .read_string("/usr/local/go/VERSION", 4096)
        .ok()
        .filter(|_| !owned("/usr/local/go/VERSION"))
        .and_then(|v| v.lines().next()?.strip_prefix("go").map(str::to_string))
    {
        let mut p = Package::new(
            "go",
            &go,
            PackageKind::Os,
            purl::build("generic", None, "go", &go, &[]),
        );
        p.coordinate = Some(Coordinate::eco("Go", "stdlib", &go));
        p.files = ["/usr/local/go/bin/go"]
            .iter()
            .filter_map(|f| fs.resolve(f))
            .collect();
        out.push(p);
    }
    out
}

fn runtime(name: &str, cpe: &str, version: &str, files: Vec<String>) -> Package {
    let mut p = Package::new(
        name,
        version,
        PackageKind::Os,
        purl::build("generic", None, name, version, &[]),
    );
    p.coordinate = Some(Coordinate::Cpe {
        cpe: format!("cpe:2.3:a:{cpe}:{version}:*:*:*:*:*:*:*"),
    });
    p.files = files;
    p
}

/// `/usr/local/bin/node` itself, or the files of a directory starting with a
/// prefix (`/usr/local/lib/libpython3.` → `libpython3.12.so.1.0`), as canonical paths.
fn candidates(fs: &Rootfs, path: &str) -> Vec<String> {
    if let Some(p) = fs.resolve(path) {
        return vec![p];
    }
    let (dir, prefix) = path.rsplit_once('/').unwrap_or(("/", path));
    let Some(dir) = fs.resolve(dir) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(fs.root().join(dir.trim_start_matches('/'))) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(prefix))
        .filter_map(|n| fs.resolve(&format!("{dir}/{n}")))
        .collect();
    found.sort();
    found.dedup();
    found
}

fn version_in(fs: &Rootfs, path: &str, re: &Regex) -> Option<String> {
    let bytes = fs.read_limited(path, MAX_BINARY).ok()?;
    let caps = re.captures(&bytes)?;
    Some(String::from_utf8_lossy(caps.get(1)?.as_bytes()).into_owned())
}

/// `KEY="value"` in a JDK `release` file.
fn release_field(release: &str, key: &str) -> Option<String> {
    release.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(root: &std::path::Path, path: &str, bytes: &[u8]) {
        let p = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    #[test]
    fn finds_source_built_runtimes_and_skips_owned_files() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(
            r,
            "/usr/local/lib/libpython3.12.so.1.0",
            b"\x7fELF..\x003.12.16\x00(main)",
        );
        put(
            r,
            "/usr/local/bin/node",
            b"\x7fELF https://nodejs.org node.js/v22.23.4 ",
        );
        put(
            r,
            "/usr/local/bin/php",
            b"\x7fELF X-Powered-By: PHP/8.3.36\r\n",
        );
        put(
            r,
            "/usr/lib/apache2/modules/libphp.so",
            b"\x7fELF X-Powered-By: PHP/8.3.36\r\n",
        );
        put(
            r,
            "/usr/local/bin/redis-server",
            b"\x7fELF\x007.4.12\x0012.2.0\x00c11-builtin\x00",
        );
        put(
            r,
            "/usr/local/apache2/bin/httpd",
            b"\x7fELF Apache/2.4.69 (Unix)",
        );
        put(
            r,
            "/opt/java/openjdk/release",
            b"IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"21.0.13\"\n",
        );
        put(r, "/opt/java/openjdk/bin/java", b"\x7fELF");
        put(r, "/usr/local/go/VERSION", b"go1.23.12\ntime 2025-08-01\n");
        // A package of the image owns this one: its CVEs come through that package.
        put(
            r,
            "/usr/local/bin/perl",
            b"\x7fELF /usr/local/lib/perl5/5.40.5/",
        );

        let fs = Rootfs::new(r);
        let got = scan(&fs, |p| p == "/usr/local/bin/perl");
        let by = |n: &str| {
            got.iter()
                .find(|p| p.name == n)
                .map(|p| (p.version.clone(), p.coordinate.clone()))
        };

        assert_eq!(
            by("python"),
            Some((
                "3.12.16".into(),
                Some(Coordinate::Cpe {
                    cpe: "cpe:2.3:a:python:python:3.12.16:*:*:*:*:*:*:*".into()
                })
            ))
        );
        assert_eq!(by("node").unwrap().0, "22.23.4");
        assert_eq!(by("php").unwrap().0, "8.3.36");
        assert_eq!(by("redis").unwrap().0, "7.4.12");
        assert_eq!(by("httpd").unwrap().0, "2.4.69");
        assert_eq!(
            by("openjdk"),
            Some((
                "21.0.13".into(),
                Some(Coordinate::Cpe {
                    cpe: "cpe:2.3:a:oracle:openjdk:21.0.13:*:*:*:*:*:*:*".into()
                })
            ))
        );
        assert_eq!(
            by("go"),
            Some((
                "1.23.12".into(),
                Some(Coordinate::eco("Go", "stdlib", "1.23.12"))
            ))
        );
        assert_eq!(by("perl"), None, "owned by a package");
        let php = got.iter().find(|p| p.name == "php").unwrap();
        assert_eq!(
            php.files,
            ["/usr/local/bin/php", "/usr/lib/apache2/modules/libphp.so"]
        );
        let jdk = got.iter().find(|p| p.name == "openjdk").unwrap();
        assert_eq!(jdk.files, ["/opt/java/openjdk/bin/java"]);
    }
}
