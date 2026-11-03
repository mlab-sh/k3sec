//! alpm (pacman, Arch Linux): one `/var/lib/pacman/local/<name>-<ver>-<rel>/`
//! per package, `desc` holding `%NAME%`, `%VERSION%`, `%BASE%` (the source
//! package), `%ARCH%` sections and `files` the `%FILES%` list.

use crate::rootfs::Rootfs;

use super::{OsPackage, MAX_DB_SIZE};

const DB: &str = "/var/lib/pacman/local";

pub fn read(fs: &Rootfs) -> Option<Vec<OsPackage>> {
    let dir = fs.host_path(DB)?;
    let mut entries: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    Some(
        entries
            .iter()
            .filter_map(|e| {
                let desc = fs
                    .read_string(&format!("{DB}/{e}/desc"), MAX_DB_SIZE)
                    .ok()?;
                let files = fs
                    .read_string(&format!("{DB}/{e}/files"), MAX_DB_SIZE)
                    .unwrap_or_default();
                parse(&desc, &files)
            })
            .collect(),
    )
}

/// One package from its `desc` and `files`.
pub fn parse(desc: &str, files: &str) -> Option<OsPackage> {
    let field = |key: &str| {
        sections(desc)
            .find(|(k, _)| *k == key)
            .and_then(|(_, v)| v.first().map(|s| s.to_string()))
    };
    let name = field("NAME")?;
    let files = sections(files)
        .find(|(k, _)| *k == "FILES")
        .map(|(_, v)| {
            v.iter()
                .filter(|f| !f.ends_with('/'))
                .map(|f| format!("/{f}"))
                .collect()
        })
        .unwrap_or_default();
    Some(OsPackage {
        source: field("BASE").filter(|b| *b != name),
        name,
        version: field("VERSION")?,
        arch: field("ARCH").unwrap_or_default(),
        source_version: None,
        files,
    })
}

/// `%KEY%` followed by its value lines, up to a blank line.
fn sections(content: &str) -> impl Iterator<Item = (&str, Vec<&str>)> {
    content.split("\n\n").filter_map(|block| {
        let mut lines = block.lines().filter(|l| !l.is_empty());
        let key = lines.next()?.strip_prefix('%')?.strip_suffix('%')?;
        Some((key, lines.collect()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desc_and_files() {
        let desc = "%NAME%\nopenssl\n\n%VERSION%\n3.6.5-1\n\n%BASE%\nopenssl\n\n%ARCH%\nx86_64\n\n";
        let files = "%FILES%\nusr/\nusr/lib/\nusr/lib/libssl.so.3\nusr/bin/openssl\n\n%BACKUP%\netc/ssl/openssl.cnf\tabc\n";
        let p = parse(desc, files).unwrap();
        assert_eq!(
            (p.name.as_str(), p.version.as_str(), p.arch.as_str()),
            ("openssl", "3.6.5-1", "x86_64")
        );
        assert_eq!(p.source, None, "base equal to the name");
        assert_eq!(p.files, ["/usr/lib/libssl.so.3", "/usr/bin/openssl"]);
        let lib = parse(
            "%NAME%\nlib32-glibc\n\n%VERSION%\n2.40-1\n\n%BASE%\nglibc\n",
            "",
        )
        .unwrap();
        assert_eq!(lib.source.as_deref(), Some("glibc"));
        assert!(parse("%VERSION%\n1\n", "").is_none());
    }
}
