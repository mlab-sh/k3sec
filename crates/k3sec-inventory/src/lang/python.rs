//! Python distributions installed by pip, conda or the official images:
//! `<name>.dist-info/METADATA` (or `<name>.egg-info/PKG-INFO`) names the
//! project and its version; `RECORD` lists its files, so a C extension
//! (`.so`) a process maps tags the distribution loaded.

/// `Name:` and `Version:` from the RFC 822 header block of METADATA / PKG-INFO.
pub fn metadata(content: &str) -> Option<(String, String)> {
    let (mut name, mut version) = (None, None);
    for line in content.lines() {
        if line.is_empty() {
            break; // the description body follows the headers
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name.get_or_insert_with(|| v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version.get_or_insert_with(|| v.trim().to_string());
        }
    }
    Some((
        name.filter(|n| !n.is_empty())?,
        version.filter(|v| !v.is_empty())?,
    ))
}

/// The shared objects a RECORD lists (`path,hash,size` lines, paths relative
/// to `site`), as in-container paths.
pub fn shared_objects(record: &str, site: &str) -> Vec<String> {
    record
        .lines()
        .filter_map(|l| l.split(',').next())
        .filter(|p| p.ends_with(".so") || p.contains(".so."))
        .filter(|p| !p.starts_with('/') && !p.contains(".."))
        .map(|p| format!("{}/{p}", site.trim_end_matches('/')))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_headers_only() {
        let m =
            "Metadata-Version: 2.1\nName: aiohttp\nVersion: 3.9.1\nSummary: x\n\nName: not-this\n";
        assert_eq!(metadata(m), Some(("aiohttp".into(), "3.9.1".into())));
        assert_eq!(metadata("Metadata-Version: 2.1\nName: x\n"), None);
    }

    #[test]
    fn record_shared_objects() {
        let r = "aiohttp/__init__.py,sha256=a,1\naiohttp/_http_parser.cpython-312-x86_64-linux-gnu.so,sha256=b,2\n\
                 aiohttp.libs/libz-1.so.1.2.13,sha256=c,3\n../../../bin/evil.so,,\n";
        assert_eq!(
            shared_objects(r, "/usr/local/lib/python3.12/site-packages"),
            [
                "/usr/local/lib/python3.12/site-packages/aiohttp/_http_parser.cpython-312-x86_64-linux-gnu.so",
                "/usr/local/lib/python3.12/site-packages/aiohttp.libs/libz-1.so.1.2.13",
            ]
        );
    }
}
