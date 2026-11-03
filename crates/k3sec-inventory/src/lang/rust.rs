//! Rust binaries built with `cargo auditable`: the `.dep-v0` ELF section is
//! the dependency tree as zlib-compressed JSON (`rust-audit-info` format).
//! Registry crates are reported; the binary's own crate and path or git
//! dependencies have no advisory coordinates.

use std::io::Read;

use serde::Deserialize;

/// The decompressed JSON is refused beyond this (a crate list is a few KiB).
const MAX_JSON: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct Audit {
    #[serde(default)]
    packages: Vec<Crate>,
}

#[derive(Deserialize)]
struct Crate {
    name: String,
    version: String,
    #[serde(default)]
    source: String,
}

/// `(name, version)` of the crates.io crates in a `.dep-v0` section.
pub fn crates(section: &[u8]) -> Vec<(String, String)> {
    let mut json = Vec::new();
    if flate2::read::ZlibDecoder::new(section)
        .take(MAX_JSON)
        .read_to_end(&mut json)
        .is_err()
    {
        return Vec::new();
    }
    let Ok(audit) = serde_json::from_slice::<Audit>(&json) else {
        return Vec::new();
    };
    audit
        .packages
        .into_iter()
        .filter(|c| c.source == "crates.io" || c.source.starts_with("registry"))
        .map(|c| (c.name, c.version))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn registry_crates_from_the_section() {
        let json = r#"{"packages":[
            {"name":"uv","version":"0.9.1","source":"local","root":true},
            {"name":"tokio","version":"1.47.1","source":"crates.io","dependencies":[]},
            {"name":"rustls","version":"0.23.31","source":"crates.io"},
            {"name":"fork","version":"0.1.0","source":"git"}]}"#;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(json.as_bytes()).unwrap();
        let got = crates(&z.finish().unwrap());
        assert_eq!(
            got,
            [
                ("tokio".to_string(), "1.47.1".to_string()),
                ("rustls".to_string(), "0.23.31".to_string())
            ]
        );
        assert!(crates(b"not zlib").is_empty());
    }
}
