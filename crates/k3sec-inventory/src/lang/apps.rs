//! Software that ships its own manifest, no package manager involved:
//! * PEAR, PHP's legacy installer: `.registry/<name>.reg`, a serialized PHP
//!   array (`s:4:"name";s:11:"Archive_Tar"`). Advisories file these packages
//!   on Packagist as `pear/<name>`.
//! * WordPress: `wp-includes/version.php` (`$wp_version = '6.9.4';`), matched
//!   by CPE; its plugins (`wp-content/plugins/<slug>/<slug>.php` headers),
//!   listed only (no advisory feed names them).
//! * Bitnami: `/opt/bitnami/<component>/.spdx-<name>.spdx`, the SPDX SBOM of
//!   what Bitnami compiled, matched in OSV's `Bitnami` ecosystem.

use serde::Deserialize;

/// `(name, version)` of a PEAR registry entry: the first `name` and the
/// first `release` (the package's own, before maintainers and dependencies).
pub fn pear_registry(content: &str) -> Option<(String, String)> {
    let string_after = |key: &str| {
        let marker = format!("s:{}:\"{key}\";s:", key.len());
        let rest = &content[content.find(&marker)? + marker.len()..];
        let (_, rest) = rest.split_once(":\"")?;
        Some(rest.split('"').next()?.to_string())
    };
    Some((string_after("name")?, string_after("release")?))
}

/// `$wp_version = '6.9.4';` from `wp-includes/version.php`.
pub fn wordpress_version(content: &str) -> Option<String> {
    content.lines().find_map(|l| {
        let v = l
            .trim()
            .strip_prefix("$wp_version")?
            .trim_start()
            .strip_prefix('=')?;
        Some(
            v.trim()
                .trim_end_matches(';')
                .trim_matches(['\'', '"'])
                .to_string(),
        )
    })
}

/// A plugin's `Version:` header (the main file's opening comment).
pub fn wordpress_plugin_version(content: &str) -> Option<String> {
    content.lines().take(60).find_map(|l| {
        let l = l.trim_start_matches([' ', '*', '/', '#']).trim();
        let v = l.strip_prefix("Version:")?.trim();
        (!v.is_empty()).then(|| v.to_string())
    })
}

#[derive(Deserialize)]
struct Spdx {
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Deserialize)]
struct SpdxPackage {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "versionInfo")]
    version: String,
}

/// `(name, version)` of the packages of a Bitnami SPDX document, the build
/// revision (`18.6.0-25`) dropped as Bitnami's advisories do.
pub fn bitnami_spdx(content: &str) -> Vec<(String, String)> {
    let Ok(doc) = serde_json::from_str::<Spdx>(content) else {
        return Vec::new();
    };
    doc.packages
        .into_iter()
        .filter(|p| !p.name.is_empty() && !p.version.is_empty())
        .map(|p| {
            let v = p
                .version
                .split_once('-')
                .map_or(p.version.as_str(), |(v, _)| v)
                .to_string();
            (p.name, v)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pear_wordpress_bitnami() {
        let reg = r#"a:24:{s:7:"attribs";a:1:{s:7:"version";s:3:"2.0";}s:4:"name";s:11:"Archive_Tar";s:7:"channel";s:12:"pear.php.net";s:4:"lead";a:1:{s:4:"name";s:14:"Vincent Blavet";}s:7:"version";a:2:{s:7:"release";s:5:"1.6.0";s:3:"api";s:5:"1.6.0";}s:9:"stability";a:1:{s:7:"release";s:6:"stable";}"#;
        assert_eq!(
            pear_registry(reg),
            Some(("Archive_Tar".into(), "1.6.0".into()))
        );

        assert_eq!(
            wordpress_version(
                "<?php\n/**\n * @global string $wp_version\n */\n$wp_version = '6.9.4';\n"
            ),
            Some("6.9.4".into())
        );
        assert_eq!(
            wordpress_plugin_version("<?php\n/**\n * Plugin Name: Akismet\n * Version: 5.6\n */"),
            Some("5.6".into())
        );

        let spdx = r#"{"spdxVersion":"SPDX-2.3","packages":[
            {"name":"postgresql","versionInfo":"18.6.0-25"},{"name":"geos","versionInfo":"3.15.0"},{"name":"x"}]}"#;
        assert_eq!(
            bitnami_spdx(spdx),
            [
                ("postgresql".into(), "18.6.0".into()),
                ("geos".into(), "3.15.0".into())
            ]
        );
    }
}
