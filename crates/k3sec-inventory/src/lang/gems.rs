//! Installed gems without a `Gemfile.lock` to read: RubyGems writes one
//! `specifications/<name>-<version>.gemspec` per gem (`default/` for those
//! Ruby ships), whose first lines name it: `# stub: abbrev 0.1.2 ruby lib`.

/// `(name, version)` of an installed gemspec.
pub fn gemspec(content: &str) -> Option<(String, String)> {
    for line in content.lines().take(40) {
        if let Some(stub) = line.strip_prefix("# stub: ") {
            let mut f = stub.split_whitespace();
            if let (Some(n), Some(v)) = (f.next(), f.next()) {
                return Some((n.to_string(), v.to_string()));
            }
        }
    }
    let field = |key: &str| {
        content.lines().find_map(|l| {
            let v = l.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
            Some(v.trim().split('"').nth(1)?.to_string())
        })
    };
    Some((field("s.name")?, field("s.version")?))
}

/// Whether `path` is an installed gemspec (not one in a gem's source tree).
pub fn is_installed_gemspec(path: &str) -> bool {
    path.ends_with(".gemspec")
        && (path.contains("/specifications/") || path.contains("/specifications/default/"))
}

/// Whether `path` lies in an installed gem's directory
/// (`…/ruby/gems/3.3.0/gems/rbs-3.4.0/Gemfile.lock`, `/usr/local/bundle/gems/…`).
pub fn inside_installed_gem(path: &str) -> bool {
    ["/ruby/gems/", "/bundle/gems/", "/bundle/ruby/"]
        .iter()
        .any(|root| path.contains(root))
        && path.contains("/gems/")
        && path.matches('/').count() > 4
        && path
            .split("/gems/")
            .last()
            .is_some_and(|rest| rest.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_line_then_fields() {
        let stub = "# -*- encoding: utf-8 -*-\n# stub: abbrev 0.1.2 ruby lib\n\nGem::Specification.new do |s|\n";
        assert_eq!(gemspec(stub), Some(("abbrev".into(), "0.1.2".into())));
        let plain = "Gem::Specification.new do |s|\n  s.name = \"nokogiri\".freeze\n  s.version = \"1.16.0\"\n";
        assert_eq!(gemspec(plain), Some(("nokogiri".into(), "1.16.0".into())));
        assert_eq!(gemspec("nothing here"), None);
        assert!(is_installed_gemspec(
            "/usr/local/lib/ruby/gems/3.3.0/specifications/default/abbrev-0.1.2.gemspec"
        ));
        assert!(!is_installed_gemspec("/app/vendor/foo/foo.gemspec"));
        assert!(inside_installed_gem(
            "/usr/local/lib/ruby/gems/3.3.0/gems/rbs-3.4.0/Gemfile.lock"
        ));
        assert!(inside_installed_gem(
            "/usr/local/bundle/gems/rails-7.1.0/Gemfile.lock"
        ));
        assert!(!inside_installed_gem("/usr/src/redmine/Gemfile.lock"));
    }
}
