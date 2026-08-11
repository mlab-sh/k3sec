//! Ruleset loading and compilation.
//!
//! Rules are compiled **once** at startup from `--rules <path>` (a single `.yar`
//! file or a directory scanned recursively). Compilation is fail-fast: an invalid
//! rule aborts startup with a readable error rather than running with a broken
//! ruleset. The compiled [`Rules`] are shared (`Arc`) across scan workers, each
//! of which creates its own cheap [`yara_x::Scanner`], rules are never
//! recompiled per scan.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use walkdir::WalkDir;
use yara_x::{Compiler, Rules};

/// A compiled, shareable ruleset.
#[derive(Clone)]
pub struct RuleSet {
    rules: Arc<Rules>,
    rule_count: usize,
    file_count: usize,
}

impl RuleSet {
    /// Compile every `.yar`/`.yara` file under `path` (file or directory).
    ///
    /// Fails if the path yields no rule files or any rule is invalid.
    pub fn compile(path: &Path) -> Result<Self> {
        let files = collect_rule_files(path)
            .with_context(|| format!("failed to enumerate rules at {}", path.display()))?;
        if files.is_empty() {
            bail!("no .yar/.yara rule files found at {}", path.display());
        }

        let mut compiler = Compiler::new();
        for file in &files {
            let src = std::fs::read_to_string(file)
                .with_context(|| format!("failed to read rule file {}", file.display()))?;
            let origin = file.display().to_string();
            compiler
                .add_source(yara_x::SourceCode::from(src.as_str()).with_origin(&origin))
                .map_err(|e| anyhow!("invalid YARA rules in {origin}:\n{e}"))?;
        }

        let rules = compiler.build();
        let rule_count = rules.iter().count();
        if rule_count == 0 {
            bail!("ruleset at {} compiled to zero rules", path.display());
        }

        Ok(Self {
            rules: Arc::new(rules),
            rule_count,
            file_count: files.len(),
        })
    }

    /// The shared compiled rules, for constructing per-worker scanners.
    pub fn rules(&self) -> Arc<Rules> {
        self.rules.clone()
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn file_count(&self) -> usize {
        self.file_count
    }
}

/// Collect rule files: a single file returns itself; a directory is walked
/// recursively for `.yar`/`.yara` files (sorted for deterministic order).
fn collect_rule_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!("rules path does not exist: {}", path.display());
    }

    let mut files: Vec<PathBuf> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("yar") | Some("yara")
            )
        })
        .collect();
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        rule marker {
            strings: $a = "K3SEC_YARA_TEST"
            condition: $a
        }
    "#;

    #[test]
    fn compiles_valid_rules_from_a_string_source() {
        let mut compiler = Compiler::new();
        compiler.add_source(VALID).unwrap();
        let rules = compiler.build();
        assert_eq!(rules.iter().count(), 1);
    }

    #[test]
    fn invalid_rule_is_rejected() {
        let mut compiler = Compiler::new();
        let err = compiler.add_source("rule broken { condition: $missing }");
        assert!(err.is_err(), "undefined string ref must fail to compile");
    }

    #[test]
    fn compile_from_dir_collects_and_compiles() {
        let dir = std::env::temp_dir().join(format!("k3sec-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("marker.yar"), VALID).unwrap();

        let set = RuleSet::compile(&dir).unwrap();
        assert_eq!(set.rule_count(), 1);
        assert_eq!(set.file_count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_dir_fails_fast() {
        let dir = std::env::temp_dir().join(format!("k3sec-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(RuleSet::compile(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shipped_rules_compile() {
        // The `rules/` directory shipped with the repo must always compile.
        let repo_rules = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("rules");
        let set = RuleSet::compile(&repo_rules).expect("bundled rules must compile");
        assert!(set.rule_count() >= 3, "expected the bundled test rules");
    }
}
