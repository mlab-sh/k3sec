//! Detection rules over k3sec's events (`watch --detect`): a CEL condition
//! per rule, evaluated on every event. A rule that matches raises the event
//! (severity, MITRE ATT&CK ids, its name in `rule`) or drops it (`drop`: the
//! exceptions that keep a node quiet). Rule files are JSON:
//!
//! ```json
//! {"rules": [{"name": "shell-in-nginx",
//!             "when": "kind == 'exec' && meta.comm in ['sh', 'bash'] && meta.ancestry.contains('nginx')",
//!             "severity": "critical", "mitre": ["T1059.004"]},
//!            {"name": "kubelet-probes", "when": "kind == 'dns' && meta.comm == 'coredns'", "drop": true}]}
//! ```
//!
//! In a condition: `source`, `kind`, `severity`, `namespace`, `object`,
//! `message`, `meta` (the event's metadata, a map of strings), `payload`.
//! A condition that fails on a missing key does not match.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use cel_interpreter::{Context as CelContext, Program, Value};
use serde::Deserialize;

use k3sec_core::{SecEvent, Severity};

#[derive(Deserialize)]
struct RuleFile {
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
struct RuleSpec {
    name: String,
    when: String,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    mitre: Vec<String>,
    #[serde(default)]
    drop: bool,
}

struct Rule {
    name: String,
    program: Program,
    severity: Option<Severity>,
    mitre: Vec<String>,
    drop: bool,
}

/// The rules of a file or a directory of `*.json` files, reloaded when one changes.
pub struct DetectRules {
    path: PathBuf,
    stamp: Vec<(PathBuf, SystemTime)>,
    rules: Vec<Rule>,
}

impl DetectRules {
    pub fn load(path: &Path) -> Result<Self> {
        let files = files(path)?;
        let rules = compile(&files)?;
        Ok(Self {
            path: path.to_path_buf(),
            stamp: stamps(&files),
            rules,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Reload when a file was added, removed or modified. A broken edit is
    /// reported and the rules in force stay. Returns whether rules changed.
    pub fn reload_if_changed(&mut self) -> bool {
        let Ok(files) = files(&self.path) else {
            return false;
        };
        let stamp = stamps(&files);
        if stamp == self.stamp {
            return false;
        }
        self.stamp = stamp;
        match compile(&files) {
            Ok(rules) => {
                tracing::info!(rules = rules.len(), path = %self.path.display(), "detection rules reloaded");
                self.rules = rules;
                true
            }
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "detection rules not reloaded, the previous ones stay");
                false
            }
        }
    }

    /// The event as the rules leave it: `None` when one drops it.
    pub fn apply(&self, mut ev: SecEvent) -> Option<SecEvent> {
        if self.rules.is_empty() {
            return Some(ev);
        }
        let ctx = context(&ev);
        let mut names = Vec::new();
        let mut mitre: Vec<String> = ev
            .metadata
            .get("mitre")
            .map(|m| m.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        for rule in &self.rules {
            if !matches!(rule.program.execute(&ctx), Ok(Value::Bool(true))) {
                continue;
            }
            if rule.drop {
                return None;
            }
            names.push(rule.name.clone());
            if let Some(s) = rule.severity {
                ev.severity = ev.severity.max(s);
            }
            for m in &rule.mitre {
                if !mitre.contains(m) {
                    mitre.push(m.clone());
                }
            }
        }
        if !names.is_empty() {
            ev.message = format!("[{}] {}", names.join(","), ev.message);
            ev.metadata.insert("rule".into(), names.join(","));
            ev.metadata.insert("mitre".into(), mitre.join(","));
        }
        Some(ev)
    }
}

fn context(ev: &SecEvent) -> CelContext<'static> {
    let mut ctx = CelContext::default();
    let s = |v: &Option<String>| v.clone().unwrap_or_default();
    // A serialized `Source` / `Severity` is its snake_case name.
    let name = |v: serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let _ = ctx.add_variable(
        "source",
        name(serde_json::to_value(ev.source).unwrap_or_default()),
    );
    let _ = ctx.add_variable(
        "severity",
        name(serde_json::to_value(ev.severity).unwrap_or_default()),
    );
    let _ = ctx.add_variable("kind", ev.kind.clone());
    let _ = ctx.add_variable("namespace", s(&ev.namespace));
    let _ = ctx.add_variable("object", s(&ev.object));
    let _ = ctx.add_variable("message", ev.message.clone());
    let _ = ctx.add_variable("meta", ev.metadata.clone());
    let _ = ctx.add_variable("payload", ev.payload.clone());
    ctx
}

fn files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut out: Vec<PathBuf> = std::fs::read_dir(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    out.sort();
    Ok(out)
}

fn stamps(files: &[PathBuf]) -> Vec<(PathBuf, SystemTime)> {
    files
        .iter()
        .filter_map(|f| Some((f.clone(), std::fs::metadata(f).ok()?.modified().ok()?)))
        .collect()
}

fn compile(files: &[PathBuf]) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for f in files {
        let text =
            std::fs::read_to_string(f).with_context(|| format!("cannot read {}", f.display()))?;
        let file: RuleFile = serde_json::from_str(&text)
            .with_context(|| format!("{}: not a rule file", f.display()))?;
        for spec in file.rules {
            // The CEL parser (antlr4rust) panics on some malformed input
            // (`kind ==`) instead of returning an error: a broken edit must
            // not bring `watch` down.
            let program = std::panic::catch_unwind(|| Program::compile(&spec.when))
                .map_err(|_| {
                    anyhow::anyhow!("{}: rule `{}`: invalid condition", f.display(), spec.name)
                })?
                .map_err(|e| anyhow::anyhow!("{}: rule `{}`: {e}", f.display(), spec.name))?;
            rules.push(Rule {
                name: spec.name,
                program,
                severity: spec.severity,
                mitre: spec.mitre,
                drop: spec.drop,
            });
        }
    }
    if rules.iter().any(|r| r.name.is_empty()) {
        bail!("a detection rule has no name");
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k3sec_core::Source;

    fn exec(comm: &str, ancestry: &str) -> SecEvent {
        SecEvent::builder(Source::Ebpf, chrono::Utc::now())
            .kind("exec")
            .severity(Severity::Info)
            .namespace("web".to_string())
            .message(format!("exec /bin/{comm} ({comm})"))
            .meta("comm", comm.to_string())
            .meta("ancestry", ancestry.to_string())
            .build()
    }

    #[test]
    fn raise_drop_and_hot_reload() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rules.json");
        std::fs::write(
            &file,
            r#"{"rules": [
              {"name": "shell-in-nginx", "when": "kind == 'exec' && meta.comm in ['sh', 'bash'] && meta.ancestry.contains('nginx')",
               "severity": "critical", "mitre": ["T1059.004"]},
              {"name": "quiet-ls", "when": "meta.comm == 'ls'", "drop": true},
              {"name": "needs-a-missing-key", "when": "meta.nope == 'x'"}]}"#,
        )
        .unwrap();
        let mut rules = DetectRules::load(dir.path()).unwrap();
        assert_eq!(rules.len(), 3);

        let hit = rules.apply(exec("sh", "nginx > sh")).unwrap();
        assert_eq!(hit.severity, Severity::Critical);
        assert_eq!(hit.metadata["rule"], "shell-in-nginx");
        assert_eq!(hit.metadata["mitre"], "T1059.004");
        assert!(hit.message.starts_with("[shell-in-nginx] "));

        assert!(rules.apply(exec("ls", "sh")).is_none(), "dropped");
        let plain = rules.apply(exec("sh", "bash")).unwrap();
        assert_eq!(plain.severity, Severity::Info);
        assert!(!plain.metadata.contains_key("rule"));

        // A broken edit keeps the rules in force; a good one replaces them.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&file, r#"{"rules": [{"name": "x", "when": "kind =="}]}"#).unwrap();
        assert!(!rules.reload_if_changed());
        assert_eq!(rules.len(), 3);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            &file,
            r#"{"rules": [{"name": "any", "when": "true", "drop": true}]}"#,
        )
        .unwrap();
        assert!(rules.reload_if_changed());
        assert!(rules.apply(exec("sh", "nginx")).is_none());
    }
}
