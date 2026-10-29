//! The config mlab chooses, clamped to the local policy, and its persistence.

use std::path::{Path, PathBuf};

use k3sec_api::{Config, Settings, MAX_RULES_SOURCE};

/// A config ready to run: clamped, with the rules resolved to a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub config: Config,
    /// Namespaces to keep; empty = all.
    pub namespaces: Vec<String>,
    /// YARA rules file/dir for `rules`, when on.
    pub rules_path: Option<PathBuf>,
}

/// Intersect `wanted` with what `settings` allows; the reasons go in words
/// into the returned list. Pure: no file is touched.
pub fn clamp(settings: &Settings, wanted: &Config) -> (Config, Vec<String>) {
    let mut c = wanted.clone();
    let mut cut = Vec::new();
    let a = &settings.allow;
    let mut off = |on: &mut bool, allowed: bool, name: &str| {
        if *on && !allowed {
            *on = false;
            cut.push(format!("{name} not allowed by policy"));
        }
    };
    off(&mut c.sources.k8s_events, a.k8s_events, "k8s_events");
    off(&mut c.sources.logs, a.logs, "logs");
    off(&mut c.sources.ebpf, a.ebpf, "ebpf");
    off(&mut c.sources.rules, a.rules, "rules");
    off(&mut c.sources.vulns, a.vulns, "vulns");
    if c.sources.rules && !c.sources.ebpf {
        c.sources.rules = false;
        cut.push("rules need ebpf".into());
    }

    if !settings.namespaces.is_empty() {
        let (kept, refused): (Vec<String>, Vec<String>) = c
            .namespaces
            .iter()
            .cloned()
            .partition(|n| settings.namespaces.contains(n));
        for n in refused {
            cut.push(format!("namespace {n} not allowed by policy"));
        }
        c.namespaces = kept;
    }

    if c.rules_source.is_some() && !settings.allow_remote_rules {
        c.rules_source = None;
        cut.push("remote rules not allowed by policy".into());
    }
    if c.rules_source
        .as_ref()
        .is_some_and(|r| r.len() > MAX_RULES_SOURCE)
    {
        c.rules_source = None;
        cut.push("remote rules over 1 MiB".into());
    }
    if let Some(name) = &c.ruleset {
        if !settings.rulesets.contains_key(name) {
            cut.push(format!("ruleset {name} not in policy"));
            c.ruleset = None;
        }
    }
    if c.sources.rules && c.ruleset.is_none() && c.rules_source.is_none() {
        // Fall back to the only ruleset when there is exactly one.
        match settings.rulesets.keys().next() {
            Some(only) if settings.rulesets.len() == 1 => c.ruleset = Some(only.clone()),
            _ => {
                c.sources.rules = false;
                cut.push("rules on but no ruleset chosen".into());
            }
        }
    }
    c.kinds.retain(|k| {
        let ok = ["exec", "connect", "file_write"].contains(&k.as_str());
        if !ok {
            cut.push(format!("unknown eBPF kind {k}"));
        }
        ok
    });
    (c, cut)
}

/// Resolve a clamped config against the work dir: remote rules are written
/// to a file there, named rulesets mapped to their policy path.
pub fn effective(
    settings: &Settings,
    config: Config,
    work_dir: &Path,
) -> std::io::Result<Effective> {
    let namespaces = if config.namespaces.is_empty() {
        settings.namespaces.clone()
    } else {
        config.namespaces.clone()
    };
    let rules_path = if !config.sources.rules {
        None
    } else if let Some(src) = &config.rules_source {
        let path = work_dir.join("remote-rules.yar");
        std::fs::write(&path, src)?;
        Some(path)
    } else {
        config
            .ruleset
            .as_ref()
            .and_then(|n| settings.rulesets.get(n))
            .map(PathBuf::from)
    };
    Ok(Effective {
        config,
        namespaces,
        rules_path,
    })
}

const CONFIG_FILE: &str = "config.cbor";

pub fn load(work_dir: &Path) -> Option<Config> {
    let bytes = std::fs::read(work_dir.join(CONFIG_FILE)).ok()?;
    k3sec_api::from_cbor(&bytes)
        .inspect_err(|e| tracing::warn!("ignoring saved config: {e}"))
        .ok()
}

pub fn save(work_dir: &Path, config: &Config) -> std::io::Result<()> {
    let bytes = k3sec_api::to_cbor(config).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = work_dir.join("config.cbor.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, work_dir.join(CONFIG_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k3sec_api::{Severity, Sources};

    fn settings() -> Settings {
        Settings {
            allow: Sources {
                k8s_events: true,
                logs: false,
                ebpf: true,
                rules: true,
                vulns: true,
            },
            namespaces: vec!["prod".into(), "staging".into()],
            rulesets: [("default".to_string(), "/usr/share/k3sec/rules".to_string())].into(),
            ..Settings::default()
        }
    }

    #[test]
    fn clamps_to_the_policy_and_says_why() {
        let wanted = Config {
            sources: Sources {
                k8s_events: true,
                logs: true,
                ebpf: true,
                rules: true,
                vulns: true,
            },
            kinds: vec!["exec".into(), "ptrace".into()],
            namespaces: vec!["prod".into(), "kube-system".into()],
            min_severity: Severity::Warning,
            ruleset: None,
            rules_source: Some("rule x { condition: true }".into()),
        };
        let (c, cut) = clamp(&settings(), &wanted);
        assert!(!c.sources.logs);
        assert_eq!(c.namespaces, ["prod"]);
        assert_eq!(c.kinds, ["exec"]);
        assert!(c.rules_source.is_none());
        assert_eq!(
            c.ruleset.as_deref(),
            Some("default"),
            "single ruleset picked"
        );
        assert!(c.sources.rules);
        for reason in [
            "logs not allowed",
            "namespace kube-system",
            "remote rules not allowed",
            "unknown eBPF kind ptrace",
        ] {
            assert!(
                cut.iter().any(|r| r.contains(reason)),
                "{reason} in {cut:?}"
            );
        }
    }

    #[test]
    fn rules_need_ebpf_and_a_ruleset() {
        let mut s = settings();
        s.rulesets.clear();
        let mut wanted = Config::default();
        wanted.sources.rules = true;
        let (c, cut) = clamp(&s, &wanted);
        assert!(!c.sources.rules);
        assert!(cut.iter().any(|r| r.contains("no ruleset")));

        wanted.sources.ebpf = false;
        let (c, _) = clamp(&settings(), &wanted);
        assert!(!c.sources.rules);
    }

    #[test]
    fn remote_rules_go_to_the_work_dir_and_config_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = settings();
        s.allow_remote_rules = true;
        let mut wanted = Config::default();
        wanted.sources.rules = true;
        wanted.rules_source = Some("rule x { condition: true }".into());
        let (c, cut) = clamp(&s, &wanted);
        assert!(cut.is_empty(), "{cut:?}");
        let eff = effective(&s, c.clone(), dir.path()).unwrap();
        assert_eq!(
            eff.rules_path.as_deref(),
            Some(dir.path().join("remote-rules.yar").as_path())
        );
        assert_eq!(
            eff.namespaces,
            ["prod", "staging"],
            "policy namespaces when none chosen"
        );

        save(dir.path(), &c).unwrap();
        assert_eq!(load(dir.path()), Some(c));
    }
}
