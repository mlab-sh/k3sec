//! Java archives: the Maven coordinates Maven, Gradle and the Shade / Spring
//! Boot plugins leave in `META-INF/maven/<group>/<artifact>/pom.properties`,
//! in the archive itself and in the jars it nests (`BOOT-INF/lib/`,
//! `WEB-INF/lib/`, two levels deep). Jenkins plugins (`.hpi`, `.jpi`) name
//! theirs in the manifest.
//!
//! A jar with none of that (Gradle builds: Spring, Lucene) is named from its
//! file name and manifest; its group comes from [`KNOWN_GROUPS`], else it is
//! listed without a group and not matched (no guessed coordinates).

use std::io::{Cursor, Read};

/// Entries looked at per archive: a zip bomb stops here.
const MAX_ENTRIES: usize = 100_000;
const MAX_PROPERTIES: u64 = 64 * 1024;
/// A nested jar is read into memory; larger ones are skipped.
const MAX_NESTED: u64 = 64 * 1024 * 1024;
/// Archives inside archives followed (a war's libraries, an agent's plugins).
const MAX_DEPTH: usize = 2;

/// The group of common artifacts published without `pom.properties`, by
/// artifact-name prefix (the longest prefix wins).
const KNOWN_GROUPS: &[(&str, &str)] = &[
    ("spring-security-", "org.springframework.security"),
    ("spring-boot", "org.springframework.boot"),
    ("spring-", "org.springframework"),
    ("ant-", "org.apache.ant"),
    ("ant", "org.apache.ant"),
    ("groovy", "org.codehaus.groovy"),
    ("guice", "com.google.inject"),
    ("jna", "net.java.dev.jna"),
    ("dom4j", "org.dom4j"),
    ("lucene-", "org.apache.lucene"),
    ("elasticsearch", "org.elasticsearch"),
    ("kotlin-", "org.jetbrains.kotlin"),
];

/// `(groupId:artifactId, version)` of an archive and of the archives it
/// nests; an artifact whose group is unknown comes as `artifactId` alone.
/// `file_name` names the archive itself (`spring-core-7.0.9.jar`).
pub fn parse(bytes: &[u8], file_name: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    walk(bytes, file_name, 0, &mut out);
    out.sort();
    out.dedup();
    out
}

fn walk(bytes: &[u8], file_name: &str, depth: usize, out: &mut Vec<(String, String)>) {
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return;
    };
    let found_before = out.len();
    let mut manifest = None;
    for i in 0..zip.len().min(MAX_ENTRIES) {
        let Ok(entry) = zip.by_index(i) else { continue };
        let name = entry.name().to_string();
        if name.starts_with("META-INF/maven/") && name.ends_with("/pom.properties") {
            let mut text = String::new();
            if entry.take(MAX_PROPERTIES).read_to_string(&mut text).is_ok() {
                out.extend(coordinate(&text));
            }
        } else if name == "META-INF/MANIFEST.MF" {
            let mut text = String::new();
            if entry.take(MAX_PROPERTIES).read_to_string(&mut text).is_ok() {
                manifest = Some(text);
            }
        } else if depth < MAX_DEPTH && is_archive(&name) && entry.size() <= MAX_NESTED {
            let inner_name = name.rsplit('/').next().unwrap_or(&name).to_string();
            let mut inner = Vec::with_capacity(entry.size() as usize);
            if entry.take(MAX_NESTED).read_to_end(&mut inner).is_ok() {
                walk(&inner, &inner_name, depth + 1, out);
            }
        }
    }
    let manifest = manifest.unwrap_or_default();
    if let Some(plugin) = jenkins_plugin(&manifest) {
        out.push(plugin);
    } else if out.len() == found_before {
        // Nothing named this archive (its own pom.properties, nested ones aside).
        out.extend(from_file_name(file_name, &manifest));
    }
}

fn is_archive(name: &str) -> bool {
    name.ends_with(".jar") || name.ends_with(".hpi") || name.ends_with(".jpi")
}

fn coordinate(properties: &str) -> Option<(String, String)> {
    let get = |key: &str| {
        properties.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };
    let (group, artifact, version) = (get("groupId")?, get("artifactId")?, get("version")?);
    (!group.is_empty() && !artifact.is_empty() && !version.is_empty())
        .then(|| (format!("{group}:{artifact}"), version))
}

/// A manifest attribute (continuation lines, which start with a space, joined).
fn attribute(manifest: &str, key: &str) -> Option<String> {
    let mut lines = manifest.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
            let mut v = v.trim().to_string();
            while let Some(cont) = lines.peek().and_then(|l| l.strip_prefix(' ')) {
                v.push_str(cont);
                lines.next();
            }
            return Some(v).filter(|v| !v.is_empty());
        }
    }
    None
}

/// `Group-Id` + `Short-Name` + `Plugin-Version` of a Jenkins plugin.
fn jenkins_plugin(manifest: &str) -> Option<(String, String)> {
    let name = attribute(manifest, "Short-Name")?;
    let version = attribute(manifest, "Plugin-Version")?;
    let group = attribute(manifest, "Group-Id").unwrap_or_else(|| "org.jenkins-ci.plugins".into());
    Some((format!("{group}:{name}"), version))
}

/// `spring-core-7.0.9.jar` → `org.springframework:spring-core`, `7.0.9` (the
/// manifest's version wins over the file name's).
fn from_file_name(file_name: &str, manifest: &str) -> Option<(String, String)> {
    let stem = file_name
        .strip_suffix(".jar")
        .or_else(|| file_name.strip_suffix(".war"))?;
    let split = stem
        .char_indices()
        .filter(|&(i, c)| c == '-' && stem[i + 1..].starts_with(|d: char| d.is_ascii_digit()))
        .map(|(i, _)| i)
        .next();
    let (artifact, file_version) = match split {
        Some(i) => (&stem[..i], Some(&stem[i + 1..])),
        None => (stem, None),
    };
    let version = ["Implementation-Version", "Bundle-Version"]
        .iter()
        .find_map(|k| attribute(manifest, k))
        .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .or_else(|| file_version.map(str::to_string))?;
    let group = KNOWN_GROUPS
        .iter()
        .filter(|(prefix, _)| {
            artifact.starts_with(prefix) || artifact == prefix.trim_end_matches('-')
        })
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, g)| *g);
    Some((
        match group {
            Some(g) => format!("{g}:{artifact}"),
            None => artifact.to_string(),
        },
        version,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn jar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, data) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn props(g: &str, a: &str, v: &str) -> Vec<u8> {
        format!("#Generated by Maven\nartifactId={a}\ngroupId={g}\nversion={v}\n").into_bytes()
    }

    #[test]
    fn reads_pom_properties_and_fat_jar_libraries() {
        let log4j = jar(&[(
            "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
            &props("org.apache.logging.log4j", "log4j-core", "2.14.1"),
        )]);
        let app = jar(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            (
                "META-INF/maven/com.example/shop/pom.properties",
                &props("com.example", "shop", "1.0.0"),
            ),
            ("BOOT-INF/lib/log4j-core-2.14.1.jar", &log4j),
            ("BOOT-INF/lib/no-coordinates.jar", &jar(&[("a.class", b"")])),
        ]);
        assert_eq!(
            parse(&app, "app.jar"),
            [
                ("com.example:shop".into(), "1.0.0".into()),
                (
                    "org.apache.logging.log4j:log4j-core".into(),
                    "2.14.1".into()
                ),
            ]
        );
    }

    #[test]
    fn not_a_jar_or_incomplete_properties() {
        assert!(parse(b"\x7fELF not a zip", "x.jar").is_empty());
        let partial = jar(&[(
            "META-INF/maven/g/a/pom.properties",
            b"groupId=g\nartifactId=a\n",
        )]);
        assert!(parse(&partial, "partial.jar").is_empty());
    }

    #[test]
    fn gradle_jars_and_jenkins_plugins_by_manifest() {
        let spring = jar(&[(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\nImplementation-Title: spring-core\nImplementation-Version: 7.0.9\n",
        )]);
        let jna = jar(&[(
            "META-INF/MANIFEST.MF",
            b"Implementation-Version: 5.19.1 (b0)\nBundle-SymbolicName: com.sun.jna\n",
        )]);
        let unknown = jar(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")]);
        let war = jar(&[
            ("WEB-INF/lib/spring-core-7.0.9.jar", &spring),
            ("WEB-INF/lib/jna-5.19.1.jar", &jna),
            ("WEB-INF/lib/relaxngDatatype-20020414.jar", &unknown),
        ]);
        assert_eq!(
            parse(&war, "jenkins.war"),
            [
                ("net.java.dev.jna:jna".into(), "5.19.1".into()),
                ("org.springframework:spring-core".into(), "7.0.9".into()),
                ("relaxngDatatype".into(), "20020414".into()),
            ]
        );

        let hpi = jar(&[(
            "META-INF/MANIFEST.MF",
            b"Short-Name: git\nPlugin-Version: 5.2.1\nGroup-Id: org.jenkins-ci.plugins\n",
        )]);
        assert_eq!(
            parse(&hpi, "git.jpi"),
            [("org.jenkins-ci.plugins:git".into(), "5.2.1".into())]
        );
    }
}
