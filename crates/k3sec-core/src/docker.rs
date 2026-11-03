//! Container hosts without Kubernetes: the containers of the local Docker or
//! Podman, read from the engine's state files rather than its socket, so no
//! HTTP client and no daemon round trip. Needs root, like the rest of the
//! node inventory.
//!
//! * Docker: `<data-root>/containers/<id>/config.v2.json`.
//! * Podman (rootful): `/var/lib/containers/storage/<driver>-containers/containers.json`,
//!   which lists stopped containers too: those have no process and are skipped
//!   by the inventory like any container without one.
//!
//! nerdctl keeps its containers in containerd's bolt metadata: not read.
//!
//! A container shows as namespace `docker` / `podman`, pod and container both its name.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    ContainerInfo, ContainerResolver, EventSink, EventSource, PodContainer, SecEvent, Severity,
    Source,
};

/// How often the engine's state is read again for new containers and log lines.
const POLL: Duration = Duration::from_secs(2);
/// Log bytes read per container per poll: a flood is caught up over polls.
const MAX_LOG_CHUNK: u64 = 1024 * 1024;

/// The namespace Docker containers are shown under.
pub const NAMESPACE: &str = "docker";
/// The namespace Podman containers are shown under.
pub const PODMAN_NAMESPACE: &str = "podman";

/// A container engine and where its state lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Engine {
    Docker(PathBuf),
    Podman(PathBuf),
}

impl Engine {
    /// Docker: `$DOCKER_DATA_ROOT`, else `data-root` from `/etc/docker/daemon.json`,
    /// else `/var/lib/docker`.
    pub fn docker() -> Self {
        Engine::Docker(data_root(Path::new("/etc/docker/daemon.json")))
    }

    /// Rootful Podman: `$CONTAINERS_STORAGE_ROOT`, else `/var/lib/containers/storage`.
    pub fn podman() -> Self {
        Engine::Podman(
            std::env::var_os("CONTAINERS_STORAGE_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/containers/storage")),
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            Engine::Docker(_) => NAMESPACE,
            Engine::Podman(_) => PODMAN_NAMESPACE,
        }
    }

    /// The engine's containers (Docker: running only; Podman: all).
    pub fn list(&self) -> Result<Vec<PodContainer>> {
        match self {
            Engine::Docker(root) => list_containers(root),
            Engine::Podman(root) => list_podman(root),
        }
    }

    /// Where the engine writes a container's output: Docker's `json-file`
    /// driver, Podman's `k8s-file` one.
    fn log_file(&self, id: &str) -> PathBuf {
        match self {
            Engine::Docker(root) => root
                .join("containers")
                .join(id)
                .join(format!("{id}-json.log")),
            Engine::Podman(root) => root
                .join("overlay-containers")
                .join(id)
                .join("userdata/ctr.log"),
        }
    }

    fn lookup(&self, id: &str) -> Option<PodContainer> {
        match self {
            Engine::Docker(root) => {
                read_config(&root.join("containers").join(id).join("config.v2.json"))
                    .map(to_pod_container)
            }
            Engine::Podman(root) => list_podman(root)
                .ok()?
                .into_iter()
                .find(|c| c.container_id == id),
        }
    }
}

fn data_root(daemon_json: &Path) -> PathBuf {
    if let Some(root) = std::env::var_os("DOCKER_DATA_ROOT") {
        return PathBuf::from(root);
    }
    std::fs::read(daemon_json)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("data-root")?.as_str().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/var/lib/docker"))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Config {
    #[serde(rename = "ID")]
    id: String,
    name: String,
    /// Image id (`sha256:…` of the image config): the dedup and cache key.
    image: String,
    config: ConfigInner,
    state: State,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConfigInner {
    /// The reference it was started from (`nginx:1.27`).
    image: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
    running: bool,
}

fn read_config(path: &Path) -> Option<Config> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn to_pod_container(c: Config) -> PodContainer {
    let name = c.name.trim_start_matches('/').to_string();
    PodContainer {
        namespace: NAMESPACE.into(),
        pod: name.clone(),
        container: name,
        image: c.config.image,
        image_digest: Some(c.image).filter(|d| !d.is_empty()),
        container_id: c.id.to_ascii_lowercase(),
    }
}

/// The running containers of the Docker daemon whose state lives in `root`.
pub fn list_containers(root: &Path) -> Result<Vec<PodContainer>> {
    let dir = root.join("containers");
    let entries = std::fs::read_dir(&dir)
        .with_context(|| format!("cannot read {} (Docker installed? root?)", dir.display()))?;
    Ok(entries
        .flatten()
        .filter_map(|e| read_config(&e.path().join("config.v2.json")))
        .filter(|c| c.state.running)
        .map(to_pod_container)
        .collect())
}

#[derive(Deserialize)]
struct PodmanContainer {
    id: String,
    #[serde(default)]
    names: Vec<String>,
    /// Image id (hex, no `sha256:`).
    #[serde(default)]
    image: String,
    /// A JSON document in a string: `{"image-name": "docker.io/library/nginx:1.27", ...}`.
    #[serde(default)]
    metadata: String,
}

/// Every container of the Podman store in `root`, whatever its storage driver.
pub fn list_podman(root: &Path) -> Result<Vec<PodContainer>> {
    let entries = std::fs::read_dir(root)
        .with_context(|| format!("cannot read {} (Podman installed? root?)", root.display()))?;
    let mut out = Vec::new();
    for dir in entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with("-containers"))
    {
        let Ok(bytes) = std::fs::read(dir.path().join("containers.json")) else {
            continue;
        };
        let Ok(list) = serde_json::from_slice::<Vec<PodmanContainer>>(&bytes) else {
            continue;
        };
        out.extend(list.into_iter().map(|c| {
            let meta: serde_json::Value = serde_json::from_str(&c.metadata).unwrap_or_default();
            let name = c
                .names
                .first()
                .cloned()
                .unwrap_or_else(|| c.id[..12.min(c.id.len())].into());
            PodContainer {
                namespace: PODMAN_NAMESPACE.into(),
                pod: name.clone(),
                container: name,
                image: meta
                    .get("image-name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&c.image)
                    .to_string(),
                image_digest: (!c.image.is_empty()).then(|| format!("sha256:{}", c.image)),
                container_id: c.id.to_ascii_lowercase(),
            }
        }));
    }
    Ok(out)
}

/// Container id → name, read from the engine's state on first sight of an id.
pub struct DockerResolver {
    engine: Engine,
    cache: Mutex<HashMap<String, Option<ContainerInfo>>>,
}

impl DockerResolver {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            cache: Mutex::default(),
        }
    }
}

#[async_trait::async_trait]
impl ContainerResolver for DockerResolver {
    async fn by_container_id(&self, container_id: &str) -> Option<ContainerInfo> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = cache.get(container_id) {
            return hit.clone();
        }
        // A miss is remembered too: ids of nested runtimes (kind, k3d) are never the engine's.
        // shortcut: unbounded, one entry per container id seen; fine for a host's lifetime of containers
        let info = self.engine.lookup(container_id).map(|c| ContainerInfo {
            namespace: c.namespace,
            pod: c.pod,
            container: c.container,
        });
        cache.insert(container_id.to_string(), info.clone());
        info
    }
}

/// Send the containers that appear on the engine (and, with `existing`, those
/// already there) to `tx`, until `cancel` fires: `watch --vulns` scans them.
pub async fn notify_new_containers(
    engine: Engine,
    tx: mpsc::Sender<PodContainer>,
    existing: bool,
    cancel: CancellationToken,
) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut first = true;
    loop {
        for c in engine.list().unwrap_or_default() {
            if seen.insert(c.container_id.clone())
                && (existing || !first)
                && tx.send(c).await.is_err()
            {
                return;
            }
        }
        first = false;
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
    }
}

/// The containers' output, followed from their log files (realtime: what was
/// written before the watch started is skipped), as `log` events.
pub struct EngineLogSource {
    engine: Engine,
}

impl EngineLogSource {
    pub fn new(engine: Engine) -> Self {
        Self { engine }
    }
}

#[async_trait::async_trait]
impl EventSource for EngineLogSource {
    fn name(&self) -> &'static str {
        "engine-logs"
    }

    async fn run(self: Box<Self>, sink: EventSink, cancel: CancellationToken) -> Result<()> {
        // Container id → (read offset, the partial line read so far).
        let mut tails: HashMap<String, (u64, Vec<u8>)> = HashMap::new();
        let mut first = true;
        loop {
            for c in self.engine.list().unwrap_or_default() {
                let path = self.engine.log_file(&c.container_id);
                let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) else {
                    continue;
                };
                // A container already running at start is followed from its end.
                let (offset, partial) = tails
                    .entry(c.container_id.clone())
                    .or_insert_with(|| (if first { len } else { 0 }, Vec::new()));
                if len < *offset {
                    *offset = 0; // rotated or truncated
                    partial.clear();
                }
                let Some(chunk) = read_from(&path, *offset, (len - *offset).min(MAX_LOG_CHUNK))
                else {
                    continue;
                };
                *offset += chunk.len() as u64;
                partial.extend(chunk);
                let Some(end) = partial.iter().rposition(|&b| b == b'\n') else {
                    continue;
                };
                let complete: Vec<u8> = partial.drain(..=end).collect();
                for line in String::from_utf8_lossy(&complete).lines() {
                    if let Some((at, msg)) = parse_log_line(&self.engine, line) {
                        let ev = SecEvent::builder(Source::K8sLog, at)
                            .kind("log")
                            .severity(Severity::Info)
                            .namespace(c.namespace.clone())
                            .object(format!("{}/{}", c.pod, c.container))
                            .message(msg)
                            .meta("pod", c.pod.clone())
                            .meta("container", c.container.clone())
                            .build();
                        if sink.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            first = false;
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(POLL) => {}
            }
        }
    }
}

fn read_from(path: &Path, offset: u64, len: u64) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = Vec::with_capacity(len as usize);
    f.take(len).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Docker `json-file`: `{"log":"GET / 200\n","stream":"stdout","time":"…"}`.
/// Podman `k8s-file`: `2026-11-03T15:07:00.1+00:00 stdout F GET / 200`.
fn parse_log_line(engine: &Engine, line: &str) -> Option<(chrono::DateTime<chrono::Utc>, String)> {
    let parse_time = |t: &str| {
        chrono::DateTime::parse_from_rfc3339(t)
            .ok()
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    match engine {
        Engine::Docker(_) => {
            #[derive(Deserialize)]
            struct Line {
                log: String,
                #[serde(default)]
                time: String,
            }
            let l: Line = serde_json::from_str(line).ok()?;
            let at = parse_time(&l.time).unwrap_or_else(chrono::Utc::now);
            Some((at, l.log.trim_end_matches(['\n', '\r']).to_string()))
        }
        Engine::Podman(_) => {
            let mut f = line.splitn(4, ' ');
            let at = parse_time(f.next()?).unwrap_or_else(chrono::Utc::now);
            let (_stream, _flag) = (f.next()?, f.next()?);
            Some((at, f.next().unwrap_or("").to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = "1d66d1043c468d1d3d79b51db3f010608fb6756deddd6177f327c425ed872570";
    const STOPPED: &str = "2d66d1043c468d1d3d79b51db3f010608fb6756deddd6177f327c425ed872570";

    fn write(root: &Path, id: &str, name: &str, running: bool) {
        let dir = root.join("containers").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"ID":"{id}","Name":"/{name}","Image":"sha256:738f","Config":{{"Image":"nginx:1.25.3","Env":[]}},"State":{{"Running":{running},"Pid":42}},"Driver":"overlay2"}}"#
        );
        std::fs::write(dir.join("config.v2.json"), json).unwrap();
    }

    #[test]
    fn lists_running_containers_only() {
        let tmp = std::env::temp_dir().join(format!("k3sec-docker-{}", std::process::id()));
        write(&tmp, RUNNING, "web", true);
        write(&tmp, STOPPED, "old", false);
        std::fs::create_dir_all(tmp.join("containers/junk")).unwrap();

        let got = list_containers(&tmp).unwrap();
        assert_eq!(
            got,
            vec![PodContainer {
                namespace: "docker".into(),
                pod: "web".into(),
                container: "web".into(),
                image: "nginx:1.25.3".into(),
                image_digest: Some("sha256:738f".into()),
                container_id: RUNNING.into(),
            }]
        );

        let r = DockerResolver::new(Engine::Docker(tmp.clone()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert_eq!(
            rt.block_on(r.by_container_id(RUNNING)).map(|i| i.pod),
            Some("web".into())
        );
        assert_eq!(rt.block_on(r.by_container_id(&"f".repeat(64))), None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn podman_store_and_docker_data_root() {
        let tmp = std::env::temp_dir().join(format!("k3sec-podman-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("overlay-containers")).unwrap();
        std::fs::write(
            tmp.join("overlay-containers/containers.json"),
            format!(
                r#"[{{"id":"{RUNNING}","names":["web"],"image":"1e5f3c5b",
                     "metadata":"{{\"image-name\":\"docker.io/library/nginx:1.27\",\"name\":\"web\"}}"}}]"#
            ),
        )
        .unwrap();
        let podman = Engine::Podman(tmp.clone());
        let got = podman.list().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (
                got[0].namespace.as_str(),
                got[0].pod.as_str(),
                got[0].image.as_str()
            ),
            ("podman", "web", "docker.io/library/nginx:1.27")
        );
        assert_eq!(got[0].image_digest.as_deref(), Some("sha256:1e5f3c5b"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r = DockerResolver::new(podman);
        assert_eq!(
            rt.block_on(r.by_container_id(RUNNING)).map(|i| i.namespace),
            Some("podman".into())
        );

        std::fs::write(tmp.join("daemon.json"), r#"{"data-root": "/srv/docker"}"#).unwrap();
        if std::env::var_os("DOCKER_DATA_ROOT").is_none() {
            assert_eq!(
                data_root(&tmp.join("daemon.json")),
                PathBuf::from("/srv/docker")
            );
            assert_eq!(
                data_root(&tmp.join("missing.json")),
                PathBuf::from("/var/lib/docker")
            );
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn engine_log_lines() {
        let docker = Engine::Docker(PathBuf::new());
        let (at, msg) = parse_log_line(
            &docker,
            r#"{"log":"GET / 200\n","stream":"stdout","time":"2026-11-03T15:07:00.123Z"}"#,
        )
        .unwrap();
        assert_eq!(msg, "GET / 200");
        assert_eq!(at.to_rfc3339(), "2026-11-03T15:07:00.123+00:00");
        assert!(parse_log_line(&docker, "not json").is_none());

        let podman = Engine::Podman(PathBuf::new());
        let (_, msg) =
            parse_log_line(&podman, "2026-11-03T15:07:00.1+00:00 stdout F hello world").unwrap();
        assert_eq!(msg, "hello world");
    }
}
