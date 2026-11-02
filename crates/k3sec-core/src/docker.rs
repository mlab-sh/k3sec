//! Plain Docker hosts (no Kubernetes): the running containers, read from the
//! daemon's state files (`<data-root>/containers/<id>/config.v2.json`) rather
//! than its socket, so no HTTP client and no daemon round trip. Needs root,
//! like the rest of the node inventory.
//!
//! A container shows as namespace `docker`, pod and container both its name.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::{ContainerInfo, ContainerResolver, PodContainer};

/// The namespace Docker containers are shown under.
pub const NAMESPACE: &str = "docker";

/// Docker's default `data-root`.
// shortcut: a custom `data-root` in daemon.json is not read, set $DOCKER_DATA_ROOT
pub fn data_root() -> PathBuf {
    std::env::var_os("DOCKER_DATA_ROOT")
        .map(PathBuf::from)
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

/// Container id → name, read from the state file on first sight of an id.
pub struct DockerResolver {
    root: PathBuf,
    cache: Mutex<HashMap<String, Option<ContainerInfo>>>,
}

impl DockerResolver {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            cache: Mutex::default(),
        }
    }

    fn lookup(&self, id: &str) -> Option<ContainerInfo> {
        let c = read_config(&self.root.join("containers").join(id).join("config.v2.json"))?;
        let c = to_pod_container(c);
        Some(ContainerInfo {
            namespace: c.namespace,
            pod: c.pod,
            container: c.container,
        })
    }
}

#[async_trait::async_trait]
impl ContainerResolver for DockerResolver {
    async fn by_container_id(&self, container_id: &str) -> Option<ContainerInfo> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = cache.get(container_id) {
            return hit.clone();
        }
        // A miss is remembered too: ids of nested runtimes (kind, k3d) are never Docker's.
        // shortcut: unbounded, one entry per container id seen; fine for a host's lifetime of containers
        let info = self.lookup(container_id);
        cache.insert(container_id.to_string(), info.clone());
        info
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

        let r = DockerResolver::new(tmp.clone());
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
}
