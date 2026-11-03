//! cgroup path parsing, shared by the probe (to tag events) and the inventory
//! (to find a container's PIDs).

/// Extract a container runtime ID (64-hex) from a cgroup path.
///
/// Handles the common shapes across cgroup drivers:
/// * cgroupfs: `…/pod<uid>/<64hex>`
/// * systemd:  `…/cri-containerd-<64hex>.scope`, `docker-<64hex>.scope`, …
///
/// The *last* 64-hex segment wins: when k3s itself runs in a container (k3d,
/// kind), the outer segment is the node container and the inner one the pod's.
///
/// Returns the lowercased id, or `None` if no 64-hex segment is present (host
/// process, not in a container).
pub fn container_id_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .split(['/', '-', '.', '_', ':', '\n'])
        .rfind(|seg| seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|seg| seg.to_ascii_lowercase())
}

/// Read `/proc/<pid>/cgroup` and extract the container id, if any.
pub fn container_id_of_pid(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    container_id_from_cgroup(&content)
}

/// The container id of a cgroup v2 id (`bpf_get_current_cgroup_id`), for a
/// process gone before its `/proc/<pid>/cgroup` was read (a short `exec`).
/// The id is the inode of the cgroup's directory. An id not seen yet walks the
/// host's tree again at once (a few ms): a container seconds old is there now
/// and may be gone in a second. An id still unknown after a walk is no
/// container and is not walked for again. Through `/proc/1/root`, which is the
/// host's root in a `hostPID` pod too (its own `/sys/fs/cgroup` is only its
/// cgroup namespace).
#[cfg(target_os = "linux")]
pub fn container_id_of_cgroup(cgroup_id: u64) -> Option<String> {
    let mut guard = INDEX.lock().unwrap_or_else(|e| e.into_inner());
    let index = guard.get_or_insert_with(Default::default);
    if let Some(id) = index.containers.get(&cgroup_id) {
        return Some(id.clone());
    }
    if index.misses.contains(&cgroup_id) {
        return None;
    }
    let root = ["/proc/1/root/sys/fs/cgroup", "/sys/fs/cgroup"]
        .into_iter()
        .find(|r| std::fs::read_dir(r).is_ok())?;
    let root = std::path::Path::new(root);
    let (containers, hosts) = cgroup_index(root);
    index.containers = containers;
    // Only a pure cgroup v2 tree shares its ids with the kernel's
    // `bpf_get_current_cgroup_id`; a v1 hierarchy's inodes are another space.
    index.hosts = if root.join("cgroup.controllers").exists() {
        hosts
    } else {
        Default::default()
    };
    let found = index.containers.get(&cgroup_id).cloned();
    if found.is_none() {
        // shortcut: wholesale reset instead of expiry, bounded by the node's cgroups
        if index.misses.len() >= 4096 {
            index.misses.clear();
        }
        index.misses.insert(cgroup_id);
    }
    found
}

/// A cgroup v2 id that is a directory of the host's tree with no container in
/// its path (`system.slice/sshd.service`), as of the last walk: the kernel can
/// drop its events (`HOST_CGROUPS`). False for anything not seen in a walk.
#[cfg(target_os = "linux")]
pub fn is_host_cgroup(cgroup_id: u64) -> bool {
    let guard = INDEX.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().is_some_and(|i| i.hosts.contains(&cgroup_id))
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Index {
    /// Inode → container id.
    containers: std::collections::HashMap<u64, String>,
    /// Inodes no walk found a container for.
    misses: std::collections::HashSet<u64>,
    /// Inodes of the host's own cgroups.
    hosts: std::collections::HashSet<u64>,
}

#[cfg(target_os = "linux")]
static INDEX: std::sync::Mutex<Option<Index>> = std::sync::Mutex::new(None);

/// Directory inode → container id, for every container cgroup under `root`,
/// and the inodes of the others (the host's).
#[cfg(target_os = "linux")]
fn cgroup_index(
    root: &std::path::Path,
) -> (
    std::collections::HashMap<u64, String>,
    std::collections::HashSet<u64>,
) {
    use std::os::unix::fs::MetadataExt;

    let mut map = std::collections::HashMap::new();
    let mut hosts = std::collections::HashSet::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_dir() {
                continue;
            }
            let path = entry.path();
            if let Some(id) = path.to_str().and_then(container_id_from_cgroup) {
                map.insert(meta.ino(), id);
            } else {
                hosts.insert(meta.ino());
            }
            // Deep enough for nested runtimes (k3s in a container: 5 to 6).
            if depth < 12 {
                stack.push((path, depth + 1));
            }
        }
    }
    (map, hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: &str = "3f9a1b2c4d5e6f7089abcdef0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn parses_cgroupfs_path() {
        let path = format!("0::/kubepods/besteffort/pod1234-5678/{CID}");
        assert_eq!(container_id_from_cgroup(&path).as_deref(), Some(CID));
    }

    #[test]
    fn parses_systemd_scope_path() {
        let path = format!(
            "0::/kubepods.slice/kubepods-besteffort.slice/\
             kubepods-besteffort-pod1234_5678.slice/cri-containerd-{CID}.scope"
        );
        assert_eq!(container_id_from_cgroup(&path).as_deref(), Some(CID));
    }

    #[test]
    fn nested_runtime_picks_innermost_id() {
        let outer = "a".repeat(64);
        // As read from /proc/<pid>/cgroup: newline-terminated.
        let path =
            format!("0::/system.slice/docker-{outer}.scope/kubepods/besteffort/podx/{CID}\n");
        assert_eq!(container_id_from_cgroup(&path).as_deref(), Some(CID));
    }

    #[test]
    fn host_process_has_no_container_id() {
        assert_eq!(container_id_from_cgroup("0::/init.scope"), None);
        assert_eq!(
            container_id_from_cgroup("0::/system.slice/sshd.service"),
            None
        );
    }

    #[test]
    fn uppercase_hex_is_normalized() {
        let upper = CID.to_ascii_uppercase();
        let path = format!("0::/kubepods/besteffort/podabc/{upper}");
        assert_eq!(container_id_from_cgroup(&path).as_deref(), Some(CID));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_inode_maps_to_its_container() {
        use std::os::unix::fs::MetadataExt;

        let root = std::env::temp_dir().join(format!("k3sec-cgroup-{}", std::process::id()));
        let dir = root.join("kubepods/besteffort/pod1234").join(CID);
        std::fs::create_dir_all(&dir).unwrap();
        let ino = std::fs::metadata(&dir).unwrap().ino();
        let pod_ino = std::fs::metadata(dir.parent().unwrap()).unwrap().ino();
        let host_ino = {
            let sshd = root.join("system.slice/sshd.service");
            std::fs::create_dir_all(&sshd).unwrap();
            std::fs::metadata(&sshd).unwrap().ino()
        };
        let (map, hosts) = cgroup_index(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(map.get(&ino).map(String::as_str), Some(CID));
        assert!(
            !map.contains_key(&pod_ino),
            "the pod's cgroup is no container"
        );
        assert!(hosts.contains(&host_ino) && !hosts.contains(&ino));
    }
}
