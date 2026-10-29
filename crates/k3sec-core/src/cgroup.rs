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
/// The id is the inode of the cgroup's directory: on a miss, the host's tree is
/// walked again, at most once a second. Through `/proc/1/root`, which is the
/// host's root in a `hostPID` pod too (its own `/sys/fs/cgroup` is only its
/// cgroup namespace).
#[cfg(target_os = "linux")]
pub fn container_id_of_cgroup(cgroup_id: u64) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static INDEX: Mutex<Option<(HashMap<u64, String>, Instant)>> = Mutex::new(None);
    let mut index = INDEX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((map, at)) = index.as_ref() {
        if let Some(id) = map.get(&cgroup_id) {
            return Some(id.clone());
        }
        if at.elapsed() < Duration::from_secs(1) {
            return None;
        }
    }
    let root = ["/proc/1/root/sys/fs/cgroup", "/sys/fs/cgroup"]
        .into_iter()
        .find(|r| std::fs::read_dir(r).is_ok())?;
    let map = cgroup_index(std::path::Path::new(root));
    let found = map.get(&cgroup_id).cloned();
    *index = Some((map, Instant::now()));
    found
}

/// Directory inode → container id, for every container cgroup under `root`.
#[cfg(target_os = "linux")]
fn cgroup_index(root: &std::path::Path) -> std::collections::HashMap<u64, String> {
    use std::os::unix::fs::MetadataExt;

    let mut map = std::collections::HashMap::new();
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
            }
            // Deep enough for nested runtimes (k3s in a container: 5 to 6).
            if depth < 12 {
                stack.push((path, depth + 1));
            }
        }
    }
    map
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
        let map = cgroup_index(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(map.get(&ino).map(String::as_str), Some(CID));
        assert!(
            !map.contains_key(&pod_ino),
            "the pod's cgroup is no container"
        );
    }
}
