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
        .split(['/', '-', '.', '_', ':'])
        .rfind(|seg| seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|seg| seg.to_ascii_lowercase())
}

/// Read `/proc/<pid>/cgroup` and extract the container id, if any.
pub fn container_id_of_pid(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    container_id_from_cgroup(&content)
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
        let path = format!("0::/system.slice/docker-{outer}.scope/kubepods/besteffort/podx/{CID}");
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
}
