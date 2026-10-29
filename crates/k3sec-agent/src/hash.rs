//! SHA-256 of executed binaries, for hash reputation on the mlab side.
//!
//! Most execs are of the same few binaries (`sh`, `curl`, the app), so the
//! digest is cached by file identity (device, inode, size, mtime): a binary
//! is read once, not on every exec.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use sha2::{Digest, Sha256};

/// Binaries above this are not hashed.
pub const MAX_HASH_SIZE: u64 = 128 * 1024 * 1024;
const CACHE_ENTRIES: usize = 4096;

type FileKey = (u64, u64, u64, i64);

#[derive(Debug, Default)]
pub struct ExecHasher {
    cache: HashMap<FileKey, String>,
}

impl ExecHasher {
    /// Hex SHA-256 of the binary `pid` runs, through `/proc/<pid>/exe`
    /// (still readable after the file is deleted). `None` if the process is
    /// gone, the file too large, or unreadable.
    pub fn of_pid(&mut self, pid: u32) -> Option<String> {
        self.of_path(&format!("/proc/{pid}/exe"))
    }

    pub fn of_path(&mut self, path: &str) -> Option<String> {
        let file = std::fs::File::open(path).ok()?;
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.len() > MAX_HASH_SIZE {
            return None;
        }
        let key = (meta.dev(), meta.ino(), meta.len(), meta.mtime());
        if let Some(h) = self.cache.get(&key) {
            return Some(h.clone());
        }
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut reader = file.take(MAX_HASH_SIZE);
        loop {
            let n = reader.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if self.cache.len() >= CACHE_ENTRIES {
            // shortcut: wholesale reset instead of LRU, fine for a few thousand binaries
            self.cache.clear();
        }
        self.cache.insert(key, hex.clone());
        Some(hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bin");
        std::fs::write(&p, b"abc").unwrap();
        let mut h = ExecHasher::default();
        let digest = h.of_path(p.to_str().unwrap()).unwrap();
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.cache.len(), 1);
        assert_eq!(h.of_path(p.to_str().unwrap()).unwrap(), digest);
        assert_eq!(h.of_pid(u32::MAX), None, "no such process");
        // A running process: its binary, through /proc/<pid>/exe.
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let via_pid = h.of_pid(child.id());
        child.kill().ok();
        child.wait().ok();
        let direct = h.of_path("/bin/sleep");
        assert!(via_pid.is_some());
        assert_eq!(via_pid, direct);
    }
}
