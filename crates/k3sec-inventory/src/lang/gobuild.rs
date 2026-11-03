//! Go build info (`.go.buildinfo`): the toolchain version and module list
//! embedded in every Go ≥ 1.18 binary, as `go version -m` prints it.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

pub const MAGIC: &[u8] = b"\xff Go buildinf:";
/// The build info section is a header and two strings; anything larger is not one.
const MAX_SECTION: u64 = 16 * 1024 * 1024;
/// `flags & 2`: version and modinfo are inline varint-prefixed strings (1.18+).
const FLAG_INLINE: u8 = 0x2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoBuild {
    /// `1.22.1` (the `go` prefix stripped, as OSV's `stdlib` versions are).
    pub go_version: String,
    /// `(module path, version)` of every dependency, replacements applied.
    pub deps: Vec<(String, String)>,
}

/// Find and decode the build info in an executable's bytes.
pub fn parse(bin: &[u8]) -> Option<GoBuild> {
    // The header sits 16-byte aligned in the data segment, as Go's own reader assumes.
    let start = (0..bin.len().saturating_sub(32))
        .step_by(16)
        .find(|&i| bin[i..].starts_with(MAGIC))?;
    let flags = bin[start + 15];
    if flags & FLAG_INLINE == 0 {
        return None; // pre-1.18 pointer-based layout: not supported
    }
    let mut rest = &bin[start + 32..];
    let version = read_varint_str(&mut rest)?;
    let mut modinfo = read_varint_str(&mut rest)?;
    // modinfo is wrapped in 16-byte sentinels.
    if modinfo.len() >= 33 && modinfo.as_bytes()[modinfo.len() - 17] == b'\n' {
        modinfo = modinfo[16..modinfo.len() - 16].to_string();
    }

    let mut deps: Vec<(String, String)> = Vec::new();
    for line in modinfo.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["dep", path, ver, ..] => deps.push((path.to_string(), ver.to_string())),
            // `=>` replaces the dep on the line before it.
            ["=>", path, ver, ..] if !ver.is_empty() => {
                if let Some(last) = deps.last_mut() {
                    *last = (path.to_string(), ver.to_string());
                }
            }
            _ => {}
        }
    }
    Some(GoBuild {
        go_version: version.trim_start_matches("go").to_string(),
        deps,
    })
}

/// The `.go.buildinfo` section of a 64-bit little-endian ELF, read alone:
/// a Go binary can weigh hundreds of MiB (Vault: 550), its build info a few
/// KiB. `None` when the file is no such ELF or has no section table.
pub fn section(path: &Path) -> Option<Vec<u8>> {
    let f = File::open(path).ok()?;
    let read = |off: u64, len: u64| -> Option<Vec<u8>> {
        let mut buf = vec![0u8; usize::try_from(len).ok()?];
        f.read_exact_at(&mut buf, off).ok()?;
        Some(buf)
    };
    let eh = read(0, 64)?;
    if !eh.starts_with(b"\x7fELF") || eh[4] != 2 || eh[5] != 1 {
        return None;
    }
    let u16_at = |b: &[u8], at: usize| u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) as u64;
    let u64_at = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let (shoff, shentsize, shnum, shstrndx) = (
        u64_at(&eh, 0x28),
        u16_at(&eh, 0x3a),
        u16_at(&eh, 0x3c),
        u16_at(&eh, 0x3e),
    );
    if shentsize < 64 || shnum == 0 || shstrndx >= shnum {
        return None;
    }
    let table = read(shoff, shentsize * shnum)?;
    let header = |i: u64| &table[(i * shentsize) as usize..][..64];
    let (stroff, strsize) = (
        u64_at(header(shstrndx), 0x18),
        u64_at(header(shstrndx), 0x20),
    );
    let names = read(stroff, strsize.min(MAX_SECTION))?;
    (0..shnum).find_map(|i| {
        let h = header(i);
        let name = names.get(u32::from_le_bytes(h[0..4].try_into().unwrap()) as usize..)?;
        if !name.starts_with(b".go.buildinfo\0") {
            return None;
        }
        let (off, size) = (u64_at(h, 0x18), u64_at(h, 0x20));
        (size <= MAX_SECTION).then(|| read(off, size)).flatten()
    })
}

fn read_varint_str(buf: &mut &[u8]) -> Option<String> {
    let (mut len, mut shift) = (0usize, 0);
    loop {
        let (&b, rest) = buf.split_first()?;
        *buf = rest;
        len |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    let s = buf.get(..len)?;
    *buf = &buf[len..];
    Some(String::from_utf8_lossy(s).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_str(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut n = s.len();
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out.extend(s.as_bytes());
        out
    }

    fn fake_binary(modinfo: &str) -> Vec<u8> {
        let mut bin = b"\x7fELF".to_vec();
        bin.resize(48, 0); // header lands at 48: 16-aligned
        bin.extend(MAGIC);
        bin.extend([8, FLAG_INLINE]);
        bin.resize(48 + 32, 0);
        bin.extend(varint_str("go1.22.1"));
        let sentinel = "0123456789abcdef";
        bin.extend(varint_str(&format!("{sentinel}{modinfo}{sentinel}")));
        bin.extend([0; 64]);
        bin
    }

    /// A 64-bit LE ELF: 1 MiB of padding standing for the code, then the
    /// build info and a section table naming it.
    fn fake_elf(buildinfo: &[u8]) -> Vec<u8> {
        let names = b"\0.shstrtab\0.go.buildinfo\0";
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // little-endian
        elf.resize(1 << 20, 0);
        let info_off = elf.len() as u64;
        elf.extend(buildinfo);
        let names_off = elf.len() as u64;
        elf.extend(names);
        let shoff = elf.len() as u64;
        let sh = |name: u32, off: u64, size: u64| {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&off.to_le_bytes());
            h[0x20..0x28].copy_from_slice(&size.to_le_bytes());
            h
        };
        let table = [
            sh(0, 0, 0),
            sh(1, names_off, names.len() as u64),
            sh(11, info_off, buildinfo.len() as u64),
        ]
        .concat();
        elf.extend(table);
        elf[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        elf[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes());
        elf
    }

    #[test]
    fn reads_only_the_buildinfo_section() {
        let modinfo = "path\tex.com/vault\ndep\tgolang.org/x/net\tv0.17.0\th1:y=\n";
        let info = &fake_binary(modinfo)[48..]; // from the magic on, as the section holds it
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        std::fs::write(&path, fake_elf(info)).unwrap();

        let sec = section(&path).unwrap();
        assert!(sec.starts_with(MAGIC));
        assert!(sec.len() < 4096, "the section, not the binary");
        let got = parse(&sec).unwrap();
        assert_eq!(got.go_version, "1.22.1");
        assert_eq!(got.deps, [("golang.org/x/net".into(), "v0.17.0".into())]);

        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        assert!(section(&path).is_none());
    }

    #[test]
    fn decodes_version_deps_and_replacements() {
        let modinfo = "path\texample.com/app\nmod\texample.com/app\t(devel)\t\n\
dep\tgithub.com/gin-gonic/gin\tv1.9.1\th1:x=\n\
dep\tgolang.org/x/net\tv0.17.0\th1:y=\n\
=>\tgolang.org/x/net\tv0.23.0\th1:z=\n\
build\t-compiler=gc\n";
        let info = parse(&fake_binary(modinfo)).unwrap();
        assert_eq!(info.go_version, "1.22.1");
        assert_eq!(
            info.deps,
            vec![
                ("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string()),
                ("golang.org/x/net".to_string(), "v0.23.0".to_string()),
            ]
        );
    }

    #[test]
    fn non_go_binary() {
        assert_eq!(parse(b"\x7fELF just some C program"), None);
        assert_eq!(parse(&[]), None);
    }
}
