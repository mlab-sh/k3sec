//! rpm: the SQLite rpmdb (`/var/lib/rpm/rpmdb.sqlite`, RHEL/Rocky/Alma 9+,
//! Fedora 33+; `/usr/lib/sysimage/rpm/rpmdb.sqlite` on Fedora 36+, RHEL 10 and
//! Hummingbird). Each row of `Packages` is a binary rpm header blob.
//! The Berkeley DB hash rpmdb (`/var/lib/rpm/Packages`, EL7 / EL8) holds the
//! same blobs as its values. NDB (SUSE) is not supported.

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::rootfs::{read_file_limited, Rootfs};

use super::{OsPackage, MAX_DB_SIZE};

const NAME: u32 = 1000;
const VERSION: u32 = 1001;
const RELEASE: u32 = 1002;
const EPOCH: u32 = 1003;
const ARCH: u32 = 1022;
const SOURCERPM: u32 = 1044;
const DIRINDEXES: u32 = 1116;
const BASENAMES: u32 = 1117;
const DIRNAMES: u32 = 1118;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

/// Where the SQLite rpmdb lives: the historical path, then the one rpm moved
/// to (Fedora 36+, RHEL 10, Hummingbird), which may have no `/var/lib/rpm`.
pub const SQLITE_PATHS: [&str; 2] = [
    "/var/lib/rpm/rpmdb.sqlite",
    "/usr/lib/sysimage/rpm/rpmdb.sqlite",
];

pub fn read(fs: &Rootfs) -> Option<Result<Vec<OsPackage>>> {
    if let Some(path) = SQLITE_PATHS.iter().find_map(|p| fs.host_path(p)) {
        return Some(read_copy(&path));
    }
    let path = fs.host_path("/var/lib/rpm/Packages")?;
    Some(read_bdb_file(&path))
}

fn read_bdb_file(path: &std::path::Path) -> Result<Vec<OsPackage>> {
    let db = read_file_limited(path, MAX_DB_SIZE).context("cannot read rpmdb Packages")?;
    Ok(bdb_values(&db)?
        .iter()
        .filter_map(|b| parse_header(b))
        .filter(|p| p.name != "gpg-pubkey")
        .collect())
}

/// The values of a Berkeley DB hash database: walk the hash pages, follow each
/// off-page item through its chain of overflow pages (rpm headers never fit
/// inline). Byte order is the writer's, told by the metadata magic.
fn bdb_values(db: &[u8]) -> Result<Vec<Vec<u8>>> {
    const HASH_MAGIC: u32 = 0x0006_1561;
    const P_HASH_UNSORTED: u8 = 2;
    const P_HASH: u8 = 13;
    const H_OFFPAGE: u8 = 3;
    const PAGE_HEADER: usize = 26;

    let le = match db.get(12..16).map(|m| <[u8; 4]>::try_from(m).unwrap()) {
        Some(m) if u32::from_le_bytes(m) == HASH_MAGIC => true,
        Some(m) if u32::from_be_bytes(m) == HASH_MAGIC => false,
        _ => bail!("not a Berkeley DB hash database"),
    };
    let u16_at = |b: &[u8], at: usize| -> Option<usize> {
        let x: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(x)
        } else {
            u16::from_be_bytes(x)
        } as usize)
    };
    let u32_at = |b: &[u8], at: usize| -> Option<usize> {
        let x: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(x)
        } else {
            u32::from_be_bytes(x)
        } as usize)
    };
    let page_size = u32_at(db, 20).context("truncated metadata page")?;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        bail!("bad Berkeley DB page size {page_size}");
    }
    let last = u32_at(db, 32).context("truncated metadata page")?;
    let page = |n: usize| db.get(n * page_size..(n + 1) * page_size);

    let mut values = Vec::new();
    for n in 1..=last {
        let Some(p) = page(n) else { break };
        if !matches!(p[25], P_HASH | P_HASH_UNSORTED) {
            continue;
        }
        let entries = u16_at(p, 20).unwrap_or(0);
        // Items alternate key, value: the values are the odd ones.
        for i in (1..entries).step_by(2) {
            let Some(off) = u16_at(p, PAGE_HEADER + 2 * i) else {
                break;
            };
            if p.get(off) != Some(&H_OFFPAGE) {
                continue;
            }
            let (Some(mut next), Some(len)) = (u32_at(p, off + 4), u32_at(p, off + 8)) else {
                continue;
            };
            if len as u64 > MAX_DB_SIZE {
                continue;
            }
            let mut value = Vec::with_capacity(len);
            // The chain is at most `last` pages long: a loop is corruption.
            for _ in 0..=last {
                let Some(o) = page(next).filter(|_| next != 0 && value.len() < len) else {
                    break;
                };
                let used = u16_at(o, 22).unwrap_or(0);
                value.extend_from_slice(o.get(PAGE_HEADER..PAGE_HEADER + used).unwrap_or(&[]));
                next = u32_at(o, 16).unwrap_or(0);
            }
            if value.len() >= len {
                value.truncate(len);
                values.push(value);
            }
        }
    }
    Ok(values)
}

/// SQLite canonicalizes the db path, and `/proc/<pid>/root` is a magic link
/// to `/`: opened in place it would read the *host's* rpmdb. Read a copy.
fn read_copy(path: &std::path::Path) -> Result<Vec<OsPackage>> {
    let bytes = read_file_limited(path, MAX_DB_SIZE).context("cannot read rpmdb.sqlite")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp =
        std::env::temp_dir().join(format!("k3sec-rpmdb-{}-{nanos}.sqlite", std::process::id()));
    std::fs::write(&tmp, bytes).context("cannot copy rpmdb.sqlite to a temp file")?;
    let result = read_db(&tmp);
    let _ = std::fs::remove_file(&tmp);
    result
}

fn read_db(path: &std::path::Path) -> Result<Vec<OsPackage>> {
    // Read-only and immutable: no locks, no -wal/-shm side files.
    let uri = format!("file:{}?immutable=1", path.display());
    let conn = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .context("failed to open rpmdb.sqlite")?;
    let mut stmt = conn
        .prepare("SELECT blob FROM Packages")
        .context("rpmdb.sqlite has no Packages table")?;
    let blobs = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    Ok(blobs
        .filter_map(|b| b.ok().and_then(|b| parse_header(&b)))
        .filter(|p| p.name != "gpg-pubkey")
        .collect())
}

/// Parse an rpm header blob (as stored in rpmdb, without the 8-byte magic):
/// `il:u32 dl:u32`, then `il` index entries `tag type offset count`, then data.
pub fn parse_header(blob: &[u8]) -> Option<OsPackage> {
    let be = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(blob.get(at..at + 4)?.try_into().ok()?))
    };
    let il = be(0)? as usize;
    let dl = be(4)? as usize;
    let data_start = 8 + il.checked_mul(16)?;
    let data = blob.get(data_start..data_start.checked_add(dl)?)?;

    let strings = |tag: u32| -> Vec<String> {
        (0..il)
            .find_map(|i| {
                let e = 8 + i * 16;
                (be(e)? == tag).then_some(())?;
                let (ty, off, count) = (be(e + 4)?, be(e + 8)? as usize, be(e + 12)? as usize);
                let tail = data.get(off..)?;
                match ty {
                    TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING => Some(
                        tail.split(|&b| b == 0)
                            .take(count.max(1))
                            .map(|s| String::from_utf8_lossy(s).into_owned())
                            .collect(),
                    ),
                    TYPE_INT32 => Some(
                        tail.chunks_exact(4)
                            .take(count)
                            .map(|c| u32::from_be_bytes(c.try_into().unwrap()).to_string())
                            .collect(),
                    ),
                    _ => None,
                }
            })
            .unwrap_or_default()
    };

    let one = |v: Vec<String>| v.into_iter().next();
    let name = one(strings(NAME))?;
    let version = one(strings(VERSION))?;
    let release = one(strings(RELEASE))?;
    let epoch = one(strings(EPOCH));
    let arch = one(strings(ARCH)).unwrap_or_default();
    let source = one(strings(SOURCERPM)).and_then(|s| source_name(&s));

    let dirs = strings(DIRNAMES);
    let files = strings(BASENAMES)
        .into_iter()
        .zip(strings(DIRINDEXES))
        .filter_map(|(base, idx)| Some(format!("{}{base}", dirs.get(idx.parse::<usize>().ok()?)?)))
        .collect();

    let evr = match epoch {
        Some(e) if e != "0" => format!("{e}:{version}-{release}"),
        _ => format!("{version}-{release}"),
    };
    Some(OsPackage {
        name,
        version: evr,
        arch,
        source,
        source_version: None,
        files,
    })
}

/// `openssl-3.0.7-27.el9.src.rpm` → `openssl`.
fn source_name(srpm: &str) -> Option<String> {
    let stem = srpm.strip_suffix(".src.rpm")?;
    let mut parts = stem.rsplitn(3, '-');
    let (_release, _version) = (parts.next()?, parts.next()?);
    parts.next().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header blob from `(tag, type, payload, count)` entries.
    fn header(entries: &[(u32, u32, Vec<u8>, u32)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, ty, payload, count) in entries {
            while *ty == TYPE_INT32 && data.len() % 4 != 0 {
                data.push(0);
            }
            for v in [*tag, *ty, data.len() as u32, *count] {
                index.extend(v.to_be_bytes());
            }
            data.extend(payload);
        }
        let mut blob = Vec::new();
        blob.extend((entries.len() as u32).to_be_bytes());
        blob.extend((data.len() as u32).to_be_bytes());
        blob.extend(index);
        blob.extend(data);
        blob
    }

    fn s(v: &str) -> Vec<u8> {
        format!("{v}\0").into_bytes()
    }

    #[test]
    fn parses_header_with_files_and_epoch() {
        let blob = header(&[
            (NAME, TYPE_STRING, s("openssl-libs"), 1),
            (VERSION, TYPE_STRING, s("3.0.7"), 1),
            (RELEASE, TYPE_STRING, s("27.el9"), 1),
            (EPOCH, TYPE_INT32, 1u32.to_be_bytes().to_vec(), 1),
            (ARCH, TYPE_STRING, s("x86_64"), 1),
            (SOURCERPM, TYPE_STRING, s("openssl-3.0.7-27.el9.src.rpm"), 1),
            (
                DIRNAMES,
                TYPE_STRING_ARRAY,
                [s("/usr/lib64/"), s("/etc/")].concat(),
                2,
            ),
            (
                BASENAMES,
                TYPE_STRING_ARRAY,
                [s("libssl.so.3"), s("ssl.cnf")].concat(),
                2,
            ),
            (
                DIRINDEXES,
                TYPE_INT32,
                [0u32.to_be_bytes(), 1u32.to_be_bytes()].concat(),
                2,
            ),
        ]);
        let p = parse_header(&blob).unwrap();
        assert_eq!(p.name, "openssl-libs");
        assert_eq!(p.version, "1:3.0.7-27.el9");
        assert_eq!(p.source.as_deref(), Some("openssl"));
        assert_eq!(p.files, ["/usr/lib64/libssl.so.3", "/etc/ssl.cnf"]);
    }

    #[test]
    fn reads_rpmdb_under_usr_lib_sysimage() {
        // Hummingbird: no /var/lib/rpm at all, the db only at its new home.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("usr/lib/sysimage/rpm");
        std::fs::create_dir_all(&db).unwrap();
        let conn = Connection::open(db.join("rpmdb.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)",
            [],
        )
        .unwrap();
        let blob = header(&[
            (NAME, TYPE_STRING, s("nginx-core"), 1),
            (VERSION, TYPE_STRING, s("1.30.6"), 1),
            (RELEASE, TYPE_STRING, s("1.hum1"), 1),
            (ARCH, TYPE_STRING, s("x86_64"), 1),
        ]);
        conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [blob])
            .unwrap();
        drop(conn);

        let pkgs = read(&Rootfs::new(dir.path())).unwrap().unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "nginx-core");
        assert_eq!(pkgs[0].version, "1.30.6-1.hum1");
    }

    /// A 3-page little-endian hash db: metadata, one hash page whose value
    /// is off-page, the overflow page holding `blob`.
    fn bdb(blob: &[u8], next_of_overflow: u32) -> Vec<u8> {
        const PS: usize = 512;
        let mut db = vec![0u8; 3 * PS];
        db[12..16].copy_from_slice(&0x0006_1561u32.to_le_bytes());
        db[20..24].copy_from_slice(&(PS as u32).to_le_bytes());
        db[32..36].copy_from_slice(&2u32.to_le_bytes());
        let hash = &mut db[PS..2 * PS];
        hash[25] = 13;
        hash[20..22].copy_from_slice(&2u16.to_le_bytes());
        hash[26..28].copy_from_slice(&400u16.to_le_bytes());
        hash[28..30].copy_from_slice(&450u16.to_le_bytes());
        hash[400] = 1; // key: inline
        hash[450] = 3; // value: off-page
        hash[454..458].copy_from_slice(&2u32.to_le_bytes());
        hash[458..462].copy_from_slice(&(blob.len() as u32).to_le_bytes());
        let over = &mut db[2 * PS..];
        over[25] = 7;
        over[16..20].copy_from_slice(&next_of_overflow.to_le_bytes());
        over[22..24].copy_from_slice(&(blob.len() as u16).to_le_bytes());
        over[26..26 + blob.len()].copy_from_slice(blob);
        db
    }

    #[test]
    fn reads_berkeley_db_hash_rpmdb() {
        let blob = header(&[
            (NAME, TYPE_STRING, s("openssl-libs"), 1),
            (VERSION, TYPE_STRING, s("1.1.1k"), 1),
            (RELEASE, TYPE_STRING, s("14.el8_10"), 1),
            (EPOCH, TYPE_INT32, 1u32.to_be_bytes().to_vec(), 1),
            (ARCH, TYPE_STRING, s("x86_64"), 1),
        ]);
        let values = bdb_values(&bdb(&blob, 0)).unwrap();
        assert_eq!(values, [blob.clone()]);
        let p = parse_header(&values[0]).unwrap();
        assert_eq!(
            (p.name.as_str(), p.version.as_str()),
            ("openssl-libs", "1:1.1.1k-14.el8_10")
        );

        // An overflow chain pointing back at itself stops instead of looping.
        let short = &blob[..blob.len() / 2];
        let mut looped = bdb(short, 2);
        looped[512 + 458..512 + 462].copy_from_slice(&(blob.len() as u32).to_le_bytes());
        assert!(bdb_values(&looped)
            .unwrap()
            .iter()
            .all(|v| v.len() == blob.len()));

        assert!(bdb_values(b"not a database at all, really").is_err());
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert!(parse_header(&[0, 0, 0, 9, 0, 0, 0, 1]).is_none());
        assert!(parse_header(&[]).is_none());
    }
}
