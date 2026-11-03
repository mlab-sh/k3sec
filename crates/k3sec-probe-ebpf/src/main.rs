//! k3sec eBPF kernel programs.
//!
//! Three hooks, each filling one fixed-size [`Event`] into the `EVENTS` ring
//! buffer:
//! * `execve`     , `sched:sched_process_exec` (executed binary, successful
//!   execs only).
//! * `connect`    , kprobes on `tcp_v4_connect` / `tcp_v6_connect` (dest ip:port).
//! * `file_write` , kprobe on `do_sys_openat2` (every open, openat, openat2 and
//!   creat), filtered in-kernel to *write* opens under sensitive paths, so
//!   userspace never sees the firehose.
//!
//! On ring-buffer backpressure we bump `DROPS` and return cleanly, never block,
//! never panic on event data.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, raw_tracepoint, tracepoint},
    maps::{Array, RingBuf},
    programs::{ProbeContext, RawTracePointContext, TracePointContext},
    EbpfContext,
};
use k3sec_probe_common::{af, kind, Event, AUX_LEN, FILENAME_LEN};

/// Ring buffer carrying events to userspace (256 KiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Single-slot counter of events dropped because the ring buffer was full.
#[map]
static DROPS: Array<u64> = Array::with_max_entries(1, 0);

/// Sensitive path prefixes matched in-kernel for `file_write`.
const SENSITIVE_PREFIXES: [&[u8]; 6] = [
    b"/etc/",
    b"/usr/bin/",
    b"/root/",
    b"/var/run/secrets",
    // Escape primitives: cgroup v1 release_agent, core_pattern, modprobe.
    b"/sys/fs/cgroup/",
    b"/proc/sys/",
];

/// Credentials, matched in-kernel for `secret_read` (read-only opens). Under
/// `/home/` userspace keeps only the credential directories.
const SECRET_PREFIXES: [&[u8]; 12] = [
    b"/var/run/secrets/kubernetes.io/",
    b"/run/secrets/kubernetes.io/",
    b"/etc/shadow",
    b"/etc/kubernetes/",
    b"/var/lib/kubelet/pki/",
    b"/root/.ssh/",
    b"/root/.aws/",
    b"/root/.kube/",
    b"/root/.docker/",
    b"/root/.config/gcloud/",
    b"/root/.azure/",
    b"/home/",
];

// ---------------------------------------------------------------------------
// execve
// ---------------------------------------------------------------------------

/// Tracepoint: `sched:sched_process_exec`, in the new image after a successful
/// exec. Not `syscalls:sys_enter_execve`: on recent kernels (7.0) its BPF
/// programs miss most execs, and it also fires for failed PATH lookups.
#[tracepoint]
pub fn k3sec_execve(ctx: TracePointContext) -> u32 {
    let _ = try_execve(&ctx);
    0
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();

    // SAFETY: `e` is a freshly reserved, exclusively-owned slot sized for `Event`;
    // every field is initialized before `submit`.
    unsafe {
        fill_common(e, kind::EXEC);
        // `__data_loc char[] filename` at offset 8: the string's offset in the
        // record (low 16 bits), its length (high 16).
        if let Ok(loc) = ctx.read_at::<u32>(8) {
            let src = (ctx.as_ptr() as *const u8).add((loc & 0xffff) as usize);
            let _ = bpf_probe_read_kernel_str_bytes(src, &mut (*e).filename);
        }
    }

    entry.submit(0);
    Ok(())
}

/// The same `sched_process_exec`, as a raw tracepoint: attached by name, so it
/// works where tracefs is not mounted (Talos in Docker). It does not read the
/// path (that needs `struct linux_binprm` offsets, per kernel): userspace
/// takes it from `/proc/<pid>/exe`.
#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn k3sec_execve_raw(_ctx: RawTracePointContext) -> i32 {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return 0;
    };
    // SAFETY: as in `try_execve`; `fill_common` initializes every field.
    unsafe { fill_common(entry.as_mut_ptr(), kind::EXEC) };
    entry.submit(0);
    0
}

/// `sched_process_exit`, as a raw tracepoint (no field is read): a process,
/// not each of its threads, ends.
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn k3sec_exit(_ctx: RawTracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    if (id >> 32) as u32 != id as u32 {
        return 0; // a thread, not the group leader
    }
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return 0;
    };
    // SAFETY: as in `try_execve`; `fill_common` initializes every field.
    unsafe { fill_common(entry.as_mut_ptr(), kind::EXIT) };
    entry.submit(0);
    0
}

// ---------------------------------------------------------------------------
// file_write (openat with write intent, under a sensitive path)
// ---------------------------------------------------------------------------

/// kprobe: `do_sys_openat2(int dfd, const char __user *filename, struct
/// open_how *how)`, where every open syscall ends up. Not the
/// `syscalls:sys_enter_openat` tracepoint: on recent kernels (7.0) its BPF
/// programs miss most calls, and `open` / `creat` never pass there. Emits only
/// write-opens under a sensitive path; everything else is filtered here.
#[kprobe]
pub fn k3sec_openat(ctx: ProbeContext) -> u32 {
    let _ = try_openat(&ctx);
    0
}

fn try_openat(ctx: &ProbeContext) -> Result<(), i64> {
    let filename_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let how: *const u64 = ctx.arg(2).ok_or(0i64)?;
    if filename_ptr.is_null() || how.is_null() {
        return Ok(());
    }
    // `struct open_how` starts with `u64 flags`.
    let flags: u64 = unsafe { bpf_probe_read_kernel(how) }.unwrap_or(0);
    let write = is_write_open(flags);

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();

    // SAFETY: as in `try_execve`. We read the path into the slot, then keep the
    // event only if it targets a sensitive prefix (writes) or a credential
    // (reads), else discard it.
    unsafe {
        fill_common(
            e,
            if write {
                kind::FILE_WRITE
            } else {
                kind::SECRET_READ
            },
        );
        let read = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*e).filename);
        let keep = match read {
            Ok(bytes) if write => matches_any(bytes, &SENSITIVE_PREFIXES),
            Ok(bytes) => matches_any(bytes, &SECRET_PREFIXES),
            Err(_) => false,
        };
        if !keep {
            entry.discard(0);
            return Ok(());
        }
    }

    entry.submit(0);
    Ok(())
}

fn is_write_open(flags: u64) -> bool {
    // Access mode is the low 2 bits: 1=O_WRONLY, 2=O_RDWR. Plus create/trunc/append.
    let acc = flags & 0o3;
    acc == 1 || acc == 2 || (flags & (0o100 | 0o1000 | 0o2000)) != 0
}

fn matches_any(path: &[u8], prefixes: &[&[u8]]) -> bool {
    let mut p = 0;
    while p < prefixes.len() {
        if starts_with(path, prefixes[p]) {
            return true;
        }
        p += 1;
    }
    false
}

#[inline(always)]
fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    let mut i = 0;
    // Hard cap keeps the verifier happy; all prefixes are far shorter than 32.
    while i < prefix.len() && i < 32 {
        if i >= path.len() || path[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// connect (TCP v4/v6)
// ---------------------------------------------------------------------------

/// kprobe: `unix_stream_connect(struct socket *sock, struct sockaddr *uaddr,
/// int addr_len, int flags)`: `uaddr` is the kernel's copy of the
/// `sockaddr_un`, its path at offset 2 (abstract sockets start with NUL and
/// read as empty). Userspace keeps the container runtimes' sockets.
#[kprobe]
pub fn k3sec_unix_connect(ctx: ProbeContext) -> u32 {
    let _ = try_unix_connect(&ctx);
    0
}

fn try_unix_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let uaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    if uaddr.is_null() {
        return Ok(());
    }
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    // SAFETY: as in `try_execve`; the path is read into the reserved slot.
    unsafe {
        fill_common(e, kind::UNIX_CONNECT);
        let path = (uaddr as usize + 2) as *const u8;
        if bpf_probe_read_kernel_str_bytes(path, &mut (*e).filename).is_err()
            || (*e).filename[0] != b'/'
        {
            entry.discard(0);
            return Ok(());
        }
    }
    entry.submit(0);
    Ok(())
}

/// kprobe: `alloc_fs_context(struct file_system_type *fs_type, struct dentry
/// *reference, unsigned int sb_flags, unsigned int sb_flags_mask, enum
/// fs_context_purpose purpose)`: every new mount, through `mount(2)` or the
/// `fsopen(2)` API alike. `struct file_system_type` starts with `const char
/// *name`, the one field read. Remounts and submounts (`purpose` != 0) skipped.
#[kprobe]
pub fn k3sec_mount(ctx: ProbeContext) -> u32 {
    let _ = try_mount(&ctx);
    0
}

fn try_mount(ctx: &ProbeContext) -> Result<(), i64> {
    let fs_type: *const *const u8 = ctx.arg(0).ok_or(1i64)?;
    let purpose: u64 = ctx.arg(4).ok_or(1i64)?;
    if fs_type.is_null() || purpose != 0 {
        return Ok(());
    }
    let name: *const u8 = unsafe { bpf_probe_read_kernel(fs_type) }?;
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    // SAFETY: as in `try_execve`; the type name is a kernel string.
    unsafe {
        fill_common(e, kind::MOUNT);
        if !name.is_null() {
            let _ = bpf_probe_read_kernel_str_bytes(name, &mut (*e).aux);
        }
    }
    entry.submit(0);
    Ok(())
}

/// kprobe: `commit_creds(struct cred *new)`, where every change of identity
/// lands (setuid calls, a setuid binary's exec, capset). Only a non-root
/// process's: the uid in the event is the old one, userspace reads the new
/// one from `/proc/<pid>/status` (the `struct cred` layout varies by kernel).
#[kprobe]
pub fn k3sec_commit_creds(_ctx: ProbeContext) -> u32 {
    if bpf_get_current_uid_gid() as u32 == 0 {
        return 0;
    }
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return 0;
    };
    // SAFETY: as in `try_execve`; `fill_common` initializes every field.
    unsafe { fill_common(entry.as_mut_ptr(), kind::CREDS) };
    entry.submit(0);
    0
}

/// kprobe: `tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int len)`.
#[kprobe]
pub fn k3sec_tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx, af::INET);
    0
}

/// kprobe: `tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int len)`.
#[kprobe]
pub fn k3sec_tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx, af::INET6);
    0
}

fn try_connect(ctx: &ProbeContext, family: u16) -> Result<(), i64> {
    // arg1 = struct sockaddr *uaddr (kernel memory at this point).
    let uaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    if uaddr.is_null() {
        return Ok(());
    }

    // sockaddr_in{,6}: sin_port at offset 2 (big-endian). Address at offset 4
    // (v4) / offset 8 (v6).
    let port_be: u16 = unsafe { bpf_probe_read_kernel((uaddr as usize + 2) as *const u16) }?;
    let dport = u16::from_be(port_be);

    let mut daddr = [0u8; 16];
    match family {
        af::INET => {
            let a: [u8; 4] =
                unsafe { bpf_probe_read_kernel((uaddr as usize + 4) as *const [u8; 4]) }?;
            daddr[..4].copy_from_slice(&a);
        }
        _ => {
            let a: [u8; 16] =
                unsafe { bpf_probe_read_kernel((uaddr as usize + 8) as *const [u8; 16]) }?;
            daddr = a;
        }
    }

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    // SAFETY: as above.
    unsafe {
        fill_common(e, kind::CONNECT);
        (*e).daddr = daddr;
        (*e).dport = dport;
        (*e).af = family;
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Fill the fields common to every event and zero the rest.
///
/// SAFETY: `e` must point at a valid, writable `Event` slot.
unsafe fn fill_common(e: *mut Event, kind: u32) {
    (*e).kind = kind;
    (*e).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*e).uid = bpf_get_current_uid_gid() as u32;
    (*e).cgroup_id = bpf_get_current_cgroup_id();
    (*e)._pad = 0;
    (*e).daddr = [0u8; 16];
    (*e).dport = 0;
    (*e).af = 0;
    (*e)._pad2 = 0;
    (*e).aux = [0u8; AUX_LEN];
    match bpf_get_current_comm() {
        Ok(comm) => (*e).comm = comm,
        Err(_) => (*e).comm = [0u8; 16],
    }
    core::ptr::write_bytes((*e).filename.as_mut_ptr(), 0, FILENAME_LEN);
}

fn bump_drops() {
    if let Some(ptr) = DROPS.get_ptr_mut(0) {
        // SAFETY: single-slot counter; a lost increment is acceptable.
        unsafe { *ptr += 1 };
    }
}

/// GPL license, required for the tracepoint/kprobe + `bpf_probe_read` helpers.
#[no_mangle]
#[link_section = "license"]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable in verified BPF; present to satisfy the compiler.
    loop {}
}
