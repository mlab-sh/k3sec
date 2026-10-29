# Reachability: loaded, dormant, unknown

The point of k3sec's vulnerability view: a CVE in code that is mapped in a
running process is a different problem from a CVE in a file nobody executes.

| Tag | Meaning |
|-----|---------|
| `loaded` | At least one file of the package is mapped by a process of the container (binary or shared library), or was exec'd since k3sec started (`watch --vulns --ebpf`). Node components (k3s, containerd, kernel) are always loaded. |
| `dormant` | OS package with no file mapped or executed: on disk, not running. |
| `unknown` | Language dependency (lockfile, Go module). Not determinable from memory maps. |

Lab numbers: nginx 6 loaded / 143 dormant, httpd 8 / 118, Rocky 7 / 111,
redis 2 / 87.

## How it's computed

1. **Processes of the container.** Every PID on the host whose
   `/proc/<pid>/cgroup` names the container id (the innermost 64-hex segment, so
   it also works when k3s itself runs in a container, as in k3d or the lab).
2. **What they map.** `/proc/<pid>/maps`, file-backed entries, for every PID of
   every container of the image. The kernel prints these paths relative to the
   process's own root, so they are already the in-container paths. A library
   replaced on disk after it was loaded shows ` (deleted)`: it's still the code
   that runs, so it still counts.
3. **Who owns them.** A path → package index built from the package file lists
   (`dpkg info/*.list`, apk `F:`/`R:`, rpm `BASENAMES`/`DIRNAMES`).
4. **Any owned file mapped → loaded.** Everything else from the OS package
   manager → dormant.

On the lab, the redis container maps 6 distinct files and nginx (two
replicas, master + workers) 10.

## Paths: why it's not a string compare

Package lists and the kernel don't spell paths the same way. Typical cases:

| Package db says | Kernel maps | Why |
|-----------------|-------------|-----|
| `/lib/x86_64-linux-gnu/libc.so.6` | `/usr/lib/x86_64-linux-gnu/libc.so.6` | usrmerge: `/lib → usr/lib` |
| `/bin/sh` | `/usr/bin/dash` | `/bin → usr/bin`, `sh → dash` |
| `/lib64/ld-linux-x86-64.so.2` (symlink) | `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` | absolute symlink |

So the index keys every file as listed **and** with its directory resolved
inside the container root. A lookup that misses is retried on the fully
resolved path. Only the directory is resolved when indexing: resolving the last
component would attribute a symlink's *target* to the package that ships the
symlink.

Resolution is done **in userspace**, one component at a time, absolute
symlinks re-anchored at the container root. Letting the kernel follow them
through `/proc/<pid>/root/...` would resolve an absolute symlink against
k3sec's root, i.e. the host: `/etc/os-release -> /usr/lib/os-release` would
read the host's file, and a hostile `-> /etc/shadow` would read the host's
secrets. The container is untrusted input: nothing escapes its root, `..` stops
at it, and loops stop after 40 hops.

## Why language deps are `unknown`

An interpreter (Node, Python, Ruby, PHP) maps itself and its native extensions,
not your `lodash`: the JavaScript is read from disk and compiled in memory.
Maps can't tell which packages were `require`d. Go modules sit inside a static
binary: the binary is mapped, but whether a vulnerable function of a module is
reachable is another question. Both are reported `unknown`, never `dormant`.

## Limits

- **A snapshot**: a library `dlopen()`ed after the snapshot is missed until the
  next run (or the next exec, with `--ebpf`). A dedicated eBPF `mmap` hook is
  planned for a later milestone.
- **Package granularity**: a loaded `libssl3` makes all its CVEs "loaded", even
  in functions the app never calls.
- **Files no package owns** (binaries built from source into `/usr/local`) make
  nothing loaded. See [Known limits](Known-Limits).
