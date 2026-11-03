# YARA detection (`--rules`)

With `--ebpf --rules <file|dir>`, k3sec scans what the [probe](eBPF-Probe)
surfaces, with [yara-x](https://github.com/VirusTotal/yara-x):

- **exec**: the executed binary, through `/proc/<pid>/exe`, so even a binary
  deleted right after it started is scanned. The priority case. A process
  already gone (it ran for a millisecond) is scanned at its exec'd path
  through the root of a live process of its container: on the lab, 20 of 20
  execs of a marked binary detected.
- **file_write**: the file dropped under a sensitive path, debounced (500 ms of
  quiet) so a file being written is scanned once, settled.
- **memory**: after a suspicious exec (fileless, deleted binary, drift), once
  settled: the process's executable anonymous memory and everything a memfd or
  a deleted file backs, read through `/proc/<pid>/mem` up to
  `--max-scan-size`. Code unpacked or injected at runtime is in no file; on the
  lab, a marker built at runtime in an anonymous `rwx` mapping of a fileless
  process is matched "on the memory of pid N (6 regions)". Not done on every
  exec: JIT runtimes (Node.js, Java) map large anonymous code.

```bash
sudo k3sec watch --ebpf --rules ./rules/
sudo k3sec watch --ebpf --rules ./rules/ --max-scan-size 33554432 --scan-workers 4
```

A match is a `source: "yara"`, `kind: "detection"` event, always `critical`
(red in pretty), with the pod, the rule names, tags and the artifact path. See
[SecEvent schema](SecEvent-Schema#yara).

## Rules

`--rules` takes a `.yar` / `.yara` file or a directory (recursive). Rules are
compiled once at startup, **before** connecting to the cluster: an invalid
ruleset refuses to start with the compiler's message. The repo ships a starter
set in `rules/`:

| File | Rule |
|------|------|
| `reverse_shell.yar` | `reverse_shell_indicators`: `bash -i`, `/dev/tcp/`, `pty.spawn`, `nc -e`, `mkfifo /tmp/` |
| `meterpreter.yar` | `meterpreter_payload`: strings of Metasploit Meterpreter payloads |
| `cryptominer.yar` | `cryptominer_indicators`: `stratum+tcp://`, `stratum+ssl://`, or two of XMRig's options and algorithms (`--donate-level`, `RandomX`, `cryptonight`) |
| `packed_elf_dropper.yar` | `packed_elf_dropper`: UPX-packed ELF, common for dropped payloads |
| `k3sec_test_marker.yar` | `k3sec_test_marker`: the string `K3SEC_YARA_TEST`, to prove the exec / file scan pipeline end to end |

## Off the hot path

```text
probe ──ScanRequest──▶ dispatcher ──▶ [bounded queue] ──▶ worker threads ──▶ sink
```

The probe only enqueues a reference (pid, path, pod). Workers are OS threads
(scanning is CPU-bound), `--scan-workers` of them (default: CPU count).
Artifacts over `--max-scan-size` (default 32 MiB), vanished processes and read
errors are skipped and counted, never fatal. A file found clean is remembered
by its identity (device, inode, size, mtime) and not read again: 5000 execs of
one binary cost 0.6 s of CPU instead of 2.8 s on the lab. A changed file is
scanned again, and a file that matched is never remembered: every exec of it
is a detection.

`--rules` without `--ebpf` warns and does nothing (real output):

```text
2026-10-29T14:42:58.276860Z  WARN --rules has no effect without --ebpf; scanning is driven by eBPF events
```
