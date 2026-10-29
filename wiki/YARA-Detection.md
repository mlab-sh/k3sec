# YARA detection (`--rules`)

With `--ebpf --rules <file|dir>`, k3sec scans what the [probe](eBPF-Probe)
surfaces, with [yara-x](https://github.com/VirusTotal/yara-x):

- **exec**: the executed binary, through `/proc/<pid>/exe`, so even a binary
  deleted right after it started is scanned. The priority case.
- **file_write**: the file dropped under a sensitive path, debounced (500 ms of
  quiet) so a file being written is scanned once, settled.

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
| `packed_elf_dropper.yar` | `packed_elf_dropper`: UPX-packed ELF, common for dropped payloads |
| `k3sec_test_marker.yar` | `k3sec_test_marker`: the string `K3SEC_YARA_TEST`, to prove the exec / file scan pipeline end to end |

## Off the hot path

```text
probe ──ScanRequest──▶ dispatcher ──▶ [bounded queue] ──▶ worker threads ──▶ sink
```

The probe only enqueues a reference (pid, path, pod). Workers are OS threads
(scanning is CPU-bound), `--scan-workers` of them (default: CPU count).
Artifacts over `--max-scan-size` (default 32 MiB), vanished processes and read
errors are skipped and counted, never fatal.

`--rules` without `--ebpf` warns and does nothing (real output):

```text
2026-10-29T14:42:58.276860Z  WARN --rules has no effect without --ebpf; scanning is driven by eBPF events
```
