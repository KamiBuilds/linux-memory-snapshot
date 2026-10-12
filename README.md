# Linux Memory Snapshot

A dependency-free, read-only CLI that combines Linux host memory, Pressure Stall Information (PSI), and cgroup v2 memory data into one human or JSON snapshot.

It answers three different questions without calling `free`, `systemd`, `docker`, or a network service:

- How much host memory and swap are available?
- Is the kernel reporting recent memory stalls?
- Is the selected cgroup directory close to its own configured memory limit, and have memory events occurred there?

The command never changes limits, kills processes, contacts a server, or writes to procfs/cgroupfs.

## Quick start

```bash
git clone https://github.com/KamiBuilds/linux-memory-snapshot.git
cd linux-memory-snapshot
python3 linux_memory_snapshot.py
```

JSON output:

```bash
python3 linux_memory_snapshot.py --json
```

Run against the included offline fixture instead of the live kernel files:

```bash
python3 linux_memory_snapshot.py \
  --proc-root examples/proc \
  --cgroup-root examples/cgroup
```

## Requirements

- Linux with readable `/proc/meminfo` and `/proc/pressure/memory`.
- Python 3.10 or newer; no third-party packages.
- cgroup v2 is optional. If all three expected memory-controller files are absent, the report says the controller is unavailable. A partial set is treated as invalid input rather than silently ignored.
- No root privileges are normally required; container or host policy may restrict the pseudo-files.

## Output and exit statuses

The human report includes host totals, swap use, PSI `avg10`, cgroup usage, and selected cumulative `memory.events` counters. JSON includes the complete parsed `avg10`, `avg60`, `avg300`, totals, and event map.

Status thresholds are intentionally simple point-in-time signals, not a capacity forecast:

| Status | Trigger |
|---|---|
| `critical` | Host available memory is at most 5%, cgroup limit is zero, or positive finite cgroup usage is at least 95% |
| `warning` | Host available memory is at most 15%, PSI `full avg10` is at least 1%, PSI `some avg10` is at least 10%, or finite cgroup usage is at least 85% |
| `healthy` | None of the above |

When several thresholds apply, the highest-priority reason is reported. Cgroup event counters are cumulative since cgroup creation and do not by themselves change the current status.

`memory.max=0` is valid and is classified as critical even when current usage is zero. JSON reports `limit_bytes: 0` and `usage_percent: null`; the human report displays `0.0 B (percentage unavailable)` for the limit. No usage percentage is defined for a zero limit. An unlimited `memory.max` (`max`) instead reports a null limit and percentage and does not itself trigger cgroup thresholds.

| Exit | Meaning |
|---:|---|
| `0` | Snapshot status is `healthy` |
| `1` | Snapshot status is `warning` or `critical` |
| `2` | Required input is missing, incomplete, oversized, or malformed |

Every pseudo-file read is limited to 65,536 bytes. Human-readable input errors escape terminal control characters. JSON strings use the standard JSON encoder.

## Command reference

```text
usage: linux-memory-snapshot [-h] [--json] [--proc-root PROC_ROOT]
                             [--cgroup-root CGROUP_ROOT]
```

- `--json`: emit deterministic JSON rather than the human report.
- `--proc-root`: use another procfs-shaped directory, useful for offline fixtures and tests.
- `--cgroup-root`: select the directory containing `memory.current`, `memory.max`, and `memory.events`; the default is `/sys/fs/cgroup`, the conventional cgroup v2 mount root as visible to the command.

The alternate roots are read-only inputs; the tool never creates or changes files beneath them.

Cgroup values are read directly from the selected directory. The tool does not autodiscover the current process's cgroup and does not compute effective ancestor limits. The default mount root may have no memory controller files or may describe a broader group than the process; its result is not a claim about the process's effective memory limit. A selected subgroup's `memory.max` is only that directory's configured limit, not necessarily the tightest limit enforced by its ancestors.

To inspect a chosen subgroup, set `CGROUP_DIR` to its directory visible in your current cgroup namespace, then run:

```bash
python3 linux_memory_snapshot.py --cgroup-root "$CGROUP_DIR"
```

Choose the directory using your environment's cgroup mount and namespace information; host paths and paths inside containers need not match. The command does not translate between them. The included `examples/cgroup` directory is a portable offline example of this explicit selection.

## Test and quality checks

Run everything documented for contributors:

```bash
./scripts/check.sh
```

Equivalent commands:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q linux_memory_snapshot.py tests
python3 linux_memory_snapshot.py --proc-root examples/proc --cgroup-root examples/cgroup
python3 linux_memory_snapshot.py --proc-root examples/proc --cgroup-root examples/cgroup --json
python3 linux_memory_snapshot.py --help
git diff --check
git diff --cached --check
```

The test suite covers parsing, malformed and oversized inputs, cgroup limits, unavailable controllers, thresholds, human and JSON output, exit statuses, and terminal-control escaping.

## Install, update, and cleanup

No installation step is required after cloning. Optionally make the script executable and link it into a directory already on your `PATH`:

```bash
chmod +x linux_memory_snapshot.py
ln -s "$PWD/linux_memory_snapshot.py" "$HOME/.local/bin/linux-memory-snapshot"
```

Update the clone:

```bash
git pull --ff-only
```

Remove the optional link:

```bash
rm "$HOME/.local/bin/linux-memory-snapshot"
```

To uninstall completely, leave the repository and delete only the clone you created:

```bash
cd ..
rm -rf linux-memory-snapshot
```

## Platform support

| Platform | Status |
|---|---|
| Linux 6.17.4-2-pve x86_64, Python 3.11.16 | Live-tested |
| Other x86_64 Linux systems with Python 3.10+ and PSI enabled | Designed, not verified in this release |
| ARM64 Linux systems with Python 3.10+ and PSI enabled | Designed, not verified in this release |
| macOS and Windows | Unsupported because procfs, PSI, and cgroup v2 are Linux interfaces |

## License

MIT. See [LICENSE](LICENSE).
