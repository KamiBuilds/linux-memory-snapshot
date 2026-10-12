#!/bin/sh
set -eu

python3 -m unittest discover -s tests -v
python3 -m compileall -q linux_memory_snapshot.py tests
python3 linux_memory_snapshot.py \
  --proc-root examples/proc \
  --cgroup-root examples/cgroup
python3 linux_memory_snapshot.py \
  --proc-root examples/proc \
  --cgroup-root examples/cgroup \
  --json
python3 linux_memory_snapshot.py --help >/dev/null

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --check
  git diff --cached --check
fi
