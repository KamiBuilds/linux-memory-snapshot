#!/usr/bin/env python3
"""Read-only Linux host and cgroup memory snapshot."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


MAX_INPUT_BYTES = 65_536
MAX_COUNTER_TEXT = str((1 << 64) - 1)


class InputError(ValueError):
    """Raised when a Linux pseudo-file is missing or malformed."""


def classify_status(
    available_bytes: int,
    total_bytes: int,
    some_avg10: float,
    full_avg10: float,
    cgroup_current_bytes: int | None,
    cgroup_limit_bytes: int | None,
) -> tuple[str, list[str]]:
    """Classify a point-in-time snapshot using documented thresholds."""
    if available_bytes * 100 <= total_bytes * 5:
        return "critical", ["host available memory is at most 5%"]
    if cgroup_limit_bytes == 0:
        return "critical", ["cgroup memory limit is zero"]
    if (
        cgroup_current_bytes is not None
        and cgroup_limit_bytes is not None
        and cgroup_current_bytes * 100 >= cgroup_limit_bytes * 95
    ):
        return "critical", ["cgroup memory usage is at least 95%"]
    if available_bytes * 100 <= total_bytes * 15:
        return "warning", ["host available memory is at most 15%"]
    if full_avg10 >= 1:
        return "warning", ["full memory PSI avg10 is at least 1%"]
    if some_avg10 >= 10:
        return "warning", ["some memory PSI avg10 is at least 10%"]
    if (
        cgroup_current_bytes is not None
        and cgroup_limit_bytes is not None
        and cgroup_current_bytes * 100 >= cgroup_limit_bytes * 85
    ):
        return "warning", ["cgroup memory usage is at least 85%"]
    return "healthy", []


def _parse_nonnegative_integer(text: str, label: str) -> int:
    value = text.strip()
    if not value.isascii() or not value.isdigit():
        raise InputError(f"{label} is not a non-negative integer")
    normalized = value.lstrip("0") or "0"
    if len(normalized) > len(MAX_COUNTER_TEXT) or (
        len(normalized) == len(MAX_COUNTER_TEXT) and normalized > MAX_COUNTER_TEXT
    ):
        raise InputError(f"{label} is too large")
    try:
        return int(normalized)
    except ValueError as error:
        raise InputError(f"{label} is too large") from error


def parse_cgroup(
    current_text: str, max_text: str, events_text: str
) -> dict[str, object]:
    """Parse the key cgroup v2 memory controller files."""
    current = _parse_nonnegative_integer(current_text, "memory.current")
    maximum_raw = max_text.strip()
    maximum = None if maximum_raw == "max" else _parse_nonnegative_integer(
        maximum_raw, "memory.max"
    )

    events: dict[str, int] = {}
    for line in events_text.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in events:
            raise InputError("memory.events contains an invalid or duplicate row")
        events[fields[0]] = _parse_nonnegative_integer(fields[1], "memory event")
    required_events = {"low", "high", "max", "oom", "oom_kill"}
    if not required_events.issubset(events):
        raise InputError("memory.events is missing a required counter")

    usage_percent = None
    if maximum is not None and maximum > 0:
        usage_percent = round(current * 100 / maximum, 2)
    return {
        "current_bytes": current,
        "limit_bytes": maximum,
        "usage_percent": usage_percent,
        "events": events,
    }


def parse_pressure(text: str) -> dict[str, dict[str, int | float]]:
    """Parse /proc/pressure/memory metrics."""
    result: dict[str, dict[str, int | float]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        kind = fields[0]
        if kind not in {"some", "full"} or kind in result:
            raise InputError("pressure data has an invalid or duplicate row")
        raw_metrics: dict[str, str] = {}
        for field in fields[1:]:
            if "=" not in field:
                raise InputError("pressure data has a malformed metric")
            key, value = field.split("=", 1)
            if key in raw_metrics:
                raise InputError("pressure data has a duplicate metric")
            raw_metrics[key] = value
        if set(raw_metrics) != {"avg10", "avg60", "avg300", "total"}:
            raise InputError("pressure data is missing a required metric")
        try:
            metrics: dict[str, int | float] = {
                "avg10": float(raw_metrics["avg10"]),
                "avg60": float(raw_metrics["avg60"]),
                "avg300": float(raw_metrics["avg300"]),
            }
        except ValueError as error:
            raise InputError("pressure data contains a non-numeric metric") from error
        metrics["total_us"] = _parse_nonnegative_integer(
            raw_metrics["total"], "pressure total"
        )
        averages = (metrics["avg10"], metrics["avg60"], metrics["avg300"])
        if any(not 0 <= value <= 100 for value in averages) or metrics["total_us"] < 0:
            raise InputError("pressure data contains an out-of-range metric")
        result[kind] = metrics
    if set(result) != {"some", "full"}:
        raise InputError("pressure data is missing a required row")
    return result


def parse_meminfo(text: str) -> dict[str, int | float]:
    """Parse the required values from /proc/meminfo."""
    required = ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")
    values: dict[str, int] = {}
    seen: set[str] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        if key not in required:
            continue
        if key in seen:
            raise InputError(f"meminfo contains duplicate field: {key}")
        seen.add(key)
        fields = raw.split()
        if (
            len(fields) != 2
            or fields[1] != "kB"
            or not fields[0].isascii()
            or not fields[0].isdigit()
        ):
            raise InputError(f"meminfo contains malformed field: {key}")
        values[key] = _parse_nonnegative_integer(fields[0], key) * 1024

    if any(key not in values for key in required):
        raise InputError("meminfo is missing a required field")
    total = values["MemTotal"]
    available = values["MemAvailable"]
    swap_total = values["SwapTotal"]
    swap_free = values["SwapFree"]
    if total <= 0 or available > total or swap_free > swap_total:
        raise InputError("meminfo contains inconsistent values")
    return {
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": total - available,
        "available_percent": round(available * 100 / total, 2),
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap_total - swap_free,
    }


def _read_bounded(path: Path, label: str, *, missing_ok: bool = False) -> str | None:
    flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, flag_name, 0)
    try:
        descriptor = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise InputError(f"{label} is not a regular file")
            chunks = []
            remaining = MAX_INPUT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(descriptor)
    except FileNotFoundError as error:
        if missing_ok:
            return None
        raise InputError(f"cannot read {label}") from error
    except OSError as error:
        raise InputError(f"cannot read {label}") from error
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"{label} exceeds the 65536-byte input limit")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as error:
        raise InputError(f"{label} is not ASCII text") from error


def collect_snapshot(proc_root: Path, cgroup_root: Path) -> dict[str, object]:
    """Collect and classify one read-only memory snapshot."""
    host = parse_meminfo(_read_bounded(proc_root / "meminfo", "meminfo"))
    pressure = parse_pressure(
        _read_bounded(proc_root / "pressure" / "memory", "memory pressure")
    )
    cgroup_paths = [
        cgroup_root / "memory.current",
        cgroup_root / "memory.max",
        cgroup_root / "memory.events",
    ]
    cgroup_texts = [
        _read_bounded(path, path.name, missing_ok=True) for path in cgroup_paths
    ]
    if all(text is None for text in cgroup_texts):
        cgroup: dict[str, object] = {"available": False}
        cgroup_current = None
        cgroup_limit = None
    else:
        if any(text is None for text in cgroup_texts):
            raise InputError("cgroup memory controller files are incomplete")
        cgroup = parse_cgroup(
            cgroup_texts[0],
            cgroup_texts[1],
            cgroup_texts[2],
        )
        cgroup["available"] = True
        cgroup_current = int(cgroup["current_bytes"])
        raw_limit = cgroup["limit_bytes"]
        cgroup_limit = None if raw_limit is None else int(raw_limit)
    status, reasons = classify_status(
        available_bytes=int(host["available_bytes"]),
        total_bytes=int(host["total_bytes"]),
        some_avg10=float(pressure["some"]["avg10"]),
        full_avg10=float(pressure["full"]["avg10"]),
        cgroup_current_bytes=cgroup_current,
        cgroup_limit_bytes=cgroup_limit,
    )
    return {
        "status": status,
        "reasons": reasons,
        "host": host,
        "pressure": pressure,
        "cgroup": cgroup,
    }


def _escape_terminal(text: str) -> str:
    pieces = []
    for character in text:
        codepoint = ord(character)
        if codepoint < 32 or 127 <= codepoint <= 159:
            pieces.append(f"\\x{codepoint:02x}")
        else:
            pieces.append(character)
    return "".join(pieces)


def _format_bytes(value: int) -> str:
    amount = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    return f"{amount:.1f} {unit}"


def format_human(report: dict[str, object]) -> str:
    """Format a compact terminal-safe report."""
    host = report["host"]
    pressure = report["pressure"]
    cgroup = report["cgroup"]
    lines = [f"Status: {str(report['status']).upper()}"]
    for reason in report["reasons"]:
        lines.append(f"Reason: {reason}")
    if not cgroup["available"]:
        cgroup_lines = ["Cgroup v2 memory controller: unavailable"]
    elif cgroup["limit_bytes"] is None:
        cgroup_lines = [
            f"Cgroup usage: {_format_bytes(cgroup['current_bytes'])} / unlimited"
        ]
    elif cgroup["limit_bytes"] == 0:
        cgroup_lines = [
            f"Cgroup usage: {_format_bytes(cgroup['current_bytes'])} / "
            "0.0 B (percentage unavailable)"
        ]
    else:
        cgroup_lines = [
            f"Cgroup usage: {_format_bytes(cgroup['current_bytes'])} / "
            f"{_format_bytes(cgroup['limit_bytes'])} "
            f"({cgroup['usage_percent']:.2f}%)"
        ]
    if cgroup["available"]:
        events = cgroup["events"]
        cgroup_lines.append(
            "Cgroup events: "
            f"high={events['high']} max={events['max']} "
            f"oom={events['oom']} oom_kill={events['oom_kill']}"
        )
    lines.extend(
        [
            f"Host total: {_format_bytes(host['total_bytes'])}",
            "Host available: "
            f"{_format_bytes(host['available_bytes'])} "
            f"({host['available_percent']:.2f}%)",
            "Host swap used: "
            f"{_format_bytes(host['swap_used_bytes'])} / "
            f"{_format_bytes(host['swap_total_bytes'])}",
            "PSI avg10: "
            f"some {pressure['some']['avg10']:.2f}%, "
            f"full {pressure['full']['avg10']:.2f}%",
        ]
    )
    lines.extend(cgroup_lines)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="linux-memory-snapshot",
        description="Report Linux host, PSI, and cgroup v2 memory pressure.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--proc-root",
        type=Path,
        default=Path("/proc"),
        help="alternate procfs root (for offline fixtures)",
    )
    parser.add_argument(
        "--cgroup-root",
        type=Path,
        default=Path("/sys/fs/cgroup"),
        help="alternate cgroup v2 root (for offline fixtures)",
    )
    args = parser.parse_args(argv)
    try:
        report = collect_snapshot(args.proc_root, args.cgroup_root)
    except InputError as error:
        if args.json:
            json.dump(
                {"status": "input_error", "error": str(error)},
                sys.stdout,
                sort_keys=True,
            )
            sys.stdout.write("\n")
        else:
            sys.stderr.write(f"input error: {_escape_terminal(str(error))}\n")
        return 2
    if args.json:
        json.dump(report, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(format_human(report))
    return 0 if report["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
