import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from linux_memory_snapshot import (
    InputError,
    classify_status,
    collect_snapshot,
    format_human,
    main,
    parse_cgroup,
    parse_meminfo,
    parse_pressure,
)


class ParseMeminfoTests(unittest.TestCase):
    def test_parses_required_values_and_converts_kibibytes(self):
        text = """MemTotal:       1000 kB
MemAvailable:    250 kB
SwapTotal:       400 kB
SwapFree:        100 kB
"""

        report = parse_meminfo(text)

        self.assertEqual(report["total_bytes"], 1_024_000)
        self.assertEqual(report["available_bytes"], 256_000)
        self.assertEqual(report["used_bytes"], 768_000)
        self.assertEqual(report["available_percent"], 25.0)
        self.assertEqual(report["swap_used_bytes"], 307_200)

    def test_rejects_duplicate_required_fields(self):
        text = """MemTotal:       1000 kB
MemTotal:        999 kB
MemAvailable:    250 kB
SwapTotal:       400 kB
SwapFree:        100 kB
"""

        with self.assertRaisesRegex(Exception, "duplicate"):
            parse_meminfo(text)

    def test_rejects_a_malformed_required_field_before_a_valid_duplicate(self):
        text = """MemTotal:       invalid kB
MemTotal:       1000 kB
MemAvailable:    250 kB
SwapTotal:       400 kB
SwapFree:        100 kB
"""

        with self.assertRaisesRegex(Exception, "malformed"):
            parse_meminfo(text)


class ParsePressureTests(unittest.TestCase):
    def test_parses_some_and_full_pressure_metrics(self):
        text = """some avg10=1.25 avg60=0.50 avg300=0.10 total=12345
full avg10=0.75 avg60=0.25 avg300=0.05 total=6789
"""

        report = parse_pressure(text)

        self.assertEqual(report["some"]["avg10"], 1.25)
        self.assertEqual(report["some"]["total_us"], 12_345)
        self.assertEqual(report["full"]["avg300"], 0.05)
        self.assertEqual(report["full"]["total_us"], 6_789)

    def test_rejects_a_total_over_the_python_integer_digit_limit(self):
        text = (
            f"some avg10=0 avg60=0 avg300=0 total={'9' * 5000}\n"
            "full avg10=0 avg60=0 avg300=0 total=0\n"
        )

        with self.assertRaisesRegex(Exception, "too large"):
            parse_pressure(text)


class ParseCgroupTests(unittest.TestCase):
    def test_reports_finite_limit_usage_and_events(self):
        report = parse_cgroup(
            current_text="850\n",
            max_text="1000\n",
            events_text="low 2\nhigh 3\nmax 4\noom 1\noom_kill 1\n",
        )

        self.assertEqual(report["current_bytes"], 850)
        self.assertEqual(report["limit_bytes"], 1000)
        self.assertEqual(report["usage_percent"], 85.0)
        self.assertEqual(report["events"]["oom_kill"], 1)

    def test_accepts_zero_memory_max_without_percentage(self):
        for current in (0, 850):
            with self.subTest(current=current):
                try:
                    report = parse_cgroup(
                        current_text=f"{current}\n",
                        max_text="0\n",
                        events_text="low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                    )
                except (InputError, ZeroDivisionError) as error:
                    self.fail(f"valid zero memory.max must be accepted: {error}")

                self.assertEqual(report["current_bytes"], current)
                self.assertEqual(report["limit_bytes"], 0)
                self.assertIsNone(report["usage_percent"])

    def test_reports_unlimited_memory_max_without_percentage(self):
        report = parse_cgroup(
            current_text="850\n",
            max_text="max\n",
            events_text="low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
        )

        self.assertIsNone(report["limit_bytes"])
        self.assertIsNone(report["usage_percent"])


class CollectSnapshotTests(unittest.TestCase):
    def test_classifies_collected_zero_limit_as_critical_without_percentage(self):
        for current in (0, 512):
            with self.subTest(current=current):
                with tempfile.TemporaryDirectory(dir=".") as directory:
                    cgroup_root = Path(directory)
                    (cgroup_root / "memory.current").write_text(
                        f"{current}\n", encoding="ascii"
                    )
                    (cgroup_root / "memory.max").write_text("0\n", encoding="ascii")
                    (cgroup_root / "memory.events").write_text(
                        "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                        encoding="ascii",
                    )

                    report = collect_snapshot(Path("examples/proc"), cgroup_root)

                self.assertEqual(report["status"], "critical")
                self.assertEqual(report["reasons"], ["cgroup memory limit is zero"])
                self.assertTrue(report["cgroup"]["available"])
                self.assertEqual(report["cgroup"]["current_bytes"], current)
                self.assertEqual(report["cgroup"]["limit_bytes"], 0)
                self.assertIsNone(report["cgroup"]["usage_percent"])

    def test_collects_host_pressure_and_cgroup_from_fixture_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc_root = root / "proc"
            cgroup_root = root / "cgroup"
            (proc_root / "pressure").mkdir(parents=True)
            cgroup_root.mkdir()
            (proc_root / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 500 kB\n"
                "SwapTotal: 0 kB\nSwapFree: 0 kB\n",
                encoding="ascii",
            )
            (proc_root / "pressure" / "memory").write_text(
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                encoding="ascii",
            )
            (cgroup_root / "memory.current").write_text("500\n", encoding="ascii")
            (cgroup_root / "memory.max").write_text("1000\n", encoding="ascii")
            (cgroup_root / "memory.events").write_text(
                "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                encoding="ascii",
            )

            report = collect_snapshot(proc_root, cgroup_root)

        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["host"]["available_percent"], 50.0)
        self.assertEqual(report["cgroup"]["usage_percent"], 50.0)

    def test_reports_cgroup_unavailable_when_all_controller_files_are_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc_root = root / "proc"
            cgroup_root = root / "cgroup"
            (proc_root / "pressure").mkdir(parents=True)
            cgroup_root.mkdir()
            (proc_root / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 500 kB\n"
                "SwapTotal: 0 kB\nSwapFree: 0 kB\n",
                encoding="ascii",
            )
            (proc_root / "pressure" / "memory").write_text(
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                encoding="ascii",
            )

            report = collect_snapshot(proc_root, cgroup_root)

        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["cgroup"], {"available": False})

    def test_cgroup_availability_does_not_use_pre_open_exists_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc_root = root / "proc"
            cgroup_root = root / "cgroup"
            (proc_root / "pressure").mkdir(parents=True)
            cgroup_root.mkdir()
            (proc_root / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 500 kB\n"
                "SwapTotal: 0 kB\nSwapFree: 0 kB\n",
                encoding="ascii",
            )
            (proc_root / "pressure" / "memory").write_text(
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                encoding="ascii",
            )

            with patch.object(Path, "exists", side_effect=AssertionError("racy exists")):
                report = collect_snapshot(proc_root, cgroup_root)

        self.assertEqual(report["cgroup"], {"available": False})

    def test_rejects_a_pseudo_file_over_the_input_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc_root = root / "proc"
            cgroup_root = root / "cgroup"
            (proc_root / "pressure").mkdir(parents=True)
            cgroup_root.mkdir()
            (proc_root / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 500 kB\n"
                "SwapTotal: 0 kB\nSwapFree: 0 kB\n" + "x" * 65_536,
                encoding="ascii",
            )
            (proc_root / "pressure" / "memory").write_text(
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                encoding="ascii",
            )

            with self.assertRaisesRegex(Exception, "input limit"):
                collect_snapshot(proc_root, cgroup_root)

    def test_classifies_threshold_neighbors_using_exact_ratios(self):
        cases = (
            (4_999, None, "critical"),
            (5_001, None, "warning"),
            (14_999, None, "warning"),
            (15_001, None, "healthy"),
            (50_000, 84_999, "healthy"),
            (50_000, 85_001, "warning"),
            (50_000, 94_999, "warning"),
            (50_000, 95_001, "critical"),
        )
        for available, cgroup_current, expected in cases:
            with self.subTest(available=available, cgroup_current=cgroup_current):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    proc_root = root / "proc"
                    cgroup_root = root / "cgroup"
                    (proc_root / "pressure").mkdir(parents=True)
                    cgroup_root.mkdir()
                    (proc_root / "meminfo").write_text(
                        f"MemTotal: 100000 kB\nMemAvailable: {available} kB\n"
                        "SwapTotal: 0 kB\nSwapFree: 0 kB\n",
                        encoding="ascii",
                    )
                    (proc_root / "pressure" / "memory").write_text(
                        "some avg10=0 avg60=0 avg300=0 total=0\n"
                        "full avg10=0 avg60=0 avg300=0 total=0\n",
                        encoding="ascii",
                    )
                    if cgroup_current is not None:
                        (cgroup_root / "memory.current").write_text(
                            f"{cgroup_current}\n", encoding="ascii"
                        )
                        (cgroup_root / "memory.max").write_text(
                            "100000\n", encoding="ascii"
                        )
                        (cgroup_root / "memory.events").write_text(
                            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                            encoding="ascii",
                        )

                    report = collect_snapshot(proc_root, cgroup_root)

                self.assertEqual(report["status"], expected)


class HumanFormatTests(unittest.TestCase):
    @staticmethod
    def _report():
        return {
            "status": "warning",
            "reasons": ["host available memory is at most 15%"],
            "host": {
                "total_bytes": 2_097_152,
                "available_bytes": 262_144,
                "used_bytes": 1_835_008,
                "available_percent": 12.5,
                "swap_total_bytes": 1_048_576,
                "swap_used_bytes": 524_288,
            },
            "pressure": {
                "some": {"avg10": 2.5, "avg60": 1.0, "avg300": 0.5, "total_us": 1},
                "full": {"avg10": 0.5, "avg60": 0.2, "avg300": 0.1, "total_us": 1},
            },
            "cgroup": {
                "available": True,
                "current_bytes": 524_288,
                "limit_bytes": 1_048_576,
                "usage_percent": 50.0,
                "events": {"low": 0, "high": 1, "max": 0, "oom": 0, "oom_kill": 0},
            },
        }

    def test_formats_key_host_pressure_and_cgroup_values(self):
        output = format_human(self._report())

        self.assertIn("Status: WARNING", output)
        self.assertIn("Host available: 256.0 KiB (12.50%)", output)
        self.assertIn("PSI avg10: some 2.50%, full 0.50%", output)
        self.assertIn("Cgroup usage: 512.0 KiB / 1.0 MiB (50.00%)", output)
        self.assertIn("Cgroup events: high=1 max=0 oom=0 oom_kill=0", output)

    def test_formats_an_unlimited_cgroup_without_a_percentage(self):
        report = self._report()
        report["cgroup"]["limit_bytes"] = None
        report["cgroup"]["usage_percent"] = None

        output = format_human(report)

        self.assertIn("Cgroup usage: 512.0 KiB / unlimited", output)

    def test_formats_an_unavailable_cgroup_honestly(self):
        report = self._report()
        report["cgroup"] = {"available": False}

        output = format_human(report)

        self.assertIn("Cgroup v2 memory controller: unavailable", output)


class ReadmeTests(unittest.TestCase):
    def test_documents_zero_limit_status_and_unavailable_percentage(self):
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("`memory.max=0` is valid", readme)
        self.assertIn("critical even when current usage is zero", readme)
        self.assertIn("`limit_bytes: 0` and `usage_percent: null`", readme)
        self.assertIn("`0.0 B (percentage unavailable)`", readme)

    def test_documents_explicit_cgroup_directory_scope(self):
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertNotIn("this process's cgroup", readme)
        self.assertIn("default is `/sys/fs/cgroup`", readme)
        self.assertIn("directly from the selected directory", readme)
        self.assertIn("does not autodiscover", readme)
        self.assertIn("does not compute effective ancestor limits", readme)
        self.assertIn('--cgroup-root "$CGROUP_DIR"', readme)
        self.assertIn("visible in your current cgroup namespace", readme)


class CheckScriptTests(unittest.TestCase):
    def test_checks_both_worktree_and_staged_diffs(self):
        script = Path("scripts/check.sh").read_text(encoding="ascii")

        self.assertIn("git diff --check", script)
        self.assertIn("git diff --cached --check", script)


class CliTests(unittest.TestCase):
    @staticmethod
    def _make_fixture(directory):
        root = Path(directory)
        proc_root = root / "proc"
        cgroup_root = root / "cgroup"
        (proc_root / "pressure").mkdir(parents=True)
        cgroup_root.mkdir()
        (proc_root / "meminfo").write_text(
            "MemTotal: 1000 kB\nMemAvailable: 500 kB\n"
            "SwapTotal: 0 kB\nSwapFree: 0 kB\n",
            encoding="ascii",
        )
        (proc_root / "pressure" / "memory").write_text(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
            "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
            encoding="ascii",
        )
        return proc_root, cgroup_root

    def test_zero_limit_cli_reports_critical_without_percentage(self):
        for current in (0, 512):
            for json_mode in (False, True):
                with self.subTest(current=current, json_mode=json_mode):
                    with tempfile.TemporaryDirectory(dir=".") as directory:
                        proc_root, cgroup_root = self._make_fixture(directory)
                        (cgroup_root / "memory.current").write_text(
                            f"{current}\n", encoding="ascii"
                        )
                        (cgroup_root / "memory.max").write_text(
                            "0\n", encoding="ascii"
                        )
                        (cgroup_root / "memory.events").write_text(
                            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                            encoding="ascii",
                        )
                        command = [
                            sys.executable,
                            "linux_memory_snapshot.py",
                            "--proc-root",
                            str(proc_root),
                            "--cgroup-root",
                            str(cgroup_root),
                        ]
                        if json_mode:
                            command.append("--json")
                        result = subprocess.run(
                            command, check=False, capture_output=True, text=True
                        )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stderr, "", result.stderr)
                    if json_mode:
                        report = json.loads(result.stdout)
                        self.assertEqual(report["status"], "critical")
                        self.assertEqual(
                            report["reasons"], ["cgroup memory limit is zero"]
                        )
                        self.assertEqual(report["cgroup"]["limit_bytes"], 0)
                        self.assertEqual(report["cgroup"]["current_bytes"], current)
                        self.assertIsNone(report["cgroup"]["usage_percent"])
                    else:
                        self.assertIn("Status: CRITICAL", result.stdout)
                        self.assertIn(
                            "Reason: cgroup memory limit is zero", result.stdout
                        )
                        cgroup_line = next(
                            line for line in result.stdout.splitlines()
                            if line.startswith("Cgroup usage:")
                        )
                        self.assertEqual(
                            cgroup_line,
                            f"Cgroup usage: {current:.1f} B / 0.0 B "
                            "(percentage unavailable)",
                        )

    def test_json_mode_emits_snapshot_and_success_status(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root, cgroup_root = self._make_fixture(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    "linux_memory_snapshot.py",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "healthy")
        self.assertEqual(result.stderr, "")

    def test_human_mode_prints_the_report(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root, cgroup_root = self._make_fixture(directory)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "--proc-root",
                        str(proc_root),
                        "--cgroup-root",
                        str(cgroup_root),
                    ]
                )

        self.assertEqual(status, 0)
        self.assertIn("Status: HEALTHY", output.getvalue())
        self.assertIn("Cgroup v2 memory controller: unavailable", output.getvalue())

    def test_json_mode_returns_two_for_invalid_input_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root, cgroup_root = self._make_fixture(directory)
            (proc_root / "meminfo").write_text("broken\n", encoding="ascii")
            result = subprocess.run(
                [
                    sys.executable,
                    "linux_memory_snapshot.py",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "input_error")
        self.assertEqual(result.stderr, "")

    def test_digit_limit_number_returns_two_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root, cgroup_root = self._make_fixture(directory)
            (proc_root / "meminfo").write_text(
                f"MemTotal: {'9' * 5000} kB\n"
                "MemAvailable: 1 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
                encoding="ascii",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "linux_memory_snapshot.py",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "input_error")
        self.assertEqual(result.stderr, "")

    def test_float_overflow_sized_cgroup_value_returns_two(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root, cgroup_root = self._make_fixture(directory)
            (cgroup_root / "memory.current").write_text(
                "9" * 4000 + "\n", encoding="ascii"
            )
            (cgroup_root / "memory.max").write_text("1\n", encoding="ascii")
            (cgroup_root / "memory.events").write_text(
                "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", encoding="ascii"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "linux_memory_snapshot.py",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "input_error")
        self.assertEqual(result.stderr, "")

    def test_fifo_input_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root, cgroup_root = self._make_fixture(directory)
            (proc_root / "meminfo").unlink()
            os.mkfifo(proc_root / "meminfo")

            result = subprocess.run(
                [
                    sys.executable,
                    "linux_memory_snapshot.py",
                    "--proc-root",
                    str(proc_root),
                    "--cgroup-root",
                    str(cgroup_root),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "input_error")
        self.assertEqual(result.stderr, "")

    def test_human_input_errors_escape_terminal_controls(self):
        output = io.StringIO()
        with patch(
            "linux_memory_snapshot.collect_snapshot",
            side_effect=InputError("Bad\x1b"),
        ), contextlib.redirect_stderr(output):
            status = main([])

        self.assertEqual(status, 2)
        self.assertIn("Bad\\x1b", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())


class StatusTests(unittest.TestCase):
    def test_warns_when_cgroup_usage_reaches_eighty_five_percent(self):
        status, reasons = classify_status(
            available_bytes=50,
            total_bytes=100,
            some_avg10=0.0,
            full_avg10=0.0,
            cgroup_current_bytes=85,
            cgroup_limit_bytes=100,
        )

        self.assertEqual(status, "warning")
        self.assertEqual(reasons, ["cgroup memory usage is at least 85%"])

    def test_marks_five_percent_host_availability_critical(self):
        status, reasons = classify_status(
            available_bytes=5,
            total_bytes=100,
            some_avg10=0.0,
            full_avg10=0.0,
            cgroup_current_bytes=None,
            cgroup_limit_bytes=None,
        )

        self.assertEqual(status, "critical")
        self.assertEqual(reasons, ["host available memory is at most 5%"])

    def test_marks_ninety_five_percent_cgroup_usage_critical(self):
        status, reasons = classify_status(
            available_bytes=50,
            total_bytes=100,
            some_avg10=0.0,
            full_avg10=0.0,
            cgroup_current_bytes=95,
            cgroup_limit_bytes=100,
        )

        self.assertEqual(status, "critical")
        self.assertEqual(reasons, ["cgroup memory usage is at least 95%"])

    def test_warns_when_host_availability_reaches_fifteen_percent(self):
        status, reasons = classify_status(
            available_bytes=15,
            total_bytes=100,
            some_avg10=0.0,
            full_avg10=0.0,
            cgroup_current_bytes=None,
            cgroup_limit_bytes=None,
        )

        self.assertEqual(status, "warning")
        self.assertEqual(reasons, ["host available memory is at most 15%"])

    def test_warns_when_full_psi_avg10_reaches_one_percent(self):
        status, reasons = classify_status(
            available_bytes=50,
            total_bytes=100,
            some_avg10=0.0,
            full_avg10=1.0,
            cgroup_current_bytes=None,
            cgroup_limit_bytes=None,
        )

        self.assertEqual(status, "warning")
        self.assertEqual(reasons, ["full memory PSI avg10 is at least 1%"])

    def test_warns_when_some_psi_avg10_reaches_ten_percent(self):
        status, reasons = classify_status(
            available_bytes=50,
            total_bytes=100,
            some_avg10=10.0,
            full_avg10=0.0,
            cgroup_current_bytes=None,
            cgroup_limit_bytes=None,
        )

        self.assertEqual(status, "warning")
        self.assertEqual(reasons, ["some memory PSI avg10 is at least 10%"])


if __name__ == "__main__":
    unittest.main()
