from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from file_integrity_monitor.cli import main
from file_integrity_monitor.config import ExclusionConfig, PipelineSettings, ScanSettings
from file_integrity_monitor.pipeline import run_pipeline
from file_integrity_monitor.scheduling import next_weekly_run, parse_time_of_day, parse_weekday
from datetime import datetime, timezone


class PipelineAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tempdir.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.db = self.base / "state.sqlite3"
        self.outdir = self.base / "reports"
        self.latest = self.outdir / "latest.json"
        self.exclusions = ExclusionConfig(
            dir_names=frozenset(),
            path_prefixes=(),
            exclude_dirs_starting_with_digit=False,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _scan_settings(self) -> ScanSettings:
        return ScanSettings(
            root=self.root,
            db=self.db,
            outdir=self.outdir,
            latest_json=self.latest,
            max_workers=1,
            sample_bytes=4,
            hash_new_files=False,
            exclusions=self.exclusions,
        )

    def _write(self, relative: str, content: str, mtime: int) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        os.utime(path, (mtime, mtime))
        return path

    def test_pipeline_writes_status_when_no_high_events(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        result = run_pipeline(PipelineSettings(scan=self._scan_settings()))

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.payload["ok"])
        self.assertEqual(result.payload["stats"]["high"], 0)
        self.assertTrue((self.outdir / "STATUS_latest.txt").exists())
        self.assertTrue((self.outdir / "STATUS_latest.html").exists())
        self.assertTrue((self.outdir / "HUMAN_latest.html").exists())
        self.assertTrue((self.outdir / "human" / f"run_{result.payload['run_id']}.html").exists())
        self.assertTrue((self.outdir / "status" / f"STATUS_{result.payload['run_id']}.html").exists())
        for folder_name in ("events", "human", "status", "alerts", "archive", "errors"):
            self.assertTrue((self.outdir / folder_name).is_dir())
        self.assertTrue(self.latest.exists())
        latest_payload = json.loads(self.latest.read_text(encoding="utf-8"))
        self.assertEqual(latest_payload["json_detail"], "compact")
        self.assertNotIn("events", latest_payload)
        self.assertIn("events_sample", latest_payload)
        self.assertIn("No critical or high severity events", result.payload["ops_report"])
        html = (self.outdir / "STATUS_latest.html").read_text(encoding="utf-8")
        self.assertIn("Lay Summary", html)
        self.assertIn("Action Likelihood", html)
        self.assertIn("#f1e9ff", html)
        self.assertIn("#b83280", html)

    def test_pipeline_writes_alert_and_archive_for_high_events(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        run_pipeline(PipelineSettings(scan=self._scan_settings()))

        file_path.unlink()
        result = run_pipeline(PipelineSettings(scan=self._scan_settings()))

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.payload["stats"]["high"], 1)
        self.assertTrue((self.outdir / "alerts" / f"ALERT_{result.payload['run_id']}.txt").exists())
        self.assertTrue((self.outdir / "alerts" / f"ALERT_{result.payload['run_id']}.html").exists())
        self.assertTrue((self.outdir / "ALERT_latest.txt").exists())
        self.assertTrue((self.outdir / "ALERT_latest.html").exists())
        self.assertTrue(list((self.outdir / "archive").glob("run_*.json")))
        alert_html = (self.outdir / "ALERT_latest.html").read_text(encoding="utf-8")
        self.assertIn("High Risk", alert_html)
        self.assertIn("Likely deleted or currently unavailable", alert_html)

    def test_pipeline_treats_reversion_as_critical_alert(self) -> None:
        settings = ScanSettings(
            root=self.root,
            db=self.db,
            outdir=self.outdir,
            latest_json=self.latest,
            max_workers=1,
            sample_bytes=4,
            hash_new_files=True,
            exclusions=self.exclusions,
        )
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        run_pipeline(PipelineSettings(scan=settings))

        file_path.write_text("bravo", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        run_pipeline(PipelineSettings(scan=settings))

        file_path.write_text("alpha", encoding="utf-8")
        os.utime(file_path, (1_700_000_003, 1_700_000_003))
        result = run_pipeline(PipelineSettings(scan=settings, fail_on_high=True))

        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.payload["stats"]["critical"], 1)
        self.assertTrue((self.outdir / "ALERT_latest.html").exists())
        self.assertTrue(list((self.outdir / "archive").glob("run_*.json")))
        alert_html = (self.outdir / "ALERT_latest.html").read_text(encoding="utf-8")
        self.assertIn("Extremely High Risk", alert_html)
        self.assertIn("Version reversion detected", alert_html)

    def test_pipeline_removes_stale_opposite_latest_files(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        run_pipeline(PipelineSettings(scan=self._scan_settings()))

        file_path.unlink()
        run_pipeline(PipelineSettings(scan=self._scan_settings()))
        self.assertTrue((self.outdir / "ALERT_latest.html").exists())
        self.assertFalse((self.outdir / "STATUS_latest.html").exists())

        replacement = self._write("replacement.txt", "bravo", 1_700_000_002)
        replacement.unlink()
        clear_db = self.base / "clear.sqlite3"
        clear_latest = self.outdir / "clear_latest.json"
        clear_settings = ScanSettings(
            root=self.root,
            db=clear_db,
            outdir=self.outdir,
            latest_json=clear_latest,
            max_workers=1,
            hash_new_files=False,
            exclusions=self.exclusions,
        )
        run_pipeline(PipelineSettings(scan=clear_settings))
        self.assertTrue((self.outdir / "STATUS_latest.html").exists())
        self.assertFalse((self.outdir / "ALERT_latest.html").exists())

    def test_pipeline_writes_error_report_for_missing_root(self) -> None:
        missing_settings = ScanSettings(
            root=self.base / "does-not-exist",
            db=self.db,
            outdir=self.outdir,
            latest_json=self.latest,
            exclusions=self.exclusions,
        )

        result = run_pipeline(PipelineSettings(scan=missing_settings))

        self.assertEqual(result.exit_code, 2)
        self.assertFalse(result.payload["ok"])
        self.assertTrue(list((self.outdir / "errors").glob("error_*.txt")))
        self.assertTrue(list((self.outdir / "errors").glob("error_*.html")))
        self.assertTrue(self.latest.exists())

    def test_cli_scan_prints_json_summary(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "scan",
                    "--root",
                    str(self.root),
                    "--db",
                    str(self.db),
                    "--outdir",
                    str(self.outdir),
                    "--no-hash-new-files",
                    "--clear-default-exclusions",
                    "--include-numbered-dirs",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["stats"]["scanned_files"], 1)
        self.assertEqual(payload["stats"]["hashed_files"], 0)

    def test_cli_run_defaults_latest_json(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "run",
                    "--root",
                    str(self.root),
                    "--db",
                    str(self.db),
                    "--outdir",
                    str(self.outdir),
                    "--clear-default-exclusions",
                    "--include-numbered-dirs",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertTrue((self.outdir / "latest.json").exists())

    def test_cli_run_can_write_full_latest_json(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "run",
                    "--root",
                    str(self.root),
                    "--db",
                    str(self.db),
                    "--outdir",
                    str(self.outdir),
                    "--json-detail",
                    "full",
                    "--clear-default-exclusions",
                    "--include-numbered-dirs",
                ]
            )

        payload = json.loads(stdout.getvalue())
        latest_payload = json.loads((self.outdir / "latest.json").read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(latest_payload["json_detail"], "full")
        self.assertIn("events", latest_payload)

    def test_cli_uses_exclude_file(self) -> None:
        exclude_file = self.base / "exclude_dirs.txt"
        exclude_file.write_text("SkipMe\n", encoding="utf-8")
        self._write("SkipMe/sample.txt", "alpha", 1_700_000_001)
        self._write("KeepMe/sample.txt", "bravo", 1_700_000_001)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "scan",
                    "--root",
                    str(self.root),
                    "--db",
                    str(self.db),
                    "--outdir",
                    str(self.outdir),
                    "--exclude-file",
                    str(exclude_file),
                    "--clear-default-exclusions",
                    "--include-numbered-dirs",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["stats"]["scanned_files"], 1)

    def test_cli_missing_exclude_file_returns_clean_error(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "run",
                    "--root",
                    str(self.root),
                    "--db",
                    str(self.db),
                    "--outdir",
                    str(self.outdir),
                    "--exclude-file",
                    str(self.base / "missing.txt"),
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertFalse(payload["ok"])
        self.assertIn("Exclusions file does not exist", payload["error"])

    def test_weekly_scheduler_calculates_next_monday_morning(self) -> None:
        now = datetime(2026, 6, 3, 12, 0, tzinfo=timezone.utc)
        monday = parse_weekday("monday")
        nine_am = parse_time_of_day("09:00")

        next_run = next_weekly_run(now, weekday=monday, at_time=nine_am)

        self.assertEqual(next_run.isoformat(), "2026-06-08T09:00:00+00:00")

    def test_cli_weekly_dry_run_prints_next_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "weekly",
                    "--root",
                    str(self.root),
                    "--db",
                    str(self.db),
                    "--outdir",
                    str(self.outdir),
                    "--weekday",
                    "monday",
                    "--time",
                    "09:00",
                    "--dry-run",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertIn("next_run_local", payload)


if __name__ == "__main__":
    unittest.main()
