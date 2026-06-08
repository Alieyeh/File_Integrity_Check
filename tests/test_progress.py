from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from file_integrity_monitor.progress import ProgressUpdate, TerminalProgress


class TerminalProgressTests(unittest.TestCase):
    def test_renderer_shows_percentage_and_checked_file_count(self) -> None:
        stream = io.StringIO()
        progress = TerminalProgress(
            stream=stream,
            enabled=True,
            min_interval_s=0,
        )

        progress(
            ProgressUpdate(
                phase="Scanning",
                current=50,
                total=100,
                estimated=True,
                message="baseline estimate",
            )
        )
        progress.finish(100)

        output = stream.getvalue()
        self.assertIn("50.0%", output)
        self.assertIn("50 / ~100 files", output)
        self.assertIn("100.0%", output)
        self.assertIn("100 / 100 files", output)

    def test_renderer_can_report_unknown_first_baseline_total(self) -> None:
        stream = io.StringIO()
        progress = TerminalProgress(
            stream=stream,
            enabled=True,
            min_interval_s=0,
        )

        progress(ProgressUpdate(phase="Scanning", current=250, total=None))

        output = stream.getvalue()
        self.assertIn("--.-%", output)
        self.assertIn("250 files", output)


if __name__ == "__main__":
    unittest.main()
