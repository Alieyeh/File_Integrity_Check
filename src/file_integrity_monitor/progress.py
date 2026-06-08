from __future__ import annotations

import shutil
import sys
import time
from dataclasses import dataclass
from typing import Callable, TextIO


@dataclass(frozen=True)
class ProgressUpdate:
    """One scanner progress observation suitable for terminal or API consumers."""

    phase: str
    current: int
    total: int | None = None
    unit: str = "files"
    estimated: bool = False
    message: str = ""


ProgressCallback = Callable[[ProgressUpdate], None]


class TerminalProgress:
    """Render throttled, single-line progress updates without affecting stdout."""

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        enabled: bool | None = None,
        min_interval_s: float = 0.1,
    ) -> None:
        self.stream = stream or sys.stderr
        self.enabled = self.stream.isatty() if enabled is None else enabled
        self.min_interval_s = max(0.0, min_interval_s)
        self._last_rendered_at = 0.0
        self._last_phase = ""
        self._last_width = 0
        self._finished = False

    def __call__(self, update: ProgressUpdate) -> None:
        """Render an update when enough time has passed or its phase changed."""

        if not self.enabled or self._finished:
            return

        now = time.monotonic()
        phase_changed = update.phase != self._last_phase
        complete = update.total is not None and update.current >= update.total
        if (
            not phase_changed
            and not complete
            and now - self._last_rendered_at < self.min_interval_s
        ):
            return

        line = self._format_line(update)
        padding = " " * max(0, self._last_width - len(line))
        self.stream.write(f"\r{line}{padding}")
        self.stream.flush()
        self._last_width = len(line)
        self._last_phase = update.phase
        self._last_rendered_at = now

    def finish(self, checked_files: int) -> None:
        """Render a final exact count and terminate the progress line."""

        if not self.enabled or self._finished:
            return
        self(
            ProgressUpdate(
                phase="Complete",
                current=checked_files,
                total=checked_files,
                message="run finished",
            )
        )
        self.stream.write("\n")
        self.stream.flush()
        self._finished = True

    def fail(self, message: str) -> None:
        """Terminate the progress line with a concise failure indicator."""

        if not self.enabled or self._finished:
            return
        text = f"FAILED: {message}"
        padding = " " * max(0, self._last_width - len(text))
        self.stream.write(f"\r{text}{padding}\n")
        self.stream.flush()
        self._finished = True

    def _format_line(self, update: ProgressUpdate) -> str:
        terminal_width = shutil.get_terminal_size(fallback=(100, 24)).columns
        bar_width = max(12, min(28, terminal_width // 5))
        total = update.total

        if total is None:
            percentage = " --.-%"
            bar = "." * bar_width
            count = f"{update.current:,} {update.unit}"
        elif total == 0:
            percentage = " 100.0%"
            bar = "#" * bar_width
            count = f"0 / 0 {update.unit}"
        else:
            raw_ratio = update.current / total
            ratio = min(1.0, max(0.0, raw_ratio))
            if update.estimated and update.current >= total:
                ratio = 0.999
            filled = min(bar_width, int(ratio * bar_width))
            bar = "#" * filled + "-" * (bar_width - filled)
            percentage_value = min(99.9, raw_ratio * 100) if update.estimated else ratio * 100
            percentage = f"{percentage_value:6.1f}%"
            estimate = "~" if update.estimated else ""
            count = f"{update.current:,} / {estimate}{total:,} {update.unit}"

        message = f" | {update.message}" if update.message else ""
        line = f"{update.phase:<11} [{bar}] {percentage} | {count}{message}"
        return line[: max(40, terminal_width - 1)]
