from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FileMeta:
    """Cheap metadata for one file."""

    path: str
    size: int
    mtime_utc: int


@dataclass(frozen=True)
class FileState:
    """Stored state for a path identity."""

    file_key: str
    path: str
    size: int
    mtime_utc: int
    fingerprint: str | None
    seen_count: int = 1
    file_id: str | None = None


@dataclass(frozen=True)
class DirectoryMeta:
    """Cheap metadata for one directory."""

    path: str
    mtime_utc: int
    child_files: int
    child_dirs: int


@dataclass(frozen=True)
class Event:
    """One integrity event detected during a scan."""

    type: str
    severity: str
    file_key: str
    path: str | None = None
    old_path: str | None = None
    new_path: str | None = None
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON representation used in reports."""

        return {
            "type": self.type,
            "severity": self.severity,
            "path": self.path,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "details": self.details or {},
        }
