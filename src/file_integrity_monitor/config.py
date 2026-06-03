from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


DEFAULT_EXCLUDED_DIR_NAMES = frozenset(
    {
        "System Volume Information",
        "$RECYCLE.BIN",
        "__pycache__",
        ".git",
        "node_modules",
        "Temp",
        "Archive",
        "Backups",
    }
)

DEFAULT_EXCLUDED_PATH_PREFIXES = (
    r"S:\Archive",
    r"S:\Backups",
    r"S:\OldProjects",
)


def _strip_optional_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def load_exclusions_file(path: Path) -> tuple[set[str], list[str]]:
    """Load non-technical exclusion entries from a plain text file.

    Supported lines:
      - DirectoryName
      - dir: DirectoryName
      - prefix: C:\\Full\\Subtree
      - path: C:\\Full\\Subtree

    Blank lines and lines beginning with # are ignored.
    """

    directory_names: set[str] = set()
    path_prefixes: list[str] = []
    if not path.exists():
        raise FileNotFoundError(
            f"Exclusions file does not exist: {path}. "
            "Create it from config/exclude_dirs.example.txt or omit --exclude-file."
        )
    if not path.is_file():
        raise ValueError(f"Exclusions path is not a file: {path}")

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            key, separator, value = line.partition(":")
            if separator and key.strip().lower() in {"dir", "directory"}:
                directory_name = _strip_optional_quotes(value)
                if directory_name:
                    directory_names.add(directory_name)
                continue

            if separator and key.strip().lower() in {"prefix", "path", "subtree"}:
                prefix = _strip_optional_quotes(value)
                if prefix:
                    path_prefixes.append(prefix)
                continue

            if separator and key.strip().lower() in {"dirs", "directories", "prefixes", "paths"}:
                raise ValueError(
                    f"{path}:{line_number}: use one exclusion per line, for example 'dir: Archive'."
                )

            directory_name = _strip_optional_quotes(line)
            if directory_name:
                directory_names.add(directory_name)

    return directory_names, path_prefixes


@dataclass(frozen=True)
class ExclusionConfig:
    """Directory pruning rules used while walking the tree."""

    dir_names: frozenset[str] = DEFAULT_EXCLUDED_DIR_NAMES
    path_prefixes: tuple[str, ...] = DEFAULT_EXCLUDED_PATH_PREFIXES
    exclude_dirs_starting_with_digit: bool = True

    @classmethod
    def from_cli(
        cls,
        *,
        clear_defaults: bool,
        exclude_dirs: Iterable[str] | None,
        exclude_prefixes: Iterable[str] | None,
        exclude_files: Iterable[Path] | None,
        include_numbered_dirs: bool,
    ) -> "ExclusionConfig":
        names = set() if clear_defaults else set(DEFAULT_EXCLUDED_DIR_NAMES)
        prefixes = [] if clear_defaults else list(DEFAULT_EXCLUDED_PATH_PREFIXES)

        for exclude_file in exclude_files or ():
            file_names, file_prefixes = load_exclusions_file(Path(exclude_file))
            names.update(file_names)
            prefixes.extend(file_prefixes)

        for name in exclude_dirs or ():
            if name:
                names.add(name)
        for prefix in exclude_prefixes or ():
            if prefix:
                prefixes.append(prefix)

        return cls(
            dir_names=frozenset(names),
            path_prefixes=tuple(prefixes),
            exclude_dirs_starting_with_digit=not include_numbered_dirs,
        )


@dataclass(frozen=True)
class ScanSettings:
    """Settings for one file integrity scan."""

    root: Path
    db: Path = Path("file_watch_state.sqlite3")
    outdir: Path = Path("reports")
    latest_json: Path | None = None
    algo: str = "sha256"
    sample_bytes: int = 1024 * 1024
    max_workers: int = 6
    hash_new_files: bool = True
    history_retention_per_path: int = 5
    exclusions: ExclusionConfig = field(default_factory=ExclusionConfig)


@dataclass(frozen=True)
class PipelineSettings:
    """Settings for one Python-only workflow run."""

    scan: ScanSettings
    archive_policy: str = "high"
    fail_on_high: bool = False
    write_root_alert_latest: bool = True
    json_detail: str = "compact"
