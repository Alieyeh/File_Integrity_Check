from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .config import ExclusionConfig, ScanSettings
from .models import DirectoryMeta, Event, FileMeta, FileState
from .progress import ProgressCallback, ProgressUpdate


class ScanError(RuntimeError):
    """Operational scan failure that should be reported to an operator."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at_utc TEXT NOT NULL,
    root TEXT NOT NULL,
    scanned_count INTEGER NOT NULL,
    duration_s REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS latest_by_path (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime_utc INTEGER NOT NULL,
    fingerprint TEXT,
    last_seen_run_id TEXT NOT NULL,
    first_seen_run_id TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS latest_directories (
    path TEXT PRIMARY KEY,
    mtime_utc INTEGER NOT NULL,
    child_files INTEGER NOT NULL,
    child_dirs INTEGER NOT NULL,
    last_seen_run_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS directory_history_by_path (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    mtime_utc INTEGER NOT NULL,
    child_files INTEGER NOT NULL,
    child_dirs INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    first_seen_run_id TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS history_by_path (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    mtime_utc INTEGER NOT NULL,
    size INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    first_seen_run_id TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS metadata_history_by_path (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_utc INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    first_seen_run_id TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_hist_path_fp ON history_by_path(path, fingerprint);
CREATE INDEX IF NOT EXISTS idx_hist_path_id ON history_by_path(path, id);
CREATE INDEX IF NOT EXISTS idx_dir_hist_path_signature ON directory_history_by_path(path, mtime_utc, child_files, child_dirs);
CREATE INDEX IF NOT EXISTS idx_dir_hist_path_shape ON directory_history_by_path(path, child_files, child_dirs);
CREATE INDEX IF NOT EXISTS idx_dir_hist_path_id ON directory_history_by_path(path, id);
CREATE INDEX IF NOT EXISTS idx_meta_hist_path_signature ON metadata_history_by_path(path, size, mtime_utc);
CREATE INDEX IF NOT EXISTS idx_meta_hist_path_size ON metadata_history_by_path(path, size);
CREATE INDEX IF NOT EXISTS idx_meta_hist_path_id ON metadata_history_by_path(path, id);
"""


def utc_now_iso() -> str:
    """Return the current UTC time in a stable, second-precision ISO format."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_run_id(now: datetime | None = None) -> str:
    """Create a sortable, collision-resistant identifier for one scan run."""

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    return current.strftime("%Y%m%dT%H%M%S%f%z")


def normalize_path(path: os.PathLike[str] | str) -> str:
    """Return the platform-normalized absolute form used as a database key."""

    return os.path.normcase(os.path.abspath(os.fspath(path)))


def normalize_prefix(path: os.PathLike[str] | str) -> str:
    """Normalize an exclusion prefix without a trailing path separator."""

    return normalize_path(path).rstrip("\\/")


def _normalise_prefixes(prefixes: Iterable[str]) -> tuple[str, ...]:
    return tuple(normalize_prefix(prefix) for prefix in prefixes)


def should_exclude_dir(
    dir_name: str,
    full_dir_path: str,
    exclusions: ExclusionConfig,
    normalized_prefixes: tuple[str, ...] | None = None,
) -> bool:
    """Return whether a directory should be pruned before traversal."""

    if (
        exclusions.exclude_dirs_starting_with_digit
        and dir_name
        and dir_name[0].isdigit()
    ):
        return True

    if dir_name in exclusions.dir_names:
        return True

    prefixes = (
        normalized_prefixes
        if normalized_prefixes is not None
        else _normalise_prefixes(exclusions.path_prefixes)
    )
    norm_full = normalize_prefix(full_dir_path)
    for prefix in prefixes:
        if norm_full == prefix or norm_full.startswith(prefix + os.sep):
            return True
    return False


def iter_files_scandir(root: os.PathLike[str] | str, exclusions: ExclusionConfig) -> Iterable[FileMeta]:
    """Yield file metadata under root while pruning excluded directories early."""

    stack = [os.fspath(root)]
    normalized_prefixes = _normalise_prefixes(exclusions.path_prefixes)

    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not should_exclude_dir(
                                entry.name,
                                entry.path,
                                exclusions,
                                normalized_prefixes,
                            ):
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            stat = entry.stat(follow_symlinks=False)
                            yield FileMeta(
                                path=normalize_path(entry.path),
                                size=int(stat.st_size),
                                mtime_utc=int(stat.st_mtime),
                            )
                    except OSError as exc:
                        raise ScanError(
                            f"Cannot inspect filesystem entry {entry.path!r}: {exc}"
                        ) from exc
        except OSError as exc:
            raise ScanError(f"Cannot list directory {current_dir!r}: {exc}") from exc


def collect_tree_scandir(
    root: os.PathLike[str] | str,
    exclusions: ExclusionConfig,
    *,
    progress_callback: ProgressCallback | None = None,
    estimated_file_total: int | None = None,
) -> tuple[dict[str, FileMeta], dict[str, DirectoryMeta]]:
    """Collect metadata in one traversal and fail if any entry is unreadable."""

    root_path = os.fspath(root)
    stack = [root_path]
    normalized_root = normalize_path(root_path)
    normalized_prefixes = _normalise_prefixes(exclusions.path_prefixes)
    files: dict[str, FileMeta] = {}
    directories: dict[str, DirectoryMeta] = {}
    issues: list[str] = []
    progress_interval = 250

    while stack:
        current_dir = stack.pop()
        child_files = 0
        child_dirs = 0
        try:
            stat = os.stat(current_dir)
            current_norm = normalize_path(current_dir)
            if current_norm != normalized_root:
                directories[current_norm] = DirectoryMeta(
                    path=current_norm,
                    mtime_utc=int(stat.st_mtime),
                    child_files=0,
                    child_dirs=0,
                )
        except OSError as exc:
            issues.append(f"cannot read directory metadata for {current_dir!r}: {exc}")
            continue

        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if should_exclude_dir(
                                entry.name,
                                entry.path,
                                exclusions,
                                normalized_prefixes,
                            ):
                                continue
                            child_dirs += 1
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            stat = entry.stat(follow_symlinks=False)
                            file_meta = FileMeta(
                                path=normalize_path(entry.path),
                                size=int(stat.st_size),
                                mtime_utc=int(stat.st_mtime),
                            )
                            files[file_meta.path] = file_meta
                            child_files += 1
                            if progress_callback and (
                                len(files) == 1 or len(files) % progress_interval == 0
                            ):
                                progress_callback(
                                    ProgressUpdate(
                                        phase="Scanning",
                                        current=len(files),
                                        total=estimated_file_total,
                                        estimated=estimated_file_total is not None,
                                        message=f"{len(directories):,} directories found",
                                    )
                                )
                    except OSError as exc:
                        issues.append(f"cannot inspect filesystem entry {entry.path!r}: {exc}")
                        continue
        except OSError as exc:
            issues.append(f"cannot list directory {current_dir!r}: {exc}")
            continue

        current_norm = normalize_path(current_dir)
        if current_norm in directories:
            previous = directories[current_norm]
            directories[current_norm] = DirectoryMeta(
                path=previous.path,
                mtime_utc=previous.mtime_utc,
                child_files=child_files,
                child_dirs=child_dirs,
            )

    if issues:
        preview = "; ".join(issues[:3])
        remaining = len(issues) - min(len(issues), 3)
        suffix = f"; plus {remaining} more issue(s)" if remaining else ""
        raise ScanError(
            "Filesystem scan was incomplete, so the baseline was not updated. "
            f"Encountered {len(issues)} inaccessible or changed entry/entries: "
            f"{preview}{suffix}"
        )

    if progress_callback:
        progress_callback(
            ProgressUpdate(
                phase="Scanning",
                current=len(files),
                total=len(files),
                message=f"{len(directories):,} directories found",
            )
        )
    return files, directories


def compute_fingerprint(
    path: os.PathLike[str] | str,
    size: int,
    *,
    algo: str = "sha256",
    sample_bytes: int = 1024 * 1024,
) -> str:
    """Compute a full or sampled content fingerprint for one file."""

    hasher = hashlib.new(algo)
    hasher.update(str(size).encode("utf-8"))
    with open(path, "rb") as handle:
        if size <= 2 * sample_bytes:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
        else:
            hasher.update(handle.read(sample_bytes))
            handle.seek(max(0, size - sample_bytes))
            hasher.update(handle.read(sample_bytes))
    return hasher.hexdigest()


def open_db(db_path: Path) -> sqlite3.Connection:
    """Open, initialize, and migrate the SQLite state database."""

    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.executescript(SCHEMA_SQL)
    _migrate_db(connection)
    return connection


def _column_names(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _migrate_db(connection: sqlite3.Connection) -> None:
    latest_columns = _column_names(connection, "latest_by_path")
    if "first_seen_run_id" not in latest_columns:
        connection.execute("ALTER TABLE latest_by_path ADD COLUMN first_seen_run_id TEXT")
        connection.execute(
            "UPDATE latest_by_path SET first_seen_run_id = last_seen_run_id WHERE first_seen_run_id IS NULL"
        )
    if "seen_count" not in latest_columns:
        connection.execute("ALTER TABLE latest_by_path ADD COLUMN seen_count INTEGER NOT NULL DEFAULT 1")

    history_columns = _column_names(connection, "history_by_path")
    if "first_seen_run_id" not in history_columns:
        connection.execute("ALTER TABLE history_by_path ADD COLUMN first_seen_run_id TEXT")
        connection.execute("UPDATE history_by_path SET first_seen_run_id = run_id WHERE first_seen_run_id IS NULL")
    if "seen_count" not in history_columns:
        connection.execute("ALTER TABLE history_by_path ADD COLUMN seen_count INTEGER NOT NULL DEFAULT 1")
    connection.execute("UPDATE latest_by_path SET seen_count = COALESCE(seen_count, 1)")
    connection.execute(
        """
        INSERT INTO metadata_history_by_path(
            path, size, mtime_utc, run_id, first_seen_run_id, seen_count
        )
        SELECT
            latest_by_path.path,
            latest_by_path.size,
            latest_by_path.mtime_utc,
            latest_by_path.last_seen_run_id,
            COALESCE(latest_by_path.first_seen_run_id, latest_by_path.last_seen_run_id),
            COALESCE(latest_by_path.seen_count, 1)
        FROM latest_by_path
        WHERE NOT EXISTS (
            SELECT 1
            FROM metadata_history_by_path
            WHERE metadata_history_by_path.path = latest_by_path.path
              AND metadata_history_by_path.size = latest_by_path.size
              AND metadata_history_by_path.mtime_utc = latest_by_path.mtime_utc
        )
        """
    )
    connection.execute(
        """
        INSERT INTO directory_history_by_path(
            path, mtime_utc, child_files, child_dirs, run_id, first_seen_run_id, seen_count
        )
        SELECT
            latest_directories.path,
            latest_directories.mtime_utc,
            latest_directories.child_files,
            latest_directories.child_dirs,
            latest_directories.last_seen_run_id,
            latest_directories.last_seen_run_id,
            1
        FROM latest_directories
        WHERE NOT EXISTS (
            SELECT 1
            FROM directory_history_by_path
            WHERE directory_history_by_path.path = latest_directories.path
              AND directory_history_by_path.mtime_utc = latest_directories.mtime_utc
              AND directory_history_by_path.child_files = latest_directories.child_files
              AND directory_history_by_path.child_dirs = latest_directories.child_dirs
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_hist_path_id ON history_by_path(path, id)")
    _deduplicate_history(connection)
    _deduplicate_signature_history(
        connection,
        table="metadata_history_by_path",
        key_columns=("path", "size", "mtime_utc"),
    )
    _deduplicate_signature_history(
        connection,
        table="directory_history_by_path",
        key_columns=("path", "mtime_utc", "child_files", "child_dirs"),
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_hist_path_fp "
        "ON history_by_path(path, fingerprint)"
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_meta_hist_path_signature "
        "ON metadata_history_by_path(path, size, mtime_utc)"
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_dir_hist_path_signature "
        "ON directory_history_by_path(path, mtime_utc, child_files, child_dirs)"
    )
    _drop_legacy_empty_tables(connection)
    connection.commit()


def _deduplicate_history(connection: sqlite3.Connection) -> None:
    """Merge legacy duplicate fingerprint history rows before indexing."""

    connection.execute(
        """
        UPDATE history_by_path
        SET first_seen_run_id = COALESCE(first_seen_run_id, run_id),
            seen_count = COALESCE(seen_count, 1)
        """
    )
    duplicates = connection.execute(
        """
        SELECT path, fingerprint, MIN(id) AS keep_id, COUNT(*) AS duplicate_count
        FROM history_by_path
        GROUP BY path, fingerprint
        HAVING COUNT(*) > 1
        """
    ).fetchall()
    for path, fingerprint, keep_id, duplicate_count in duplicates:
        latest = connection.execute(
            """
            SELECT run_id, mtime_utc, size
            FROM history_by_path
            WHERE path = ? AND fingerprint = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (path, fingerprint),
        ).fetchone()
        if latest:
            run_id, mtime_utc, size = latest
            connection.execute(
                """
                UPDATE history_by_path
                SET run_id = ?, mtime_utc = ?, size = ?, seen_count = seen_count + ?
                WHERE id = ?
                """,
                (run_id, mtime_utc, size, int(duplicate_count) - 1, keep_id),
            )
        connection.execute(
            "DELETE FROM history_by_path WHERE path = ? AND fingerprint = ? AND id <> ?",
            (path, fingerprint, keep_id),
        )


def _deduplicate_signature_history(
    connection: sqlite3.Connection,
    *,
    table: str,
    key_columns: tuple[str, ...],
) -> None:
    """Merge legacy duplicate metadata signatures before adding uniqueness."""

    allowed = {
        "metadata_history_by_path": ("path", "size", "mtime_utc"),
        "directory_history_by_path": (
            "path",
            "mtime_utc",
            "child_files",
            "child_dirs",
        ),
    }
    if allowed.get(table) != key_columns:
        raise ValueError(f"Unsupported history deduplication target: {table}")

    keys_sql = ", ".join(key_columns)
    groups = connection.execute(
        f"""
        SELECT {keys_sql}, MIN(id), SUM(COALESCE(seen_count, 1))
        FROM {table}
        GROUP BY {keys_sql}
        HAVING COUNT(*) > 1
        """
    ).fetchall()
    where_sql = " AND ".join(f"{column} = ?" for column in key_columns)
    for *key_values, keep_id, total_seen_count in groups:
        latest_run = connection.execute(
            f"""
            SELECT run_id
            FROM {table}
            WHERE {where_sql}
            ORDER BY id DESC
            LIMIT 1
            """,
            key_values,
        ).fetchone()
        if latest_run:
            connection.execute(
                f"UPDATE {table} SET run_id = ?, seen_count = ? WHERE id = ?",
                (latest_run[0], int(total_seen_count), int(keep_id)),
            )
        connection.execute(
            f"DELETE FROM {table} WHERE {where_sql} AND id <> ?",
            (*key_values, int(keep_id)),
        )


def _drop_legacy_empty_tables(connection: sqlite3.Connection) -> None:
    """Remove obsolete empty tables left by early development versions."""

    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    for table in ("latest", "history"):
        if table not in tables:
            continue
        count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if count == 0:
            connection.execute(f"DROP TABLE {table}")


def load_latest_by_path(connection: sqlite3.Connection) -> dict[str, FileState]:
    """Load the current file baseline keyed by normalized absolute path."""

    cursor = connection.cursor()
    cursor.execute("SELECT path, size, mtime_utc, fingerprint, seen_count FROM latest_by_path")
    latest: dict[str, FileState] = {}
    for path, size, mtime_utc, fingerprint, seen_count in cursor.fetchall():
        latest[path] = FileState(
            file_key=path,
            path=path,
            size=int(size),
            mtime_utc=int(mtime_utc),
            fingerprint=fingerprint,
            seen_count=int(seen_count),
        )
    return latest


def load_latest_directories(connection: sqlite3.Connection) -> dict[str, DirectoryMeta]:
    """Load the current directory baseline keyed by normalized absolute path."""

    cursor = connection.cursor()
    cursor.execute("SELECT path, mtime_utc, child_files, child_dirs FROM latest_directories")
    latest: dict[str, DirectoryMeta] = {}
    for path, mtime_utc, child_files, child_dirs in cursor.fetchall():
        latest[path] = DirectoryMeta(
            path=path,
            mtime_utc=int(mtime_utc),
            child_files=int(child_files),
            child_dirs=int(child_dirs),
        )
    return latest


def fingerprint_seen_before(
    connection: sqlite3.Connection,
    path: str,
    fingerprint: str,
) -> bool:
    """Return whether this exact fingerprint was previously stored for a path."""

    cursor = connection.cursor()
    cursor.execute(
        "SELECT 1 FROM history_by_path WHERE path = ? AND fingerprint = ? LIMIT 1",
        (path, fingerprint),
    )
    return cursor.fetchone() is not None


def metadata_signature_seen_before(
    connection: sqlite3.Connection,
    path: str,
    size: int,
    mtime_utc: int,
) -> bool:
    """Return whether an exact size and mtime pair was seen for a path."""

    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT 1
        FROM metadata_history_by_path
        WHERE path = ? AND size = ? AND mtime_utc = ?
        LIMIT 1
        """,
        (path, int(size), int(mtime_utc)),
    )
    return cursor.fetchone() is not None


def metadata_size_seen_before(
    connection: sqlite3.Connection,
    path: str,
    size: int,
) -> bool:
    """Return whether a file path previously had the supplied size."""

    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT 1
        FROM metadata_history_by_path
        WHERE path = ? AND size = ?
        LIMIT 1
        """,
        (path, int(size)),
    )
    return cursor.fetchone() is not None


def directory_signature_seen_before(
    connection: sqlite3.Connection,
    path: str,
    mtime_utc: int,
    child_files: int,
    child_dirs: int,
) -> bool:
    """Return whether exact directory metadata was previously observed."""

    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT 1
        FROM directory_history_by_path
        WHERE path = ? AND mtime_utc = ? AND child_files = ? AND child_dirs = ?
        LIMIT 1
        """,
        (path, int(mtime_utc), int(child_files), int(child_dirs)),
    )
    return cursor.fetchone() is not None


def directory_shape_seen_before(
    connection: sqlite3.Connection,
    path: str,
    child_files: int,
    child_dirs: int,
) -> bool:
    """Return whether directory child counts were previously observed."""

    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT 1
        FROM directory_history_by_path
        WHERE path = ? AND child_files = ? AND child_dirs = ?
        LIMIT 1
        """,
        (path, int(child_files), int(child_dirs)),
    )
    return cursor.fetchone() is not None


def _filename_signature(path: str) -> tuple[str, str]:
    name = os.path.basename(path)
    stem, ext = os.path.splitext(name)
    compact_stem = re.sub(r"[^a-z0-9]+", "", stem.lower())
    compact_ext = ext.lower()
    return compact_stem, compact_ext


def _path_depth(path: str) -> int:
    parts = [part for part in os.path.normpath(path).split(os.sep) if part]
    return len(parts)


def _best_rename_candidate(old_path: str, candidates: list[str]) -> str | None:
    if not candidates:
        return None

    old_parent = os.path.dirname(old_path)
    old_signature = _filename_signature(old_path)
    scored: list[tuple[int, str]] = []

    for candidate in candidates:
        score = 0
        if os.path.dirname(candidate) == old_parent:
            score += 100
        if _filename_signature(candidate) == old_signature:
            score += 80
        elif os.path.splitext(candidate)[1].lower() == os.path.splitext(old_path)[1].lower():
            score += 10
        score -= abs(_path_depth(candidate) - _path_depth(old_path))
        scored.append((score, candidate))

    scored.sort(key=lambda item: (-item[0], item[1]))
    if scored[0][0] <= 0:
        return None
    return scored[0][1]


def _candidate_action(old_path: str, candidate_path: str | None) -> str | None:
    if candidate_path is None:
        return None

    same_parent = os.path.dirname(old_path) == os.path.dirname(candidate_path)
    same_name = os.path.basename(old_path) == os.path.basename(candidate_path)

    if same_parent and not same_name:
        return "rename"
    if not same_parent and same_name:
        return "move"
    if not same_parent and not same_name:
        return "move_and_rename"
    return "same_path"


def _movement_label(candidate_action: str | None, *, confidence_prefix: str) -> str:
    if candidate_action == "rename":
        return f"{confidence_prefix} renamed"
    if candidate_action == "move":
        return f"{confidence_prefix} moved"
    if candidate_action == "move_and_rename":
        return f"{confidence_prefix} moved and renamed"
    return f"{confidence_prefix} moved or renamed"


def _matched_missing_severity(candidate_action: str | None) -> str:
    if candidate_action == "rename":
        return "low"
    return "medium"


def _alert_level(severity: str) -> str:
    return {
        "critical": "Extremely High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(severity, "Review")


def _review_note(event_type: str) -> str:
    if event_type == "reverted":
        return "Version reversion is treated as extremely high risk and should be reviewed immediately."
    if event_type == "missing":
        return "Intent cannot be proven from filesystem metadata; confirm with the data owner or change record."
    return "Review with the data owner if this change was not expected."


def _base_assessment(
    *,
    event_type: str,
    severity: str,
    action_likelihood: str,
    action_confidence: str,
    intent_likelihood: str,
    intent_confidence: str,
    target_kind: str,
    rationale: list[str],
) -> dict[str, object]:
    return {
        "alert_level": _alert_level(severity),
        "risk": _alert_level(severity),
        "target_kind": target_kind,
        "action_likelihood": action_likelihood,
        "action_confidence": action_confidence,
        "intent_likelihood": intent_likelihood,
        "intent_confidence": intent_confidence,
        "rationale": rationale,
        "review_note": _review_note(event_type),
    }


def _missing_assessment(
    *,
    old: FileState,
    candidate_path: str | None,
    candidate_reason: str | None,
    missing_in_parent: int,
) -> dict[str, object]:
    rationale: list[str] = []
    matched = candidate_path is not None
    target_kind = "file"
    action_likelihood = "Likely deleted or currently unavailable"
    action_confidence = "medium"
    candidate_action = _candidate_action(old.path, candidate_path)
    severity = _matched_missing_severity(candidate_action) if matched else "high"

    if candidate_path and candidate_reason == "fingerprint":
        action_likelihood = _movement_label(candidate_action, confidence_prefix="Likely")
        action_confidence = "high"
        rationale.append("A newly observed file has the same content fingerprint.")
    elif candidate_path and candidate_reason == "filename_metadata":
        action_likelihood = "Likely renamed"
        action_confidence = "high"
        rationale.append("A newly observed file in the same folder has the same size and a filename-equivalent signature.")
    elif candidate_path and candidate_reason == "metadata":
        action_likelihood = _movement_label(candidate_action, confidence_prefix="Possibly")
        action_confidence = "medium"
        rationale.append("A newly observed file has the same size and modified time.")
    else:
        rationale.append("No matching newly observed file was found in the scan.")

    if missing_in_parent >= 3:
        target_kind = "directory"
        rationale.append(
            f"{missing_in_parent} files are missing from the same directory, which suggests a directory-level action."
        )
        if not matched:
            action_likelihood = "Likely directory deleted, moved, renamed, or unavailable"
            action_confidence = "medium"

    if matched:
        intent_likelihood = "Could be accidental or planned reorganisation"
        intent_confidence = "low"
    elif missing_in_parent >= 10:
        intent_likelihood = "More consistent with intentional or bulk action"
        intent_confidence = "medium"
    elif missing_in_parent >= 3:
        intent_likelihood = "Could be accidental folder action or intentional bulk change"
        intent_confidence = "low"
    else:
        intent_likelihood = "Indeterminate: accidental and intentional are both plausible"
        intent_confidence = "low"

    assessment = _base_assessment(
        event_type="missing",
        severity=severity,
        action_likelihood=action_likelihood,
        action_confidence=action_confidence,
        intent_likelihood=intent_likelihood,
        intent_confidence=intent_confidence,
        target_kind=target_kind,
        rationale=rationale,
    )
    assessment.update(
        {
            "candidate_new_path": candidate_path,
            "candidate_match": candidate_reason,
            "candidate_action": candidate_action,
            "directory_missing_files": missing_in_parent,
            "last_size": old.size,
            "last_mtime_utc": old.mtime_utc,
        }
    )
    return assessment


def _directory_missing_assessment(
    *,
    old: DirectoryMeta,
    candidate_path: str | None,
) -> dict[str, object]:
    candidate_action = _candidate_action(old.path, candidate_path)
    matched = candidate_path is not None
    severity = "medium" if matched else "high"
    rationale: list[str] = []

    if matched:
        action_likelihood = _movement_label(candidate_action, confidence_prefix="Possibly")
        action_confidence = "medium"
        intent_likelihood = "Could be accidental or planned folder reorganisation"
        intent_confidence = "low"
        rationale.append("A newly observed directory has a compatible name or location pattern.")
    else:
        action_likelihood = "Likely directory deleted or currently unavailable"
        action_confidence = "medium"
        intent_likelihood = "Indeterminate: accidental and intentional are both plausible"
        intent_confidence = "low"
        rationale.append("A previously observed directory path was not found in this scan.")

    assessment = _base_assessment(
        event_type="missing",
        severity=severity,
        action_likelihood=action_likelihood,
        action_confidence=action_confidence,
        intent_likelihood=intent_likelihood,
        intent_confidence=intent_confidence,
        target_kind="directory",
        rationale=rationale,
    )
    assessment.update(
        {
            "candidate_new_path": candidate_path,
            "candidate_action": candidate_action,
            "last_mtime_utc": old.mtime_utc,
            "last_child_files": old.child_files,
            "last_child_dirs": old.child_dirs,
        }
    )
    return assessment


def _directory_metadata_reverted_assessment(*, match_type: str) -> dict[str, object]:
    if match_type == "mtime_child_counts":
        severity = "high"
        action_likelihood = "Possible directory metadata reversion"
        action_confidence = "medium"
        rationale = [
            "The directory's current modified timestamp and immediate child counts match a previously observed metadata state for this path.",
            "Directory metadata is an approximation; confirm with audit records or file-level evidence.",
        ]
    else:
        severity = "medium"
        action_likelihood = "Possible directory shape-pattern reversion"
        action_confidence = "low"
        rationale = [
            "The directory's immediate child-file and child-directory counts returned to a previously observed shape after changing away from it.",
            "The modified timestamp does not match the previous directory metadata state, so this is a weak reversion signal.",
            "Directory metadata is an approximation; confirm with audit records or file-level evidence.",
        ]

    return _base_assessment(
        event_type="directory_metadata_reverted",
        severity=severity,
        action_likelihood=action_likelihood,
        action_confidence=action_confidence,
        intent_likelihood="Indeterminate: restore, folder cleanup, routine reorganisation, accidental change, and intentional reversion are all possible",
        intent_confidence="low",
        target_kind="directory",
        rationale=rationale,
    )


def _changed_assessment() -> dict[str, object]:
    return _base_assessment(
        event_type="changed",
        severity="medium",
        action_likelihood="Content changed",
        action_confidence="high",
        intent_likelihood="Indeterminate: routine editing, accidental change, and intentional change are all possible",
        intent_confidence="low",
        target_kind="file",
        rationale=["The file content fingerprint changed from the previous known state."],
    )


def _metadata_changed_assessment(*, fingerprint_recorded: bool) -> dict[str, object]:
    rationale = [
        "The file size or modified timestamp changed, but no previous fingerprint exists for this path.",
    ]
    if fingerprint_recorded:
        rationale.append("A current fingerprint was recorded for future comparison, but there is no earlier fingerprint to compare against.")
    else:
        rationale.append("The file was not opened for hashing because metadata-only mode is active.")

    return _base_assessment(
        event_type="metadata_changed",
        severity="medium",
        action_likelihood="Metadata changed; content not fingerprinted",
        action_confidence="medium",
        intent_likelihood="Indeterminate: routine editing, accidental overwrite, restore, or intentional change are all possible",
        intent_confidence="low",
        target_kind="file",
        rationale=rationale,
    )


def _metadata_reverted_assessment(*, match_type: str) -> dict[str, object]:
    if match_type == "size_mtime":
        severity = "high"
        action_likelihood = "Possible version reversion from metadata history"
        action_confidence = "medium"
        rationale = [
            "The file's current size and modified timestamp match a previously observed metadata state for this path.",
            "No historical content fingerprint is available, so this is a metadata approximation rather than proof of content reversion.",
        ]
    else:
        severity = "medium"
        action_likelihood = "Possible size-pattern reversion"
        action_confidence = "low"
        rationale = [
            "The file's current size returned to a previously observed size after changing away from it.",
            "The modified timestamp does not match the previous metadata state, so this is a weak reversion signal.",
            "No historical content fingerprint is available, so this is not proof of content reversion.",
        ]

    return _base_assessment(
        event_type="metadata_reverted",
        severity=severity,
        action_likelihood=action_likelihood,
        action_confidence=action_confidence,
        intent_likelihood="Indeterminate: restore, overwrite, routine edit, accidental change, and intentional reversion are all possible",
        intent_confidence="low",
        target_kind="file",
        rationale=rationale,
    )


def _reverted_assessment() -> dict[str, object]:
    return _base_assessment(
        event_type="reverted",
        severity="critical",
        action_likelihood="Version reversion detected",
        action_confidence="high",
        intent_likelihood="Possible restore, rollback, overwrite, or deliberate reversion",
        intent_confidence="medium",
        target_kind="file",
        rationale=[
            "The current fingerprint matches a previous historical fingerprint for this path.",
            "All version reversions are classified as extremely high risk.",
        ],
    )


def _mtime_assessment() -> dict[str, object]:
    return _base_assessment(
        event_type="mtime_went_back",
        severity="low",
        action_likelihood="Modified time moved backwards",
        action_confidence="high",
        intent_likelihood="Indeterminate: clock, copy, restore, or tooling behaviour may explain it",
        intent_confidence="low",
        target_kind="file",
        rationale=["The file modified timestamp is older than the previous recorded timestamp."],
    )


def persist_run(
    connection: sqlite3.Connection,
    run_id: str,
    started_at_utc: str,
    root: str,
    scanned_count: int,
    duration_s: float,
) -> None:
    """Stage one audit record in the current SQLite transaction."""

    connection.execute(
        """
        INSERT INTO runs(run_id, started_at_utc, root, scanned_count, duration_s)
        VALUES(?, ?, ?, ?, ?)
        """,
        (run_id, started_at_utc, root, int(scanned_count), float(duration_s)),
    )
def upsert_latest_and_history(
    connection: sqlite3.Connection,
    run_id: str,
    items: Iterable[tuple[str, int, int, str | None]],
    *,
    history_retention_per_path: int,
) -> None:
    """Batch current file state and deduplicated fingerprint history."""

    item_list = list(items)
    if not item_list:
        return

    cursor = connection.cursor()
    cursor.executemany(
        """
        INSERT INTO latest_by_path(
            path, size, mtime_utc, fingerprint, last_seen_run_id, first_seen_run_id, seen_count
        )
        VALUES(?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(path) DO UPDATE SET
            size = excluded.size,
            mtime_utc = excluded.mtime_utc,
            fingerprint = COALESCE(excluded.fingerprint, latest_by_path.fingerprint),
            last_seen_run_id = excluded.last_seen_run_id,
            first_seen_run_id = COALESCE(latest_by_path.first_seen_run_id, excluded.first_seen_run_id),
            seen_count = latest_by_path.seen_count + 1
        """,
        [
            (path, size, mtime_utc, fingerprint, run_id, run_id)
            for path, size, mtime_utc, fingerprint in item_list
        ],
    )

    fingerprint_items = [
        (path, fingerprint, mtime_utc, size, run_id, run_id)
        for path, size, mtime_utc, fingerprint in item_list
        if fingerprint is not None
    ]
    cursor.executemany(
        """
        INSERT INTO history_by_path(
            path, fingerprint, mtime_utc, size, run_id, first_seen_run_id, seen_count
        )
        VALUES(?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(path, fingerprint) DO UPDATE SET
            mtime_utc = excluded.mtime_utc,
            size = excluded.size,
            run_id = excluded.run_id,
            seen_count = history_by_path.seen_count + 1
        """,
        fingerprint_items,
    )
    if fingerprint_items:
        prune_history(connection, history_retention_per_path)


def delete_latest_paths(connection: sqlite3.Connection, paths: Iterable[str]) -> None:
    """Remove paths that were absent from the completed scan."""

    cursor = connection.cursor()
    cursor.executemany(
        "DELETE FROM latest_by_path WHERE path = ?",
        [(path,) for path in sorted(set(paths))],
    )


def upsert_latest_directories(
    connection: sqlite3.Connection,
    run_id: str,
    directories: Iterable[DirectoryMeta],
) -> None:
    """Batch the latest directory metadata."""

    cursor = connection.cursor()
    cursor.executemany(
        """
        INSERT INTO latest_directories(path, mtime_utc, child_files, child_dirs, last_seen_run_id)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            mtime_utc = excluded.mtime_utc,
            child_files = excluded.child_files,
            child_dirs = excluded.child_dirs,
            last_seen_run_id = excluded.last_seen_run_id
        """,
        [
            (
                directory.path,
                directory.mtime_utc,
                directory.child_files,
                directory.child_dirs,
                run_id,
            )
            for directory in directories
        ],
    )


def upsert_metadata_history(
    connection: sqlite3.Connection,
    run_id: str,
    items: Iterable[tuple[str, int, int]],
    *,
    history_retention_per_path: int,
) -> None:
    """Batch deduplicated file metadata history."""

    item_list = list(items)
    cursor = connection.cursor()
    cursor.executemany(
        """
        INSERT INTO metadata_history_by_path(
            path, size, mtime_utc, run_id, first_seen_run_id, seen_count
        )
        VALUES(?, ?, ?, ?, ?, 1)
        ON CONFLICT(path, size, mtime_utc) DO UPDATE SET
            run_id = excluded.run_id,
            seen_count = metadata_history_by_path.seen_count + 1
        """,
        [
            (path, int(size), int(mtime_utc), run_id, run_id)
            for path, size, mtime_utc in item_list
        ],
    )
    prune_metadata_history(connection, history_retention_per_path)


def upsert_directory_history(
    connection: sqlite3.Connection,
    run_id: str,
    directories: Iterable[DirectoryMeta],
    *,
    history_retention_per_path: int,
) -> None:
    """Batch deduplicated directory metadata history."""

    directory_list = list(directories)
    cursor = connection.cursor()
    cursor.executemany(
        """
        INSERT INTO directory_history_by_path(
            path, mtime_utc, child_files, child_dirs, run_id, first_seen_run_id, seen_count
        )
        VALUES(?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(path, mtime_utc, child_files, child_dirs) DO UPDATE SET
            run_id = excluded.run_id,
            seen_count = directory_history_by_path.seen_count + 1
        """,
        [
            (
                directory.path,
                directory.mtime_utc,
                directory.child_files,
                directory.child_dirs,
                run_id,
                run_id,
            )
            for directory in directory_list
        ],
    )
    prune_directory_history(connection, history_retention_per_path)


def delete_latest_directories(connection: sqlite3.Connection, paths: Iterable[str]) -> None:
    """Remove directory paths that were absent from the completed scan."""

    cursor = connection.cursor()
    cursor.executemany(
        "DELETE FROM latest_directories WHERE path = ?",
        [(path,) for path in sorted(set(paths))],
    )


def prune_history(
    connection: sqlite3.Connection,
    history_retention_per_path: int,
) -> None:
    """Retain only the newest configured fingerprint states for each path."""

    if history_retention_per_path <= 0:
        return

    connection.execute(
        """
        DELETE FROM history_by_path
        WHERE id IN (
            SELECT id
            FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY path
                        ORDER BY run_id DESC, id DESC
                    ) AS history_rank
                FROM history_by_path
            )
            WHERE history_rank > ?
        )
        """,
        (int(history_retention_per_path),),
    )


def prune_metadata_history(
    connection: sqlite3.Connection,
    history_retention_per_path: int,
) -> None:
    """Retain only the newest configured metadata states for each file path."""

    if history_retention_per_path <= 0:
        return

    connection.execute(
        """
        DELETE FROM metadata_history_by_path
        WHERE id IN (
            SELECT id
            FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY path
                        ORDER BY run_id DESC, id DESC
                    ) AS history_rank
                FROM metadata_history_by_path
            )
            WHERE history_rank > ?
        )
        """,
        (int(history_retention_per_path),),
    )


def prune_directory_history(
    connection: sqlite3.Connection,
    history_retention_per_path: int,
) -> None:
    """Retain only the newest configured metadata states for each directory."""

    if history_retention_per_path <= 0:
        return

    connection.execute(
        """
        DELETE FROM directory_history_by_path
        WHERE id IN (
            SELECT id
            FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY path
                        ORDER BY run_id DESC, id DESC
                    ) AS history_rank
                FROM directory_history_by_path
            )
            WHERE history_rank > ?
        )
        """,
        (int(history_retention_per_path),),
    )


def plan_hash_jobs(
    previous: dict[str, FileState],
    current_meta: dict[str, FileMeta],
    *,
    hash_new_files: bool,
) -> list[tuple[str, int]]:
    """Select files that require a new or refreshed fingerprint."""

    jobs: list[tuple[str, int]] = []
    for path in sorted(current_meta):
        meta = current_meta[path]
        old = previous.get(path)
        if old is None:
            if hash_new_files:
                jobs.append((path, meta.size))
            continue

        if old.fingerprint is None:
            if hash_new_files:
                jobs.append((path, meta.size))
            continue

        if meta.size != old.size or meta.mtime_utc != old.mtime_utc:
            jobs.append((path, meta.size))
    return jobs


def run_hash_jobs(
    jobs: list[tuple[str, int]],
    *,
    algo: str,
    sample_bytes: int,
    max_workers: int,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, str]:
    """Fingerprint planned files concurrently and fail on any unreadable file."""

    if not jobs:
        if progress_callback:
            progress_callback(
                ProgressUpdate(
                    phase="Hashing",
                    current=0,
                    total=0,
                    message="no files require fingerprinting",
                )
            )
        return {}

    results: dict[str, str] = {}
    worker_count = max(1, max_workers)
    total = len(jobs)
    progress_interval = max(1, total // 1000)
    if progress_callback:
        progress_callback(
            ProgressUpdate(
                phase="Hashing",
                current=0,
                total=total,
                message=f"{worker_count} worker(s)",
            )
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                compute_fingerprint,
                path,
                size,
                algo=algo,
                sample_bytes=sample_bytes,
            ): path
            for path, size in jobs
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            path = futures[future]
            try:
                results[path] = future.result()
            except Exception as exc:
                for pending in futures:
                    pending.cancel()
                raise ScanError(
                    "Fingerprinting failed, so the baseline was not updated. "
                    f"Could not read {path!r}: {exc}"
                ) from exc
            if progress_callback and (
                completed == total or completed % progress_interval == 0
            ):
                progress_callback(
                    ProgressUpdate(
                        phase="Hashing",
                        current=completed,
                        total=total,
                        message=f"{worker_count} worker(s)",
                    )
                )
    return results


def diff(
    connection: sqlite3.Connection,
    previous: dict[str, FileState],
    current_meta: dict[str, FileMeta],
    current_fingerprints: dict[str, str],
) -> list[Event]:
    """Compare file baselines and classify file-level integrity events."""

    events: list[Event] = []

    previous_paths = set(previous)
    current_paths = set(current_meta)
    new_paths = current_paths - previous_paths
    missing_paths = previous_paths - current_paths

    new_paths_by_fingerprint: dict[str, list[str]] = defaultdict(list)
    for path in new_paths:
        fingerprint = current_fingerprints.get(path)
        if fingerprint:
            new_paths_by_fingerprint[fingerprint].append(path)

    new_paths_by_metadata: dict[tuple[int, int], list[str]] = defaultdict(list)
    for path in new_paths:
        meta = current_meta[path]
        new_paths_by_metadata[(meta.size, meta.mtime_utc)].append(path)

    new_paths_by_size: dict[int, list[str]] = defaultdict(list)
    for path in new_paths:
        new_paths_by_size[current_meta[path].size].append(path)

    current_paths_by_size: dict[int, list[str]] = defaultdict(list)
    for path in current_paths:
        current_paths_by_size[current_meta[path].size].append(path)

    missing_by_parent = Counter(os.path.dirname(path) for path in missing_paths)

    for path in sorted(missing_paths):
        old = previous[path]
        candidate_path: str | None = None
        candidate_reason: str | None = None

        if old.fingerprint and new_paths_by_fingerprint.get(old.fingerprint):
            candidate_path = sorted(new_paths_by_fingerprint[old.fingerprint])[0]
            candidate_reason = "fingerprint"

        if candidate_path is None:
            same_size_candidates = current_paths_by_size.get(old.size, [])
            same_signature_candidates = [
                candidate
                for candidate in same_size_candidates
                if os.path.dirname(candidate) == os.path.dirname(path)
                and _filename_signature(candidate) == _filename_signature(path)
            ]
            best = _best_rename_candidate(path, same_signature_candidates)
            if best:
                candidate_path = best
                candidate_reason = "filename_metadata"

        if candidate_path is None and new_paths_by_metadata.get((old.size, old.mtime_utc)):
            candidate_path = sorted(new_paths_by_metadata[(old.size, old.mtime_utc)])[0]
            candidate_reason = "metadata"

        assessment = _missing_assessment(
            old=old,
            candidate_path=candidate_path,
            candidate_reason=candidate_reason,
            missing_in_parent=missing_by_parent[os.path.dirname(path)],
        )
        severity = str(assessment.get("risk", "High")).lower()

        events.append(
            Event(
                type="missing",
                severity=severity,
                file_key=path,
                old_path=path,
                new_path=candidate_path,
                details={
                    "last_size": old.size,
                    "last_mtime_utc": old.mtime_utc,
                    "assessment": assessment,
                },
            )
        )

    for path in sorted(previous_paths & current_paths):
        old = previous[path]
        new_meta = current_meta[path]
        new_fingerprint = current_fingerprints.get(path)
        old_fingerprint = old.fingerprint
        metadata_changed = new_meta.size != old.size or new_meta.mtime_utc != old.mtime_utc

        if old_fingerprint is None:
            if metadata_changed:
                metadata_reversion_match: str | None = None
                if metadata_signature_seen_before(
                    connection,
                    path,
                    new_meta.size,
                    new_meta.mtime_utc,
                ):
                    metadata_reversion_match = "size_mtime"
                elif old.size != new_meta.size and metadata_size_seen_before(
                    connection,
                    path,
                    new_meta.size,
                ):
                    metadata_reversion_match = "size_only"

                if metadata_reversion_match is not None:
                    assessment = _metadata_reverted_assessment(
                        match_type=metadata_reversion_match,
                    )
                    events.append(
                        Event(
                            type="possible_metadata_reverted",
                            severity=str(assessment.get("risk", "Medium")).lower(),
                            file_key=path,
                            path=path,
                            details={
                                "old_size": old.size,
                                "new_size": new_meta.size,
                                "old_mtime_utc": old.mtime_utc,
                                "new_mtime_utc": new_meta.mtime_utc,
                                "metadata_match": metadata_reversion_match,
                                "assessment": assessment,
                            },
                        )
                    )
                    continue

                events.append(
                    Event(
                        type="metadata_changed",
                        severity="medium",
                        file_key=path,
                        path=path,
                        details={
                            "old_size": old.size,
                            "new_size": new_meta.size,
                            "old_mtime_utc": old.mtime_utc,
                            "new_mtime_utc": new_meta.mtime_utc,
                            "current_fingerprint_recorded": new_fingerprint is not None,
                            "assessment": _metadata_changed_assessment(
                                fingerprint_recorded=new_fingerprint is not None
                            ),
                        },
                    )
                )
            continue

        if new_meta.mtime_utc < old.mtime_utc:
            events.append(
                Event(
                    type="mtime_went_back",
                    severity="low",
                    file_key=path,
                    path=path,
                    details={
                        "old_mtime_utc": old.mtime_utc,
                        "new_mtime_utc": new_meta.mtime_utc,
                        "assessment": _mtime_assessment(),
                    },
                )
            )

        if new_fingerprint is None:
            continue

        if new_fingerprint != old_fingerprint:
            if fingerprint_seen_before(connection, path, new_fingerprint):
                events.append(
                    Event(
                        type="reverted",
                        severity="critical",
                        file_key=path,
                        path=path,
                        details={
                            "old_fp": old_fingerprint,
                            "new_fp": new_fingerprint,
                            "assessment": _reverted_assessment(),
                        },
                    )
                )
            else:
                events.append(
                    Event(
                        type="changed",
                        severity="medium",
                        file_key=path,
                        path=path,
                        details={
                            "old_fp": old_fingerprint,
                            "new_fp": new_fingerprint,
                            "assessment": _changed_assessment(),
                        },
                    )
                )

    return events


def _best_directory_candidate(old_path: str, candidates: set[str]) -> str | None:
    if not candidates:
        return None

    old_parent = os.path.dirname(old_path)
    old_name = os.path.basename(old_path).lower()
    scored: list[tuple[int, str]] = []
    for candidate in candidates:
        candidate_parent = os.path.dirname(candidate)
        candidate_name = os.path.basename(candidate).lower()
        score = 0
        if candidate_name == old_name:
            score += 100
        if candidate_parent == old_parent:
            score += 70
        score -= abs(_path_depth(candidate) - _path_depth(old_path))
        scored.append((score, candidate))

    scored.sort(key=lambda item: (-item[0], item[1]))
    if scored[0][0] <= 0:
        return None
    return scored[0][1]


def diff_directories(
    connection: sqlite3.Connection,
    previous: dict[str, DirectoryMeta],
    current: dict[str, DirectoryMeta],
) -> list[Event]:
    """Compare directory baselines and classify directory-level events."""

    events: list[Event] = []
    previous_dirs = set(previous)
    current_dirs = set(current)
    new_dirs = current_dirs - previous_dirs
    missing_dirs = previous_dirs - current_dirs

    for path in sorted(missing_dirs):
        old = previous[path]
        candidate_path = _best_directory_candidate(path, new_dirs)
        assessment = _directory_missing_assessment(
            old=old,
            candidate_path=candidate_path,
        )
        severity = str(assessment.get("risk", "High")).lower()
        events.append(
            Event(
                type="directory_missing",
                severity=severity,
                file_key=path,
                old_path=path,
                new_path=candidate_path,
                details={
                    "last_mtime_utc": old.mtime_utc,
                    "last_child_files": old.child_files,
                    "last_child_dirs": old.child_dirs,
                    "assessment": assessment,
                },
            )
        )

    for path in sorted(previous_dirs & current_dirs):
        old = previous[path]
        new = current[path]
        metadata_changed = (
            new.mtime_utc != old.mtime_utc
            or new.child_files != old.child_files
            or new.child_dirs != old.child_dirs
        )
        if not metadata_changed:
            continue

        metadata_reversion_match: str | None = None
        if directory_signature_seen_before(
            connection,
            path,
            new.mtime_utc,
            new.child_files,
            new.child_dirs,
        ):
            metadata_reversion_match = "mtime_child_counts"
        elif (
            (old.child_files, old.child_dirs) != (new.child_files, new.child_dirs)
            and directory_shape_seen_before(
                connection,
                path,
                new.child_files,
                new.child_dirs,
            )
        ):
            metadata_reversion_match = "child_counts"

        if metadata_reversion_match is None:
            continue

        assessment = _directory_metadata_reverted_assessment(
            match_type=metadata_reversion_match,
        )
        events.append(
            Event(
                type="possible_directory_metadata_reverted",
                severity=str(assessment.get("risk", "Medium")).lower(),
                file_key=path,
                path=path,
                details={
                    "old_mtime_utc": old.mtime_utc,
                    "new_mtime_utc": new.mtime_utc,
                    "old_child_files": old.child_files,
                    "new_child_files": new.child_files,
                    "old_child_dirs": old.child_dirs,
                    "new_child_dirs": new.child_dirs,
                    "metadata_match": metadata_reversion_match,
                    "assessment": assessment,
                },
            )
        )

    return events


def write_events_csv(events: list[Event], out_path: Path) -> None:
    """Write the stable flat event export consumed by operators and tooling."""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "type",
                "severity",
                "alert_level",
                "action_likelihood",
                "action_confidence",
                "intent_likelihood",
                "intent_confidence",
                "target_kind",
                "path",
                "old_path",
                "new_path",
                "details_json",
            ]
        )
        for event in events:
            details = event.details or {}
            assessment = details.get("assessment") if isinstance(details, dict) else {}
            if not isinstance(assessment, dict):
                assessment = {}
            writer.writerow(
                [
                    event.type,
                    event.severity,
                    assessment.get("alert_level", _alert_level(event.severity)),
                    assessment.get("action_likelihood", ""),
                    assessment.get("action_confidence", ""),
                    assessment.get("intent_likelihood", ""),
                    assessment.get("intent_confidence", ""),
                    assessment.get("target_kind", ""),
                    event.path or "",
                    event.old_path or "",
                    event.new_path or "",
                    json.dumps(event.details or {}, ensure_ascii=False, sort_keys=True),
                ]
            )


def _events_dir(outdir: Path) -> Path:
    return outdir / "events"


def _unique_destination(path: Path) -> Path:
    if not path.exists():
        return path

    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def move_legacy_event_csvs(outdir: Path) -> None:
    """Move old top-level event CSVs into the current events directory."""

    events_dir = _events_dir(outdir)
    legacy_files = sorted(outdir.glob("events_*.csv"))
    if not legacy_files:
        return

    events_dir.mkdir(parents=True, exist_ok=True)
    for legacy_file in legacy_files:
        if not legacy_file.is_file():
            continue
        destination = _unique_destination(events_dir / legacy_file.name)
        legacy_file.replace(destination)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _event_assessment(event: Event) -> dict[str, object]:
    details = event.details or {}
    assessment = details.get("assessment") if isinstance(details, dict) else {}
    return assessment if isinstance(assessment, dict) else {}


def _build_likelihood_summary(events: list[Event]) -> dict[str, object]:
    action_counts: Counter[str] = Counter()
    intent_counts: Counter[str] = Counter()
    target_counts: Counter[str] = Counter()

    for event in events:
        assessment = _event_assessment(event)
        action_counts[str(assessment.get("action_likelihood", "Unassessed"))] += 1
        intent_counts[str(assessment.get("intent_likelihood", "Unassessed"))] += 1
        target_counts[str(assessment.get("target_kind", "file"))] += 1

    return {
        "actions": dict(action_counts),
        "intent_signals": dict(intent_counts),
        "targets": dict(target_counts),
    }


def _build_directory_impacts(events: list[Event]) -> list[dict[str, object]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    explicit_directories: dict[str, dict[str, object]] = {}
    for event in events:
        if event.type == "directory_missing" and event.old_path:
            assessment = _event_assessment(event)
            details = event.details or {}
            explicit_directories[event.old_path] = {
                "path": event.old_path,
                "missing_files": int(details.get("last_child_files", 0)),
                "matched_new_paths": 1 if event.new_path else 0,
                "action_likelihood": assessment.get("action_likelihood", "Unassessed"),
                "action_confidence": assessment.get("action_confidence", ""),
                "intent_likelihood": assessment.get("intent_likelihood", ""),
                "risk": assessment.get("risk", _alert_level(event.severity)),
                "event_type": event.type,
                "possible_new_path": event.new_path,
            }
        if event.type == "possible_directory_metadata_reverted" and event.path:
            assessment = _event_assessment(event)
            explicit_directories[event.path] = {
                "path": event.path,
                "missing_files": 0,
                "matched_new_paths": 0,
                "action_likelihood": assessment.get("action_likelihood", "Unassessed"),
                "action_confidence": assessment.get("action_confidence", ""),
                "intent_likelihood": assessment.get("intent_likelihood", ""),
                "risk": assessment.get("risk", _alert_level(event.severity)),
                "event_type": event.type,
                "possible_new_path": "",
            }
        if event.type == "missing" and event.old_path:
            groups[os.path.dirname(event.old_path)].append(event)

    impacts: list[dict[str, object]] = list(explicit_directories.values())
    for directory, items in groups.items():
        if directory in explicit_directories:
            continue
        if len(items) < 2:
            continue

        matched = sum(1 for item in items if item.new_path)
        if matched:
            candidate_dirs = sorted(
                {
                    os.path.dirname(item.new_path)
                    for item in items
                    if item.new_path
                }
            )
            candidate_dir = candidate_dirs[0] if len(candidate_dirs) == 1 else None
            if candidate_dir:
                directory_action = _candidate_action(directory, candidate_dir)
            else:
                directory_action = "multiple_locations"
            if directory_action == "rename":
                action = "Possible directory rename"
            elif directory_action == "move":
                action = "Possible directory move"
            elif directory_action == "move_and_rename":
                action = "Possible directory move and rename"
            else:
                action = "Possible directory move affecting multiple locations"
            confidence = "medium"
            risk = "Medium"
        else:
            action = "Possible directory deletion or temporary unavailability"
            confidence = "high" if len(items) >= 10 else "medium"
            risk = "High"

        if len(items) >= 10:
            intent = "More consistent with intentional or bulk action"
        else:
            intent = "Could be accidental folder action or intentional bulk change"

        impacts.append(
            {
                "path": directory,
                "missing_files": len(items),
                "matched_new_paths": matched,
                "action_likelihood": action,
                "action_confidence": confidence,
                "intent_likelihood": intent,
                "risk": risk,
            }
        )

    return sorted(impacts, key=lambda item: (-int(item["missing_files"]), str(item["path"])))


def _metadata_only_file_count(
    previous: dict[str, FileState],
    current_meta: dict[str, FileMeta],
    current_fingerprints: dict[str, str],
) -> int:
    count = 0
    for path in current_meta:
        if current_fingerprints.get(path) is not None:
            continue
        old = previous.get(path)
        if old is None or old.fingerprint is None:
            count += 1
    return count


def _reversion_unprotected_file_count(
    current_meta: dict[str, FileMeta],
    current_fingerprints: dict[str, str],
    *,
    previous: dict[str, FileState],
) -> int:
    unprotected = 0
    for path in current_meta:
        old = previous.get(path)
        known_fingerprint = current_fingerprints.get(path) or (old.fingerprint if old else None)
        if known_fingerprint is None:
            unprotected += 1
    return unprotected


def _skipped_missing_fingerprint_hashes(
    previous: dict[str, FileState],
    current_meta: dict[str, FileMeta],
    current_fingerprints: dict[str, str],
    *,
    hash_new_files: bool,
) -> int:
    if hash_new_files:
        return 0

    skipped = 0
    for path in current_meta:
        old = previous.get(path)
        if old is not None and old.fingerprint is None and current_fingerprints.get(path) is None:
            skipped += 1
    return skipped


def scan_files(settings: ScanSettings) -> dict[str, object]:
    """Run one complete scan, comparison, persistence, and event export."""

    root = Path(settings.root).expanduser()
    if not root.exists():
        raise ScanError(f"Root does not exist: {root}", exit_code=2)
    if not root.is_dir():
        raise ScanError(f"Root is not a directory: {root}", exit_code=2)
    if settings.sample_bytes <= 0:
        raise ScanError("--sample-bytes must be greater than zero.", exit_code=2)
    if settings.max_workers <= 0:
        raise ScanError("--max-workers must be greater than zero.", exit_code=2)
    if settings.history_retention_per_path < 0:
        raise ScanError(
            "--history-retention-per-path must be zero or greater.",
            exit_code=2,
        )
    try:
        hashlib.new(settings.algo)
    except (TypeError, ValueError) as exc:
        raise ScanError(
            f"Unsupported hash algorithm {settings.algo!r}. "
            "Use a name supported by Python hashlib, such as sha256.",
            exit_code=2,
        ) from exc

    db_path = Path(settings.db).expanduser().resolve()
    outdir = Path(settings.outdir).expanduser().resolve()
    latest_json = (
        Path(settings.latest_json).expanduser().resolve()
        if settings.latest_json is not None
        else None
    )
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScanError(f"Cannot create report directory {str(outdir)!r}: {exc}") from exc

    run_id = make_run_id()
    started_at = utc_now_iso()
    start = time.time()

    try:
        connection = open_db(db_path)
    except (OSError, sqlite3.Error) as exc:
        raise ScanError(f"Cannot open SQLite database {str(db_path)!r}: {exc}") from exc

    try:
        previous = load_latest_by_path(connection)
        previous_directories = load_latest_directories(connection)

        if settings.progress_callback:
            settings.progress_callback(
                ProgressUpdate(
                    phase="Scanning",
                    current=0,
                    total=len(previous) or None,
                    estimated=bool(previous),
                    message="estimating from the previous baseline" if previous else "first baseline",
                )
            )
        current_meta, current_directories = collect_tree_scandir(
            root,
            settings.exclusions,
            progress_callback=settings.progress_callback,
            estimated_file_total=len(previous) or None,
        )

        jobs = plan_hash_jobs(
            previous,
            current_meta,
            hash_new_files=settings.hash_new_files,
        )
        current_fingerprints = run_hash_jobs(
            jobs,
            algo=settings.algo,
            sample_bytes=settings.sample_bytes,
            max_workers=settings.max_workers,
            progress_callback=settings.progress_callback,
        )
        if settings.progress_callback:
            settings.progress_callback(
                ProgressUpdate(
                    phase="Comparing",
                    current=0,
                    total=1,
                    unit="phase",
                    message=f"{len(current_meta):,} files",
                )
            )
        metadata_only_files = _metadata_only_file_count(
            previous,
            current_meta,
            current_fingerprints,
        )
        reversion_unprotected_files = _reversion_unprotected_file_count(
            current_meta,
            current_fingerprints,
            previous=previous,
        )
        skipped_missing_fingerprint_hashes = _skipped_missing_fingerprint_hashes(
            previous,
            current_meta,
            current_fingerprints,
            hash_new_files=settings.hash_new_files,
        )

        events = [
            *diff_directories(connection, previous_directories, current_directories),
            *diff(connection, previous, current_meta, current_fingerprints),
        ]
        if settings.progress_callback:
            settings.progress_callback(
                ProgressUpdate(
                    phase="Comparing",
                    current=1,
                    total=1,
                    unit="phase",
                    message=f"{len(events):,} event(s)",
                )
            )

        duration_s = time.time() - start
        normalized_root = normalize_path(root)
        if settings.progress_callback:
            settings.progress_callback(
                ProgressUpdate(
                    phase="Saving",
                    current=0,
                    total=len(current_meta),
                    message="batching SQLite state",
                )
            )
        persist_run(
            connection,
            run_id,
            started_at,
            normalized_root,
            len(current_meta),
            duration_s,
        )

        persist_items = [
            (
                path,
                current_meta[path].size,
                current_meta[path].mtime_utc,
                current_fingerprints.get(path),
            )
            for path in sorted(current_meta)
        ]
        upsert_latest_and_history(
            connection,
            run_id,
            persist_items,
            history_retention_per_path=settings.history_retention_per_path,
        )
        upsert_metadata_history(
            connection,
            run_id,
            [
                (
                    path,
                    current_meta[path].size,
                    current_meta[path].mtime_utc,
                )
                for path in sorted(current_meta)
            ],
            history_retention_per_path=settings.history_retention_per_path,
        )
        upsert_directory_history(
            connection,
            run_id,
            current_directories.values(),
            history_retention_per_path=settings.history_retention_per_path,
        )
        upsert_latest_directories(connection, run_id, current_directories.values())
        delete_latest_paths(connection, previous.keys() - current_meta.keys())
        delete_latest_directories(
            connection,
            previous_directories.keys() - current_directories.keys(),
        )
        connection.commit()
        if settings.progress_callback:
            settings.progress_callback(
                ProgressUpdate(
                    phase="Saving",
                    current=len(current_meta),
                    total=len(current_meta),
                    message="SQLite transaction committed",
                )
            )
    except ScanError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise ScanError(
            "SQLite persistence failed, so the current baseline was not committed. "
            f"Database {str(db_path)!r}: {exc}"
        ) from exc
    finally:
        connection.close()

    if settings.progress_callback:
        settings.progress_callback(
            ProgressUpdate(
                phase="Reporting",
                current=0,
                total=1,
                unit="phase",
                message="writing event outputs",
            )
        )
    try:
        move_legacy_event_csvs(outdir)
        events_csv = _events_dir(outdir) / f"events_{run_id}.csv"
        write_events_csv(events, events_csv)
    except OSError as exc:
        raise ScanError(
            "The scan state was saved, but the event report could not be written. "
            f"Output directory {str(outdir)!r}: {exc}"
        ) from exc

    summary: dict[str, object] = {
        "run_id": run_id,
        "started_at_utc": started_at,
        "root": normalize_path(root),
        "db": str(db_path),
        "reports": {"events_csv": str(events_csv)},
        "stats": {
            "scanned_files": len(current_meta),
            "scanned_directories": len(current_directories),
            "hashed_files": len(current_fingerprints),
            "metadata_only_files": metadata_only_files,
            "reversion_unprotected_files": reversion_unprotected_files,
            "skipped_missing_fingerprint_hashes": skipped_missing_fingerprint_hashes,
            "duration_s": round(duration_s, 3),
            "events": len(events),
            "critical": sum(1 for event in events if event.severity == "critical"),
            "high": sum(1 for event in events if event.severity == "high"),
            "medium": sum(1 for event in events if event.severity == "medium"),
            "low": sum(1 for event in events if event.severity == "low"),
        },
        "likelihood_summary": _build_likelihood_summary(events),
        "directory_impacts": _build_directory_impacts(events),
        "events": [event.to_dict() for event in events],
    }

    if latest_json is not None:
        try:
            _write_json(latest_json, summary)
        except OSError as exc:
            raise ScanError(
                "The scan state and event CSV were saved, but the latest JSON "
                f"could not be written to {str(latest_json)!r}: {exc}"
            ) from exc

    if settings.progress_callback:
        settings.progress_callback(
            ProgressUpdate(
                phase="Reporting",
                current=1,
                total=1,
                unit="phase",
                message="event outputs written",
            )
        )

    return summary
