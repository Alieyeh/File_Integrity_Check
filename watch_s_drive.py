from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple


# ----------------------------
# Data models
# ----------------------------

@dataclass(frozen=True)
class FileRecord:
    """
    Represents one observed file on disk.

    Attributes:
        path: Normalized absolute path to the file.
        size: File size in bytes.
        mtime_utc: Last modified timestamp in UTC seconds since epoch.
        file_id: Stable NTFS identity (best-effort; may be None on some shares).
        fingerprint: Content fingerprint (hash) used to detect reverts/changes.
    """
    path: str
    size: int
    mtime_utc: int
    file_id: Optional[str]
    fingerprint: str


@dataclass(frozen=True)
class Event:
    """
    Represents a detected change.

    Attributes:
        type: Event type e.g. 'missing', 'moved', 'reverted', 'changed', 'mtime_went_back'.
        severity: 'high'|'medium'|'low'
        file_key: Stable identity key used by the system.
        path: Current path (if exists).
        old_path: Previous path (if applicable).
        new_path: New path (if applicable).
        details: Free-form dict for extra info.
    """
    type: str
    severity: str
    file_key: str
    path: Optional[str] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    details: Optional[dict] = None


# ----------------------------
# Windows NTFS File ID (best-effort)
# ----------------------------

# This is a best-effort attempt to get a stable ID on Windows.
# It usually works on local NTFS volumes and many SMB shares, but not always.
# If it fails, we fall back to content fingerprint identity.
def get_windows_file_id(path: str) -> Optional[str]:
    """
    Attempts to retrieve a stable file identifier from Windows.

    Args:
        path: Full path to the file.

    Returns:
        A string identifier if available, otherwise None.
    """
    if os.name != "nt":
        return None

    # Win32 API definitions
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p
    ]
    CreateFileW.restype = ctypes.c_void_p

    GetFileInformationByHandle = ctypes.windll.kernel32.GetFileInformationByHandle
    GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    GetFileInformationByHandle.restype = ctypes.c_int

    CloseHandle = ctypes.windll.kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", ctypes.c_uint32),
            ("ftCreationTime", ctypes.c_uint64),
            ("ftLastAccessTime", ctypes.c_uint64),
            ("ftLastWriteTime", ctypes.c_uint64),
            ("dwVolumeSerialNumber", ctypes.c_uint32),
            ("nFileSizeHigh", ctypes.c_uint32),
            ("nFileSizeLow", ctypes.c_uint32),
            ("nNumberOfLinks", ctypes.c_uint32),
            ("nFileIndexHigh", ctypes.c_uint32),
            ("nFileIndexLow", ctypes.c_uint32),
        ]

    handle = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        return None

    info = BY_HANDLE_FILE_INFORMATION()
    ok = GetFileInformationByHandle(handle, ctypes.byref(info))
    CloseHandle(handle)

    if not ok:
        return None

    # Combine volume serial + file index high/low for uniqueness across volumes
    file_index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
    return f"VOL{int(info.dwVolumeSerialNumber):08X}-FID{file_index:016X}"


# ----------------------------
# Fingerprinting
# ----------------------------

def compute_fingerprint(
    path: str,
    size: int,
    *,
    algo: str = "sha256",
    sample_bytes: int = 1024 * 1024,
) -> str:
    """
    Computes a content fingerprint.

    For large files, this uses a partial hash: first N bytes + last N bytes + size.
    For small files (<= 2N), it hashes entire content.

    Args:
        path: File path.
        size: Size in bytes.
        algo: Hash algorithm name for hashlib (default sha256).
        sample_bytes: Sampling window size (default 1 MiB).

    Returns:
        Hex digest fingerprint string.
    """
    h = hashlib.new(algo)
    h.update(str(size).encode("utf-8"))
    try:
        with open(path, "rb") as f:
            if size <= 2 * sample_bytes:
                # Hash whole file
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            else:
                # Hash start
                start = f.read(sample_bytes)
                h.update(start)
                # Hash end
                f.seek(max(0, size - sample_bytes))
                end = f.read(sample_bytes)
                h.update(end)
    except (OSError, PermissionError):
        # If we can't read the file content, fall back to metadata-only fingerprint.
        # This is weaker but still lets you detect many changes.
        h.update(b"UNREADABLE")
    return h.hexdigest()


# ----------------------------
# Scanning
# ----------------------------

def normalize_path(p: Path) -> str:
    """Normalizes a path into a consistent absolute string form."""
    return str(p.resolve())


def default_exclude_dir(name: str) -> bool:
    """
    Default exclusion policy: exclude folders starting with 'A0' or starting with a digit.

    Adjust as needed.
    """
    return name.startswith("A0") or (len(name) > 0 and name[0].isdigit())


def iter_files(root: Path, exclude_dir_fn=default_exclude_dir) -> Iterator[Path]:
    """
    Iterates files under root, excluding directories based on exclude_dir_fn.

    Args:
        root: Root directory to scan.
        exclude_dir_fn: Function taking directory name -> True if excluded.

    Yields:
        Paths to files.
    """
    # os.walk is reliable and fast enough; pruning dirs is key.
    for dirpath, dirnames, filenames in os.walk(root):
        # prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if not exclude_dir_fn(d)]
        for fn in filenames:
            yield Path(dirpath) / fn


def scan_snapshot(
    root: Path,
    *,
    algo: str = "sha256",
    sample_bytes: int = 1024 * 1024,
    use_file_id: bool = True,
) -> Dict[str, FileRecord]:
    """
    Scans the filesystem and returns a snapshot keyed by a stable identity.

    Identity key strategy:
        - If Windows file_id available: key = file_id
        - Else: key = 'FP:' + fingerprint

    Args:
        root: Directory to scan.
        algo: Hash algorithm for fingerprinting.
        sample_bytes: Sample size for partial hashing.
        use_file_id: If True, attempt to use Windows stable file IDs.

    Returns:
        Dict mapping file_key -> FileRecord.
    """
    snapshot: Dict[str, FileRecord] = {}
    for file_path in iter_files(root):
        try:
            st = file_path.stat()
        except (OSError, PermissionError):
            continue

        if not file_path.is_file():
            continue

        path_str = normalize_path(file_path)
        size = int(st.st_size)
        mtime_utc = int(st.st_mtime)  # epoch seconds (UTC-like)
        file_id = get_windows_file_id(path_str) if (use_file_id and os.name == "nt") else None
        fingerprint = compute_fingerprint(path_str, size, algo=algo, sample_bytes=sample_bytes)

        file_key = file_id if file_id else f"FP:{fingerprint}"

        # If collisions occur (rare), keep the first seen but you can also store a list.
        if file_key not in snapshot:
            snapshot[file_key] = FileRecord(
                path=path_str,
                size=size,
                mtime_utc=mtime_utc,
                file_id=file_id,
                fingerprint=fingerprint,
            )

    return snapshot


# ----------------------------
# SQLite State
# ----------------------------

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at_utc TEXT NOT NULL,
    root TEXT NOT NULL,
    scanned_count INTEGER NOT NULL,
    duration_s REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS latest (
    file_key TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_utc INTEGER NOT NULL,
    file_id TEXT,
    fingerprint TEXT NOT NULL,
    last_seen_run_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    mtime_utc INTEGER NOT NULL,
    size INTEGER NOT NULL,
    path TEXT NOT NULL,
    run_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_key ON history(file_key);
CREATE INDEX IF NOT EXISTS idx_history_key_fp ON history(file_key, fingerprint);
"""


def open_db(db_path: Path) -> sqlite3.Connection:
    """
    Opens (and initializes) the SQLite database.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        sqlite3.Connection
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(SCHEMA_SQL)
    return conn


def load_latest(conn: sqlite3.Connection) -> Dict[str, FileRecord]:
    """
    Loads the latest known state from DB.

    Args:
        conn: SQLite connection.

    Returns:
        Dict mapping file_key -> FileRecord
    """
    cur = conn.cursor()
    cur.execute("SELECT file_key, path, size, mtime_utc, file_id, fingerprint FROM latest")
    out: Dict[str, FileRecord] = {}
    for file_key, path, size, mtime_utc, file_id, fingerprint in cur.fetchall():
        out[file_key] = FileRecord(
            path=path,
            size=int(size),
            mtime_utc=int(mtime_utc),
            file_id=file_id,
            fingerprint=fingerprint,
        )
    return out


def fingerprint_seen_before(conn: sqlite3.Connection, file_key: str, fingerprint: str) -> bool:
    """
    Checks whether a fingerprint has appeared in history for a given file_key.

    Args:
        conn: SQLite connection.
        file_key: Identity key.
        fingerprint: Fingerprint string.

    Returns:
        True if fingerprint seen before, else False.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM history WHERE file_key = ? AND fingerprint = ? LIMIT 1",
        (file_key, fingerprint),
    )
    return cur.fetchone() is not None


def persist_run_and_snapshot(
    conn: sqlite3.Connection,
    run_id: str,
    started_at_utc: str,
    root: str,
    duration_s: float,
    snapshot: Dict[str, FileRecord],
) -> None:
    """
    Persists run metadata + latest snapshot + history entries.

    Args:
        conn: SQLite connection.
        run_id: Unique run identifier.
        started_at_utc: ISO timestamp in UTC.
        root: Scanned root path.
        duration_s: Run duration in seconds.
        snapshot: Current snapshot keyed by file_key.
    """
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO runs(run_id, started_at_utc, root, scanned_count, duration_s) VALUES(?,?,?,?,?)",
        (run_id, started_at_utc, root, len(snapshot), float(duration_s)),
    )

    # Update latest + append history
    for file_key, rec in snapshot.items():
        cur.execute(
            """
            INSERT INTO latest(file_key, path, size, mtime_utc, file_id, fingerprint, last_seen_run_id)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(file_key) DO UPDATE SET
                path=excluded.path,
                size=excluded.size,
                mtime_utc=excluded.mtime_utc,
                file_id=excluded.file_id,
                fingerprint=excluded.fingerprint,
                last_seen_run_id=excluded.last_seen_run_id
            """,
            (file_key, rec.path, rec.size, rec.mtime_utc, rec.file_id, rec.fingerprint, run_id),
        )
        cur.execute(
            "INSERT INTO history(file_key, fingerprint, mtime_utc, size, path, run_id) VALUES(?,?,?,?,?,?)",
            (file_key, rec.fingerprint, rec.mtime_utc, rec.size, rec.path, run_id),
        )

    conn.commit()


# ----------------------------
# Diff logic
# ----------------------------

def diff_snapshots(
    conn: sqlite3.Connection,
    previous: Dict[str, FileRecord],
    current: Dict[str, FileRecord],
) -> List[Event]:
    """
    Computes differences between previous and current snapshots.

    Args:
        conn: SQLite connection (for history lookups to detect 'reverted').
        previous: Previous snapshot keyed by file_key.
        current: Current snapshot keyed by file_key.

    Returns:
        List of Event objects describing changes.
    """
    events: List[Event] = []

    prev_keys = set(previous.keys())
    cur_keys = set(current.keys())

    # Missing or moved detection is identity-based (file_key)
    missing_keys = prev_keys - cur_keys
    common_keys = prev_keys & cur_keys
    new_keys = cur_keys - prev_keys  # not used for alerting usually, but available

    # For keys that disappeared entirely => missing
    for k in missing_keys:
        events.append(Event(
            type="missing",
            severity="high",
            file_key=k,
            old_path=previous[k].path,
            details={"last_mtime_utc": previous[k].mtime_utc, "last_fingerprint": previous[k].fingerprint},
        ))

    # For keys present in both: moved / changed / reverted / mtime regression
    for k in common_keys:
        old = previous[k]
        new = current[k]

        if old.path != new.path:
            events.append(Event(
                type="moved",
                severity="medium",
                file_key=k,
                old_path=old.path,
                new_path=new.path,
                details={"old_mtime_utc": old.mtime_utc, "new_mtime_utc": new.mtime_utc},
            ))

        if new.mtime_utc < old.mtime_utc:
            events.append(Event(
                type="mtime_went_back",
                severity="low",
                file_key=k,
                path=new.path,
                details={"old_mtime_utc": old.mtime_utc, "new_mtime_utc": new.mtime_utc},
            ))

        if new.fingerprint != old.fingerprint:
            # Is the new fingerprint something we've seen before for this identity?
            # If yes => strong revert signal.
            seen_before = fingerprint_seen_before(conn, k, new.fingerprint)
            if seen_before:
                events.append(Event(
                    type="reverted",
                    severity="high",
                    file_key=k,
                    path=new.path,
                    details={
                        "old_fingerprint": old.fingerprint,
                        "new_fingerprint": new.fingerprint,
                        "old_mtime_utc": old.mtime_utc,
                        "new_mtime_utc": new.mtime_utc,
                    },
                ))
            else:
                events.append(Event(
                    type="changed",
                    severity="medium",
                    file_key=k,
                    path=new.path,
                    details={
                        "old_fingerprint": old.fingerprint,
                        "new_fingerprint": new.fingerprint,
                        "old_mtime_utc": old.mtime_utc,
                        "new_mtime_utc": new.mtime_utc,
                    },
                ))

    # Optional: record new files if you want
    # for k in new_keys: ...

    return events


# ----------------------------
# Reporting
# ----------------------------

def write_events_csv(events: List[Event], out_path: Path) -> None:
    """
    Writes events to CSV.

    Args:
        events: List of Event objects.
        out_path: Output CSV file path.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "severity", "file_key", "path", "old_path", "new_path", "details_json"])
        for e in events:
            w.writerow([
                e.type, e.severity, e.file_key,
                e.path or "", e.old_path or "", e.new_path or "",
                json.dumps(e.details or {}, ensure_ascii=False),
            ])


# ----------------------------
# Main
# ----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main(argv: Optional[List[str]] = None) -> int:
    """
    Entry point.

    Returns:
        Process exit code: 0 success.
    """
    p = argparse.ArgumentParser(description="Weekly file integrity watcher (offline-friendly).")
    p.add_argument("--root", required=True, help="Root directory to scan, e.g. S:\\\\")
    p.add_argument("--db", default="", help="SQLite DB path. Default: alongside this script.")
    p.add_argument("--outdir", default="reports", help="Directory for CSV/JSON reports.")
    p.add_argument("--sample-bytes", type=int, default=1024 * 1024, help="Bytes for partial hashing (default 1 MiB).")
    p.add_argument("--algo", default="sha256", help="Hash algorithm (default sha256).")
    p.add_argument("--no-file-id", action="store_true", help="Disable Windows file ID usage.")
    args = p.parse_args(argv)

    root = Path(args.root)
    if not root.exists():
        print(json.dumps({"error": f"Root path does not exist: {root}"}, ensure_ascii=False))
        return 2

    script_dir = Path(__file__).resolve().parent
    db_path = Path(args.db).resolve() if args.db else (script_dir / "file_watch_state.sqlite3")
    outdir = (Path(args.outdir).resolve() if Path(args.outdir).is_absolute() else (script_dir / args.outdir))
    outdir.mkdir(parents=True, exist_ok=True)

    run_id = utc_now_iso().replace(":", "").replace("-", "")
    started_at = utc_now_iso()
    t0 = time.time()

    conn = open_db(db_path)
    previous = load_latest(conn)

    current = scan_snapshot(
        root=root,
        algo=args.algo,
        sample_bytes=args.sample_bytes,
        use_file_id=not args.no_file_id,
    )

    # Diff BEFORE persisting history for this run, so "reverted" means "matches older than the immediate previous"
    events = diff_snapshots(conn, previous, current)

    duration_s = time.time() - t0
    persist_run_and_snapshot(
        conn=conn,
        run_id=run_id,
        started_at_utc=started_at,
        root=str(root),
        duration_s=duration_s,
        snapshot=current,
    )
    conn.close()

    # Write reports
    events_csv = outdir / f"events_{run_id}.csv"
    write_events_csv(events, events_csv)

    result = {
        "run_id": run_id,
        "started_at_utc": started_at,
        "root": str(root),
        "db": str(db_path),
        "reports": {
            "events_csv": str(events_csv),
        },
        "stats": {
            "scanned_files": len(current),
            "duration_s": round(duration_s, 3),
            "events": len(events),
            "high": sum(1 for e in events if e.severity == "high"),
            "medium": sum(1 for e in events if e.severity == "medium"),
            "low": sum(1 for e in events if e.severity == "low"),
        },
        "events": [
            {
                "type": e.type,
                "severity": e.severity,
                "file_key": e.file_key,
                "path": e.path,
                "old_path": e.old_path,
                "new_path": e.new_path,
                "details": e.details or {},
            }
            for e in events
        ],
    }

    # Print JSON for n8n to consume
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
