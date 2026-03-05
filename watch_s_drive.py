from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ----------------------------
# Config: exclusions (EDIT THESE)
# ----------------------------

# Exclude any directory whose *name* begins with a digit (e.g. "2023", "1_old")
EXCLUDE_DIRS_STARTING_WITH_DIGIT = True

# Exclude these directory names anywhere in the tree
EXCLUDED_DIR_NAMES: Set[str] = {
    "System Volume Information",
    "$RECYCLE.BIN",
    "__pycache__",
    ".git",
    "node_modules",
    "Temp",
    "Archive",
    "Backups",
}

# Exclude these full path prefixes (entire subtrees). Use absolute-like form for your environment.
# Tip: keep them normalized with backslashes (Windows) and no trailing slash.
EXCLUDED_PATH_PREFIXES: List[str] = [
    r"S:\Archive",
    r"S:\Backups",
    r"S:\OldProjects",
]


# ----------------------------
# Models
# ----------------------------

@dataclass(frozen=True)
class FileMeta:
    """Cheap metadata for one file."""
    path: str
    size: int
    mtime_utc: int


@dataclass(frozen=True)
class FileState:
    """Stored state for a file identity."""
    file_key: str           # identity key (prefer file_id; else FP-based)
    path: str
    size: int
    mtime_utc: int
    fingerprint: Optional[str]  # may be NULL if not computed
    file_id: Optional[str]      # optional; may be NULL


@dataclass(frozen=True)
class Event:
    type: str
    severity: str
    file_key: str
    path: Optional[str] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    details: Optional[dict] = None


# ----------------------------
# Utility
# ----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_path(p: str) -> str:
    # Keep Windows style; normalize case to reduce churn on Windows
    # (If your share is case-sensitive, remove normcase)
    return os.path.normcase(os.path.abspath(p))


def normalize_prefix(p: str) -> str:
    return normalize_path(p).rstrip("\\/")


# Pre-normalize excluded prefixes once for speed
_EXCLUDED_PREFIXES_NORM = [normalize_prefix(p) for p in EXCLUDED_PATH_PREFIXES]


def should_exclude_dir(dir_name: str, full_dir_path: str) -> bool:
    """
    Decide whether to exclude a directory from traversal.

    Args:
        dir_name: Directory name only (no path).
        full_dir_path: Full path to the directory.

    Returns:
        True if excluded, else False.
    """
    if EXCLUDE_DIRS_STARTING_WITH_DIGIT and dir_name and dir_name[0].isdigit():
        return True

    if dir_name in EXCLUDED_DIR_NAMES:
        return True

    # Full path subtree exclusions
    norm_full = normalize_prefix(full_dir_path)
    for pref in _EXCLUDED_PREFIXES_NORM:
        # Ensure we only exclude subtree, not unrelated prefix collisions:
        # e.g. S:\ArchiveX shouldn't match S:\Archive
        if norm_full == pref or norm_full.startswith(pref + os.sep):
            return True

    return False


# ----------------------------
# Fast tree traversal using scandir
# ----------------------------

def iter_files_scandir(root: str) -> Iterator[FileMeta]:
    """
    Recursively yields file metadata under root, pruning excluded directories early.

    This is usually faster than os.walk on large trees.

    Args:
        root: Root directory path.

    Yields:
        FileMeta entries.
    """
    stack = [root]
    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            full = entry.path
                            if not should_exclude_dir(entry.name, full):
                                stack.append(full)
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            yield FileMeta(
                                path=normalize_path(entry.path),
                                size=int(st.st_size),
                                mtime_utc=int(st.st_mtime),
                            )
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue


# ----------------------------
# Fingerprinting (only when needed)
# ----------------------------

def compute_fingerprint(
    path: str,
    size: int,
    *,
    algo: str = "sha256",
    sample_bytes: int = 1024 * 1024,
) -> str:
    """
    Compute a content fingerprint.

    For large files: hash = sha256(size + first N bytes + last N bytes).
    For small files (<= 2N): hash entire file.

    Args:
        path: File path.
        size: File size bytes.
        algo: Hash algorithm for hashlib.
        sample_bytes: Sampling size.

    Returns:
        Hex digest string.
    """
    h = hashlib.new(algo)
    h.update(str(size).encode("utf-8"))
    try:
        with open(path, "rb") as f:
            if size <= 2 * sample_bytes:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            else:
                h.update(f.read(sample_bytes))
                f.seek(max(0, size - sample_bytes))
                h.update(f.read(sample_bytes))
    except (OSError, PermissionError):
        h.update(b"UNREADABLE")
    return h.hexdigest()


# ----------------------------
# SQLite state
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

-- latest state keyed by path for speed (since file_id may not be stable on SMB)
-- also store fingerprint when computed
CREATE TABLE IF NOT EXISTS latest_by_path (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime_utc INTEGER NOT NULL,
    fingerprint TEXT,
    last_seen_run_id TEXT NOT NULL
);

-- fingerprint history by path to detect "reverted to older state"
CREATE TABLE IF NOT EXISTS history_by_path (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    mtime_utc INTEGER NOT NULL,
    size INTEGER NOT NULL,
    run_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hist_path_fp ON history_by_path(path, fingerprint);
"""


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_SQL)
    return conn


def load_latest_by_path(conn: sqlite3.Connection) -> Dict[str, FileState]:
    cur = conn.cursor()
    cur.execute("SELECT path, size, mtime_utc, fingerprint FROM latest_by_path")
    out: Dict[str, FileState] = {}
    for path, size, mtime_utc, fp in cur.fetchall():
        out[path] = FileState(
            file_key=path,   # path-keyed design for speed in huge trees
            path=path,
            size=int(size),
            mtime_utc=int(mtime_utc),
            fingerprint=fp,
            file_id=None,
        )
    return out


def fingerprint_seen_before(conn: sqlite3.Connection, path: str, fingerprint: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM history_by_path WHERE path = ? AND fingerprint = ? LIMIT 1",
        (path, fingerprint),
    )
    return cur.fetchone() is not None


def persist_run(conn: sqlite3.Connection, run_id: str, started_at_utc: str, root: str, scanned_count: int, duration_s: float) -> None:
    conn.execute(
        "INSERT INTO runs(run_id, started_at_utc, root, scanned_count, duration_s) VALUES(?,?,?,?,?)",
        (run_id, started_at_utc, root, int(scanned_count), float(duration_s)),
    )
    conn.commit()


def upsert_latest_and_history(
    conn: sqlite3.Connection,
    run_id: str,
    items: List[Tuple[str, int, int, Optional[str]]],
) -> None:
    """
    Persist latest_by_path and history_by_path for entries that have a fingerprint.

    Args:
        items: list of (path, size, mtime_utc, fingerprint_or_None)
    """
    cur = conn.cursor()
    for path, size, mtime_utc, fp in items:
        cur.execute(
            """
            INSERT INTO latest_by_path(path, size, mtime_utc, fingerprint, last_seen_run_id)
            VALUES(?,?,?,?,?)
            ON CONFLICT(path) DO UPDATE SET
                size=excluded.size,
                mtime_utc=excluded.mtime_utc,
                fingerprint=COALESCE(excluded.fingerprint, latest_by_path.fingerprint),
                last_seen_run_id=excluded.last_seen_run_id
            """,
            (path, size, mtime_utc, fp, run_id),
        )

        if fp is not None:
            cur.execute(
                "INSERT INTO history_by_path(path, fingerprint, mtime_utc, size, run_id) VALUES(?,?,?,?,?)",
                (path, fp, mtime_utc, size, run_id),
            )
    conn.commit()


# ----------------------------
# Diff + selective hashing
# ----------------------------

def plan_hash_jobs(
    previous: Dict[str, FileState],
    current_meta: Dict[str, FileMeta],
) -> List[Tuple[str, int]]:
    """
    Decide which files need fingerprinting this run.

    Rule: fingerprint only if size or mtime changed, or if no prior fingerprint exists.

    Args:
        previous: previous states keyed by path
        current_meta: current metadata keyed by path

    Returns:
        List of (path, size) to fingerprint.
    """
    jobs: List[Tuple[str, int]] = []
    for path, meta in current_meta.items():
        old = previous.get(path)
        if old is None:
            # new file: fingerprinting optional. Usually you do it only if you care about revert later.
            # We'll fingerprint new files if they are not gigantic, but we can't know without size. We'll still allow it.
            jobs.append((path, meta.size))
        else:
            if meta.size != old.size or meta.mtime_utc != old.mtime_utc or old.fingerprint is None:
                jobs.append((path, meta.size))
    return jobs


def run_hash_jobs(
    jobs: List[Tuple[str, int]],
    *,
    algo: str,
    sample_bytes: int,
    max_workers: int,
) -> Dict[str, str]:
    """
    Compute fingerprints in parallel.

    Args:
        jobs: list of (path, size)
        algo: hash algorithm
        sample_bytes: sample size
        max_workers: thread count

    Returns:
        dict path -> fingerprint
    """
    results: Dict[str, str] = {}
    if not jobs:
        return results

    # For I/O-heavy hashing, threads are usually fine; keep workers modest to avoid trashing the share.
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(compute_fingerprint, path, size, algo=algo, sample_bytes=sample_bytes): path
            for path, size in jobs
        }
        for fut in as_completed(futs):
            path = futs[fut]
            try:
                results[path] = fut.result()
            except Exception:
                # If hashing fails unexpectedly, skip fingerprint for that file.
                continue
    return results


def diff(
    conn: sqlite3.Connection,
    previous: Dict[str, FileState],
    current_meta: Dict[str, FileMeta],
    current_fp: Dict[str, str],
) -> List[Event]:
    """
    Produce events based on previous state, current metadata, and selective fingerprints.

    Key signals:
    - missing: path existed previously but not now
    - mtime_went_back: mtime decreased
    - changed: fingerprint changed to new value
    - reverted: fingerprint matches an older historical fingerprint for this path

    Args:
        conn: SQLite connection
        previous: previous states keyed by path
        current_meta: current metadata keyed by path
        current_fp: fingerprints keyed by path (only for planned jobs)

    Returns:
        list of Events
    """
    events: List[Event] = []

    prev_paths = set(previous.keys())
    cur_paths = set(current_meta.keys())

    missing_paths = prev_paths - cur_paths
    for p in missing_paths:
        events.append(Event(
            type="missing",
            severity="high",
            file_key=p,
            old_path=p,
            details={"last_size": previous[p].size, "last_mtime_utc": previous[p].mtime_utc},
        ))

    common_paths = prev_paths & cur_paths
    for p in common_paths:
        old = previous[p]
        newm = current_meta[p]

        if newm.mtime_utc < old.mtime_utc:
            events.append(Event(
                type="mtime_went_back",
                severity="low",
                file_key=p,
                path=p,
                details={"old_mtime_utc": old.mtime_utc, "new_mtime_utc": newm.mtime_utc},
            ))

        # Only evaluate fingerprint if we computed one this run
        new_fp = current_fp.get(p)
        if new_fp is not None:
            old_fp = old.fingerprint
            if old_fp is not None and new_fp != old_fp:
                if fingerprint_seen_before(conn, p, new_fp):
                    events.append(Event(
                        type="reverted",
                        severity="high",
                        file_key=p,
                        path=p,
                        details={"old_fp": old_fp, "new_fp": new_fp},
                    ))
                else:
                    events.append(Event(
                        type="changed",
                        severity="medium",
                        file_key=p,
                        path=p,
                        details={"old_fp": old_fp, "new_fp": new_fp},
                    ))

    # new files (optional)
    # new_paths = cur_paths - prev_paths

    return events


# ----------------------------
# Reporting
# ----------------------------

def write_events_csv(events: List[Event], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "severity", "path", "old_path", "new_path", "details_json"])
        for e in events:
            w.writerow([
                e.type,
                e.severity,
                e.path or "",
                e.old_path or "",
                e.new_path or "",
                json.dumps(e.details or {}, ensure_ascii=False),
            ])


# ----------------------------
# Main
# ----------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="High-performance offline file watcher for huge trees.")
    p.add_argument("--root", required=True, help=r'Root, e.g. S:\')
    p.add_argument("--db", default="", help="SQLite db path (default: alongside script)")
    p.add_argument("--outdir", default="reports", help="Report output directory")
    p.add_argument("--algo", default="sha256", help="Hash algorithm")
    p.add_argument("--sample-bytes", type=int, default=1024 * 1024, help="Partial hash sample bytes (default 1MiB)")
    p.add_argument("--max-workers", type=int, default=6, help="Thread workers for hashing (keep modest for shares)")
    p.add_argument("--no-hash-new-files", action="store_true", help="Skip hashing brand-new files")
    args = p.parse_args(argv)

    root = args.root
    if not os.path.exists(root):
        print(json.dumps({"error": f"Root does not exist: {root}"}, ensure_ascii=False))
        return 2

    script_dir = Path(__file__).resolve().parent
    db_path = Path(args.db).resolve() if args.db else (script_dir / "file_watch_state.sqlite3")
    outdir = (Path(args.outdir).resolve() if Path(args.outdir).is_absolute() else (script_dir / args.outdir))
    outdir.mkdir(parents=True, exist_ok=True)

    run_id = utc_now_iso().replace(":", "").replace("-", "")
    started_at = utc_now_iso()
    t0 = time.time()

    conn = open_db(db_path)
    previous = load_latest_by_path(conn)

    # Scan metadata only (fast)
    current_meta: Dict[str, FileMeta] = {}
    for meta in iter_files_scandir(root):
        current_meta[meta.path] = meta

    # Decide what to hash
    jobs = plan_hash_jobs(previous, current_meta)
    if args.no_hash_new_files:
        jobs = [(p, sz) for (p, sz) in jobs if p in previous]

    # Hash selectively + in parallel
    current_fp = run_hash_jobs(
        jobs,
        algo=args.algo,
        sample_bytes=args.sample_bytes,
        max_workers=args.max_workers,
    )

    # Diff (needs DB history for revert detection)
    events = diff(conn, previous, current_meta, current_fp)

    duration_s = time.time() - t0
    persist_run(conn, run_id, started_at, normalize_path(root), len(current_meta), duration_s)

    # Persist latest/history:
    # We always upsert metadata; fingerprint only if computed this run.
    persist_items: List[Tuple[str, int, int, Optional[str]]] = []
    for path, meta in current_meta.items():
        persist_items.append((path, meta.size, meta.mtime_utc, current_fp.get(path)))
    upsert_latest_and_history(conn, run_id, persist_items)
    conn.close()

    # Write report files
    events_csv = outdir / f"events_{run_id}.csv"
    write_events_csv(events, events_csv)

    summary = {
        "run_id": run_id,
        "started_at_utc": started_at,
        "root": normalize_path(root),
        "db": str(db_path),
        "reports": {"events_csv": str(events_csv)},
        "stats": {
            "scanned_files": len(current_meta),
            "hashed_files": len(current_fp),
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
                "path": e.path,
                "old_path": e.old_path,
                "new_path": e.new_path,
                "details": e.details or {},
            }
            for e in events
        ],
    }

    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
