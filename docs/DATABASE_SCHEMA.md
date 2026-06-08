# Database Schema

The monitor stores its durable state in SQLite. Paths are normalized absolute
paths and remain whole strings so comparisons, move/rename evidence, exports,
and migration from the original workflow stay straightforward.

## Entity Relationship Diagram

```mermaid
erDiagram
    RUNS {
        string run_id PK
        string started_at_utc
        string root
        int scanned_count
        float duration_s
    }

    LATEST_BY_PATH {
        string path PK
        int size
        int mtime_utc
        string fingerprint "nullable"
        string last_seen_run_id
        string first_seen_run_id "nullable"
        int seen_count
    }

    HISTORY_BY_PATH {
        int id PK
        string path
        string fingerprint
        int mtime_utc
        int size
        string run_id
        string first_seen_run_id "nullable"
        int seen_count
    }

    METADATA_HISTORY_BY_PATH {
        int id PK
        string path
        int size
        int mtime_utc
        string run_id
        string first_seen_run_id "nullable"
        int seen_count
    }

    LATEST_DIRECTORIES {
        string path PK
        int mtime_utc
        int child_files
        int child_dirs
        string last_seen_run_id
    }

    DIRECTORY_HISTORY_BY_PATH {
        int id PK
        string path
        int mtime_utc
        int child_files
        int child_dirs
        string run_id
        string first_seen_run_id "nullable"
        int seen_count
    }

    RUNS ||--o{ LATEST_BY_PATH : "last or first observed in"
    RUNS ||--o{ HISTORY_BY_PATH : "records fingerprint state"
    RUNS ||--o{ METADATA_HISTORY_BY_PATH : "records metadata state"
    RUNS ||--o{ LATEST_DIRECTORIES : "last observed in"
    RUNS ||--o{ DIRECTORY_HISTORY_BY_PATH : "records directory state"
    LATEST_BY_PATH ||--o{ HISTORY_BY_PATH : "path has fingerprint history"
    LATEST_BY_PATH ||--o{ METADATA_HISTORY_BY_PATH : "path has metadata history"
    LATEST_DIRECTORIES ||--o{ DIRECTORY_HISTORY_BY_PATH : "path has directory history"
```

> [!NOTE]
> These are logical relationships. SQLite foreign-key constraints are not
> declared because historical rows intentionally remain useful after a path
> disappears from the latest baseline.

## Tables

| Table | Cardinality | Purpose |
| --- | --- | --- |
| `runs` | one row per completed scan | Audit identity, root, count, and elapsed scan time |
| `latest_by_path` | at most one row per file path | Current file baseline |
| `history_by_path` | bounded unique fingerprints per file path | Exact content change and reversion evidence |
| `metadata_history_by_path` | bounded unique size/mtime states per file path | Metadata-only reversion approximation |
| `latest_directories` | at most one row per directory path | Current directory baseline, including empty directories |
| `directory_history_by_path` | bounded unique directory states per path | Directory metadata reversion approximation |

## Identity And Uniqueness

- `latest_by_path.path` and `latest_directories.path` are primary keys.
- fingerprint history is unique on `(path, fingerprint)`.
- file metadata history is unique on `(path, size, mtime_utc)`.
- directory history is unique on
  `(path, mtime_utc, child_files, child_dirs)`.
- repeated observations increment `seen_count` instead of creating duplicate
  history rows.
- history retention defaults to five unique states per path.

## Transaction Behavior

A completed baseline is persisted with batched SQLite upserts inside one
transaction. If scanning, hashing, comparison, or persistence fails, the new
baseline is not committed. Report-write failures are described separately
because they can occur after the database transaction has completed.

## Why Paths Are Not Split

Splitting every path into directory and filename entities could reduce repeated
text in very large databases, but it would add joins to the hottest comparison
and reporting paths and require a disruptive migration. The current model keeps
path identity explicit and predictable. A future normalized path dictionary
would be reasonable only after measuring the real database size and query cost
on representative TRE data.

