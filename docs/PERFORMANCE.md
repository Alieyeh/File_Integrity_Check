# Performance Guide

The most important performance constraint is filesystem I/O, especially on a
remote research share. The scanner therefore avoids a second pre-count walk and
collects file and directory metadata together in one traversal.

## Implemented Optimizations

| Optimization | Effect |
| --- | --- |
| `os.scandir` traversal | Uses directory-entry metadata efficiently |
| Early directory pruning | Excluded subtrees are never entered |
| Single metadata traversal | Files and directories are collected together |
| Metadata-first mode | `--no-hash-new-files` avoids opening large new files |
| Sampled large-file fingerprints | Hashing reads the first and last sample rather than a multi-TB file |
| Parallel fingerprint jobs | `--max-workers` overlaps independent file reads |
| Batched SQLite upserts | Reduces Python-to-SQLite calls for large baselines |
| One baseline transaction | Avoids repeated disk syncs and prevents partial state |
| Deduplicated bounded history | Controls long-term database growth |
| Compact JSON | Detailed evidence stays in CSV/HTML without duplicating every event in JSON |
| Throttled progress output | Avoids terminal writes for every file |

## Recommended Large-TRE Command

```powershell
python .\file_check.py `
  --root "S:\Research Data" `
  --db "C:\Approved State\file_watch_state.sqlite3" `
  --outdir "C:\Approved Reports" `
  --no-hash-new-files `
  --exclude-file ".\config\exclude_dirs.txt" `
  --history-retention-per-path 5
```

Quote every path that may contain spaces. PowerShell passes each quoted value as
one argument; the application then uses `pathlib`, `os.scandir`, and parameterized
SQLite statements, so spaces in paths and filenames are supported.

## Tuning Priorities

1. Use `--no-hash-new-files` for the routine weekly scan. This has a much larger
   effect than changing worker count when most files do not need hashing.
2. Exclude approved archives, generated output, and irrelevant subtrees as high
   in the directory tree as possible.
3. Put the SQLite database and reports on an approved fast local or low-latency
   volume. Do not place them inside the scanned root.
4. Keep the default history retention unless audit requirements need more.
   Retaining every historical state increases database and pruning work.
5. Tune `--max-workers` only for approved fingerprint passes. More workers can
   reduce performance on a constrained share by creating competing reads.
6. Schedule scans outside peak research activity and avoid concurrent runs that
   write to the same database.
7. Review `stats.duration_s`, `scanned_files`, and `hashed_files` over several
   weekly runs before changing settings.

## Progress Accuracy

During discovery, the scanner must find a file before it can count it. A
pre-count would traverse the whole tree twice, so the normal progress bar uses
the previous baseline count as an estimate. It shows `~` before the total while
estimated. On a first baseline it shows the live checked count with an unknown
percentage, then becomes exact when discovery finishes.

Hashing, comparison, saving, and final completion use known totals. Use
`--no-progress` for scheduled tasks or when terminal output is not wanted.
Progress is automatically suppressed when standard error is not an interactive
terminal.

## Possible Future Optimizations

These should be benchmarked before implementation:

- **Path dictionary normalization:** store directory and filename IDs to reduce
  repeated path text. This can save space but adds joins and migration risk.
- **Platform change journal integration:** Windows USN journal or filesystem
  snapshots could avoid full walks, but reduce portability and require elevated
  platform-specific trust.
- **Partitioned roots:** independent databases per approved top-level root can
  reduce one-run memory and make schedules parallelizable.
- **Database maintenance window:** periodic `PRAGMA optimize` and carefully
  approved `VACUUM` can reclaim space after major retention reductions.
- **Targeted fingerprint policy:** fingerprint only high-value extensions or
  approved directories. This needs an explicit policy model so coverage remains
  visible in reports.

The safest next optimization is usually better exclusions, followed by
partitioning genuinely independent roots. Both reduce work without weakening
the evidence collected for files that remain in scope.

