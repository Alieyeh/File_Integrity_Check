# TRE Deployment Notes

This package is designed to run in a trusted research environment with no
direct internet access. Runtime code uses only the Python standard library.

## Offline Installation

Preferred route:

1. Build or approve a wheel outside the TRE.
2. Transfer the wheel through the normal software approval process.
3. Install it inside the TRE with pip:

```powershell
python -m pip install file_integrity_monitor-0.1.0-py3-none-any.whl --no-index
```

If installing from an approved source folder:

```powershell
python -m pip install . --no-index --no-build-isolation
```

## Exclusions File

Create `config\exclude_dirs.txt` from `config\exclude_dirs.example.txt`.

Non-coders can add one folder name per line:

```text
Drafts
TempUploads
DoNotScan
```

Blank lines and lines beginning with `#` are ignored. Matching is by exact
directory name anywhere under the scan root.

Advanced maintainers can also add full subtree exclusions:

```text
prefix: S:\A\Whole\Subtree\To\Skip
```

## Weekly Monday Morning Run

Use the portal scheduler where available. For Windows Task Scheduler, configure:

```text
Trigger: Weekly, Monday, 09:00
Program/script: C:\Path\To\Project\.venv\Scripts\file-watch.exe
Arguments: run --root "S:\" --max-workers 6 --no-hash-new-files --exclude-file ".\config\exclude_dirs.txt"
Start in: C:\Alieyeh\project\file_check
```

For environments that prefer a long-running Python process:

```powershell
file-watch weekly --root "S:\" --weekday monday --time 09:00 --max-workers 6 --no-hash-new-files --exclude-file ".\config\exclude_dirs.txt"
```

Check the next scheduled run without scanning:

```powershell
file-watch weekly --root "S:\" --weekday monday --time 09:00 --dry-run
```

## Data Handling

The SQLite database and reports can include sensitive paths, filenames,
fingerprints, and event details. Store these under the portal's approved secure
storage location and include the SQLite sidecar files in retention/backups:

- `file_watch_state.sqlite3`
- `file_watch_state.sqlite3-wal`
- `file_watch_state.sqlite3-shm`

## Storage Efficiency

The database is designed to stay small enough for controlled portal storage:

- the current file state table stores one row per tracked file path
- the current directory state table stores one row per tracked directory path,
  including empty directories
- fingerprint history is deduplicated by path and fingerprint
- repeated observations update `seen_count` instead of adding duplicate rows
- `--history-retention-per-path 5` keeps the latest five unique fingerprints
  per path by default
- `--history-retention-per-path 0` disables pruning when a full history is
  required by policy
- saved JSON is compact by default; detailed event evidence remains in CSV and
  HTML reports

For very large roots, prefer:

```powershell
file-watch run --root "S:\" --no-hash-new-files --history-retention-per-path 5 --json-detail compact
```

With `--no-hash-new-files`, new files and files with missing fingerprints remain
metadata-only on later observations. The scanner increments the current
`seen_count` for the file path instead of opening large files just to backfill a
fingerprint. Run a separate maintenance pass with `--hash-new-files` only when
the TRE has approved the I/O cost of fingerprint backfill.

Exact version reversion detection requires historical fingerprints. Metadata-
only files are counted as `reversion_unprotected_files` in JSON and in the human
report. To reduce that blind spot without hashing huge files, the scanner keeps
compact metadata history. If a metadata-only file returns to a previously
observed size and modified timestamp, the run emits a high
`possible_metadata_reverted` event. If only the size returns to a previously
observed value, the run emits a medium lower-confidence
`possible_metadata_reverted` event. Other metadata-only size or timestamp
changes emit a medium `metadata_changed` event.

Directories use the same approximation idea. If a directory returns to a
previously observed modified timestamp and immediate child-file/child-directory
count, the run emits a high `possible_directory_metadata_reverted` event. If
only the immediate child-count shape returns, it emits a medium lower-confidence
`possible_directory_metadata_reverted` event.

## Human Reports

The workflow writes offline HTML reports with no external assets or internet
dependencies:

- `reports\HUMAN_latest.html`
- `reports\human\run_<run_id>.html`
- `reports\events\events_<run_id>.csv`
- `reports\STATUS_latest.html`
- `reports\status\STATUS_<run_id>.html`
- `reports\ALERT_latest.html`
- `reports\alerts\ALERT_<run_id>.html`
- `reports\errors\error_<date>.html`

The `*_latest` files are convenience shortcuts only. For weekly audit and
retention, use the run-specific files containing `<run_id>`.
Legacy top-level `reports\events_*.csv` files are moved into `reports\events`
automatically on the next scan.
If the report directory does not exist, `file-watch run` creates the report root
and standard subfolders: `events`, `human`, `status`, `alerts`, `archive`, and
`errors`.

The HTML report uses a soft violet/lavender visual theme outside of the alert
colors. It includes a lay summary, severity color coding, event mix bars,
action-likelihood bars, direct directory events, directory-level signals, and a
prioritised event review table. It is designed to be opened inside a secure
portal without external web access.

The likelihood fields are evidence signals, not proof of intent. They should be
reviewed with the data owner or portal audit trail before concluding whether an
action was accidental or intentional.

Likely same-folder renames are low review items. Likely moves and likely moved-
and-renamed files are medium review items, not high-risk alerts. A rename means
the same folder but a different file name; a move means the same file name in a
different folder/location. If both folder and file name change, the report
labels it as moved and renamed. Direct directory disappearance is also tracked,
including empty directories. Likely file or directory deletion/unavailability
remains high risk. All version reversions are extremely high risk and are
prioritised above deletion/unavailability.
