# File Integrity Monitor

Python-only replacement for the n8n file integrity workflow in
`reports/workflow/FileIntegrityCheckWorkflow.json`.

It preserves the workflow capabilities:

- scans a root folder recursively with directory exclusions
- keeps SQLite state between runs
- selectively fingerprints files with configurable hashing
- detects missing files, changed files, metadata-only changes, reverted content, and older mtimes
- writes per-run event CSV files
- writes `reports/latest.json`
- writes `reports/STATUS_latest.txt` when no critical/high-severity events are found
- writes dated alert files and archived run JSON when critical/high-severity events are found
- writes polished offline HTML reports with severity color coding and likelihood summaries
- writes dated error reports when the run fails
- can run once from the CLI or repeat on a Python scheduler loop
- skips folders whose name starts with a number by default
- can read extra excluded directory names from a simple text file
- deduplicates fingerprint history and keeps compact JSON reports by default

The implementation uses only the Python standard library at runtime.

## Requirements

- Python 3.10 or newer
- Windows, macOS, or Linux. The defaults are tuned for Windows shares.

Check that Python is visible:

```powershell
python --version
```

If Windows cannot find `python`, install Python from
[python.org](https://www.python.org/downloads/windows/) and enable
"Add python.exe to PATH", or use the Python Launcher command `py`.

## Quick Start

From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Run the complete workflow once:

```powershell
file-watch run --root "S:\" --max-workers 6 --no-hash-new-files
```

Or use the compatibility wrapper without installing the package:

```powershell
python .\file_check.py --root "S:\" --max-workers 6 --no-hash-new-files
```

Run only the scanner, matching the old n8n Execute Command step:

```powershell
python .\watch_s_drive.py --root "S:\" --max-workers 6 --no-hash-new-files --latest-json ".\reports\latest.json"
```

## Exclusions

By default, the scanner skips:

- any folder whose name starts with a number, such as `2023` or `1_old`
- common system/build folders such as `$RECYCLE.BIN`, `.git`, `node_modules`, `Archive`, and `Backups`
- the default full path prefixes `S:\Archive`, `S:\Backups`, and `S:\OldProjects`

Use `--include-numbered-dirs` if numbered folders should be scanned.

For non-coders, create a plain text file such as `config\exclude_dirs.txt`:

```text
# One directory name per line
Drafts
TempUploads
DoNotScan
```

Then run:

```powershell
file-watch run --root "S:\" --exclude-file ".\config\exclude_dirs.txt" --max-workers 6 --no-hash-new-files
```

The file also supports optional advanced lines:

```text
dir: ExactFolderName
prefix: S:\A\Whole\Subtree\To\Skip
```

## Output Files

The complete workflow writes:

| Path | When | Purpose |
| --- | --- | --- |
| `reports/latest.json` | every workflow run | latest machine-readable payload |
| `reports/HUMAN_latest.html` | every workflow run | convenience copy of the newest human report |
| `reports/human/run_<run_id>.html` | every workflow run | archived run-specific human report |
| `reports/events/events_<run_id>.csv` | every scan | flat event report |
| `reports/STATUS_latest.txt` | success with no critical/high events | operator status summary |
| `reports/STATUS_latest.html` | success with no critical/high events | visual status report |
| `reports/status/STATUS_<run_id>.txt` | success with no critical/high events | archived run-specific status summary |
| `reports/status/STATUS_<run_id>.html` | success with no critical/high events | archived run-specific visual status report |
| `reports/alerts/ALERT_<run_id>.txt` | success with critical/high events | archived run-specific alert report |
| `reports/alerts/ALERT_<run_id>.html` | success with critical/high events | archived run-specific visual alert report |
| `reports/ALERT_latest.txt` | success with critical/high events | easy-to-open latest alert |
| `reports/ALERT_latest.html` | success with critical/high events | easy-to-open latest visual alert |
| `reports/archive/run_<run_id>.json` | critical/high events by default | archived full JSON payload |
| `reports/errors/error_<date>.txt` | operational failure | error report |
| `reports/errors/error_<date>.html` | operational failure | visual error report |

The `*_latest` files are only convenience shortcuts. The durable weekly/audit
records are the run-specific files containing `<run_id>` in their names.
Older top-level `reports/events_*.csv` files are moved into `reports/events`
automatically on the next scan.
If the report directory does not exist, `file-watch run` creates the report root
and standard subfolders: `events`, `human`, `status`, `alerts`, `archive`, and
`errors`.

Extremely high-severity events are version reversions and are prioritised above
deletions. High-severity events are likely file or directory
deletion/unavailability. Medium review items are likely moves, likely moved-and-
renamed files or directories, and content changes. Low review items are likely
same-folder file renames and timestamp-only signals where mtimes went backwards.

## Alert Levels and Likelihoods

The human report has a clear alert banner:

- `Extremely High Risk`: version reversion, prioritised above deletion/unavailability
- `High Risk`: likely file or directory deletion/unavailability
- `Review`: likely move, likely moved-and-renamed, content changed, or metadata changed without fingerprint evidence; check against expected activity
- `Low`: likely same-folder rename or timestamp-only signal
- `Clear`: no alert-level integrity events detected

Each event includes:

- action likelihood, such as `Likely deleted or currently unavailable`, `Likely renamed`, `Likely moved`, `Likely moved and renamed`, or `Version reversion detected`
- action confidence, based on fingerprint or metadata evidence
- intent signal, such as `Indeterminate`, `Could be accidental or planned reorganisation`, or `More consistent with intentional or bulk action`
- target kind, so direct directory events and directory-level missing-file patterns stand out from single-file issues

Intent is never presented as proof. The tool uses filesystem evidence to
prioritise review, then the data owner, audit trail, or approved change record
should confirm what happened.

All version reversions are classified as extremely high risk.

Likely move/rename detection uses these definitions:

- `Likely renamed`: the file is still in the same folder, but the file name changed.
- `Likely moved`: the file name is the same, but the folder/location changed.
- `Likely moved and renamed`: both the folder/location and file name changed.

Moves are ranked higher than same-folder renames because a location change has
more operational impact. A same-folder rename is still recorded for review, but
it is low risk rather than a high alert.

The scanner uses fingerprint matches when available. It also checks same-folder
filename-equivalent changes, ignoring case, spaces, and punctuation, so
`draft 2.md` to `draft2.md` is treated as a likely rename.

Directories are baselined directly in SQLite. That means a removed directory can
be reported even when it was empty or contained too few files to create a
directory-level missing-file pattern. A directory rename or move is treated as a
medium review item rather than a high alert when the scan finds a plausible new
directory path. The scanner also keeps compact directory metadata history. If a
directory returns to a previously observed modified timestamp and immediate
child-file/child-directory count, it writes a high
`possible_directory_metadata_reverted` event. If only the immediate child-count
shape returns, it writes a medium lower-confidence
`possible_directory_metadata_reverted` event.

Exact version reversion detection requires historical fingerprints. When a file
is metadata-only, the scanner still keeps a compact metadata history. If the
file returns to a previously observed size and modified timestamp, the scanner
writes a high `possible_metadata_reverted` event. If it only returns to a
previously observed size, the scanner writes a medium lower-confidence
`possible_metadata_reverted` event. If its size or modified time changes without
matching previous metadata, the scanner writes a medium `metadata_changed` event
instead of silently accepting the change. The human report also shows
`Reversion unprotected`, which is the number of current files that do not yet
have fingerprint coverage.

## CLI

### Complete workflow

```powershell
file-watch run --root "S:\" [options]
```

Useful options:

```text
--db PATH                         SQLite state database
--outdir PATH                     report directory, default reports
--latest-json PATH                latest JSON path, default reports/latest.json for run
--hash-new-files                  fingerprint brand-new files and backfill missing fingerprints
--no-hash-new-files               store new or fingerprint-missing files without hashing them
--max-workers N                   hashing workers, default 6
--sample-bytes N                  bytes sampled from each end of large files
--history-retention-per-path N    unique fingerprints retained per path, default 5; 0 keeps all
--exclude-dir NAME                add an excluded directory name
--exclude-prefix PATH             add an excluded path subtree
--exclude-file PATH               read extra exclusions from a plain text file
--clear-default-exclusions        use only exclusions supplied on CLI
--include-numbered-dirs           do not skip directories beginning with a digit
--archive-policy high|always|never
--json-detail compact|full        compact saved JSON by default; CSV/HTML keep details
--fail-on-high                    return exit code 1 when critical/high events exist
```

### Scanner only

```powershell
file-watch scan --root "S:\" --latest-json ".\reports\latest.json"
```

`scan` prints the raw scan JSON and writes the events CSV. It does not write
status, alert, archive, or error files.

### Repeat without n8n

```powershell
file-watch schedule --root "S:\" --interval-seconds 3600 --max-workers 6 --no-hash-new-files
```

Use `--runs N` to stop after a fixed number of runs.

### Weekly Monday mornings

For a pure-Python long-running process:

```powershell
file-watch weekly --root "S:\" --weekday monday --time 09:00 --max-workers 6 --no-hash-new-files
```

To check the next scheduled run without scanning:

```powershell
file-watch weekly --root "S:\" --weekday monday --time 09:00 --dry-run
```

For a secure portal, a platform scheduler is usually preferable. On Windows,
configure Task Scheduler to run every Monday at 09:00 with:

```text
Program/script: C:\Path\To\Project\.venv\Scripts\file-watch.exe
Arguments: run --root "S:\" --max-workers 6 --no-hash-new-files --exclude-file ".\config\exclude_dirs.txt"
Start in: C:\Alieyeh\project\file_check
```

## Recommended First Run

For very large shares, start with:

```powershell
file-watch run --root "S:\" --no-hash-new-files --max-workers 6
```

That creates the initial path, directory, and metadata baseline quickly. Later
runs detect missing files and directories without backfilling missing
fingerprints. Files that have never been fingerprinted remain metadata-only
until you deliberately run with `--hash-new-files`.

If you need revert detection immediately for existing files, run a maintenance
baseline with:

```powershell
file-watch run --root "S:\" --hash-new-files --max-workers 6
```

This is more expensive because it fingerprints brand-new baseline files.
It also backfills fingerprints for files that were previously observed in
metadata-only mode.

## Storage Efficiency

SQLite storage is kept compact by default:

- `latest_by_path` stores one current row per tracked file path.
- `latest_directories` stores one current row per tracked directory path,
  including empty directories.
- `latest_by_path.seen_count` records how many times each current file path has
  been observed, even when the file remains metadata-only.
- `history_by_path` stores unique fingerprints per path instead of inserting a
  duplicate row every time the same fingerprint is seen again.
- `history_by_path.seen_count` records how many times a known fingerprint was
  observed.
- `metadata_history_by_path` stores compact unique size/mtime states per path so
  metadata-only runs can flag possible metadata reversion patterns without
  opening huge files.
- `directory_history_by_path` stores compact unique directory mtime and
  immediate child-count states so directory metadata reversion patterns can be
  flagged.
- In `--no-hash-new-files` mode, missing fingerprints are not treated as a
  reason to hash on the second or later observation. The JSON/report stats show
  `metadata_only_files`, `reversion_unprotected_files`, and
  `skipped_missing_fingerprint_hashes`.
- `--history-retention-per-path 5` keeps the latest five unique fingerprints per
  path by default. Use `0` to keep all historical fingerprints.
- Saved `latest.json` and archived run JSON use `--json-detail compact` by
  default. Detailed event data is still available in the CSV and HTML reports.
- Use `--json-detail full` when you explicitly need full event detail embedded
  in saved JSON.

## Windows Task Scheduler

After installing with `python -m pip install -e .`, create a task that runs:

```text
Program/script: C:\Path\To\Project\.venv\Scripts\file-watch.exe
Arguments: run --root "S:\" --max-workers 6 --no-hash-new-files
Start in: C:\Alieyeh\project\file_check
```

Set the trigger to weekly, Monday, 09:00 or the portal-approved morning window.

If you do not install the package, schedule the wrapper instead:

```text
Program/script: C:\Path\To\Python\python.exe
Arguments: C:\Alieyeh\project\file_check\file_check.py --root "S:\" --max-workers 6 --no-hash-new-files
Start in: C:\Alieyeh\project\file_check
```

## Tests

Run the test suite:

```powershell
python -m unittest discover -s tests
```

No external test dependencies are required.

## Migration From n8n

The old n8n command was:

```powershell
cmd /c python ".\watch_s_drive.py" --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files --latest-json ".\reports\latest.json"
```

The Python-only equivalent is:

```powershell
python .\file_check.py --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files
```

See [docs/MIGRATION_FROM_N8N.md](docs/MIGRATION_FROM_N8N.md) for the node-by-node mapping.

For locked-down portal deployment notes, see [docs/TRE_DEPLOYMENT.md](docs/TRE_DEPLOYMENT.md).
