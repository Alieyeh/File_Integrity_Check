# Migration From n8n

This project replaces the exported n8n workflow at
`reports/workflow/FileIntegrityCheckWorkflow.json` with Python code.

## Node Mapping

| n8n node | Python replacement |
| --- | --- |
| Schedule Trigger | `file-watch schedule` or Windows Task Scheduler |
| Execute Command | `file_integrity_monitor.scanner.scan_files` |
| Code in JavaScript | `file_integrity_monitor.pipeline.build_ops_report` and payload enrichment |
| If `$json.ok` | exception handling in `run_pipeline` |
| If `$json.stats.high > 0` | critical/high-event branch in `run_pipeline` |
| Convert to File | atomic text, HTML, or JSON writers |
| Read/Write Files from Disk | `reports`, `reports/alerts`, `reports/archive`, and `reports/errors` outputs |

## Equivalent Commands

Old scanner command inside n8n:

```powershell
cmd /c python ".\watch_s_drive.py" --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files --latest-json ".\reports\latest.json"
```

Scanner-only Python command:

```powershell
python .\watch_s_drive.py --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files --latest-json ".\reports\latest.json"
```

Full workflow replacement:

```powershell
python .\file_check.py --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files
```

Installed console script:

```powershell
file-watch run --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files
```

With a non-coder editable exclusions file:

```powershell
file-watch run --root "<SCAN_ROOT>" --exclude-file ".\config\exclude_dirs.txt" --max-workers 6 --no-hash-new-files
```

## Behavior Notes

- Operational failures create `reports/errors/error_<date>.txt`.
- Operational failures also create `reports/errors/error_<date>.html`.
- Successful runs with no critical/high-severity events create `reports/STATUS_latest.txt`
  and `reports/STATUS_latest.html`, plus run-specific files in `reports/status`.
- Successful runs with critical/high-severity events create
  latest alert shortcuts and run-specific files in `reports/alerts`.
- Every successful workflow run creates `reports/HUMAN_latest.html` and
  `reports/human/run_<run_id>.html`.
- Event CSVs are written under `reports/events/events_<run_id>.csv`; older
  top-level `reports/events_*.csv` files are moved there automatically.
- Critical/high-severity runs are archived as `reports/archive/run_<run_id>.json`.
- `reports/latest.json` is written by the Python workflow with the enriched
  payload, including `ok`, `ops_report`, `full_json_text`, likelihood fields,
  and human report paths.
- Critical/high-severity findings do not fail the process by default, matching n8n's
  success branch. Add `--fail-on-high` when integrating with tooling that
  should treat critical/high events as a non-zero exit.
- Directories whose name starts with a number are skipped by default. Add
  `--include-numbered-dirs` to scan them.
- Extra excluded directory names can be maintained in a plain text file and
  passed with `--exclude-file`.
- For weekly Monday morning runs, use the portal scheduler or
  `file-watch weekly --weekday monday --time 09:00`.
- The human report includes alert levels, color-coded severity, action
  likelihood, intent signals, direct directory events, and directory-level
  missing-file patterns.
- Directory paths are baselined directly, so empty directory deletion can be
  reported without relying on missing-file inference.
- All version reversions are extremely high risk.
- Likely same-folder renames are low review items.
- Likely moves and likely moved-and-renamed files are medium review items, not high-risk alerts.
- Rename means same folder with a changed file name. Move means different
  folder/location. If both change, the event is labelled moved and renamed.
- Same-folder filename cleanups such as `draft 2.md` to `draft2.md` are detected
  as likely renames by comparing filename signatures.
- Fingerprint history is now deduplicated and retained per path with
  `--history-retention-per-path`, defaulting to five unique fingerprints.
- In `--no-hash-new-files` mode, files with missing fingerprints remain
  metadata-only on later observations instead of being opened for hash backfill.
  The current path `seen_count` records repeated observations.
- Metadata-only files are counted as `reversion_unprotected_files`; if their
  size or modified time changes, the scanner emits either
  `possible_metadata_reverted` when the change matches previous metadata history
  or medium `metadata_changed` when it does not. Exact reversion detection still
  requires historical fingerprints.
- Directory metadata history is also retained; matching previous directory
  mtime and child-count states emits `possible_directory_metadata_reverted`.
- Missing report folders are created by `file-watch run`, including `events`,
  `human`, `status`, `alerts`, `archive`, and `errors`.
- Saved JSON is compact by default with `--json-detail compact`; use
  `--json-detail full` to embed full event details in JSON.

## Rollback

The compatibility scanner wrapper remains available:

```powershell
python .\watch_s_drive.py --root "<SCAN_ROOT>" --max-workers 6 --no-hash-new-files --latest-json ".\reports\latest.json"
```

That command prints raw scan JSON and does not write workflow status, alert,
archive, or error reports.
