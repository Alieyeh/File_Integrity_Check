# File Integrity Check

A monitoring tool designed to detect **file deletions, rollbacks
(version reverts), and unexpected changes** in large directory trees.

This project was created to investigate cases where files on a shared
storage portal were:

-   reverting to older versions
-   disappearing unexpectedly
-   being modified without clear traceability

The system performs scheduled scans of a directory tree and records file
metadata and content fingerprints. Results are stored and compared
against previous runs to detect anomalies.

The system is designed to handle **very large multi‑terabyte directory
structures efficiently**.

------------------------------------------------------------------------

# Architecture

The system is composed of three main components:

1.  **Python Scanner**
2.  **n8n Workflow**
3.  **SQLite State Database**

The workflow is illustrated below.

![Workflow Diagram](n8n.jpg)

### Execution Flow

    n8n Schedule Trigger
            ↓
    Execute Command Node
            ↓
    Python Scanner (watch_s_drive.py)
            ↓
    JSON result printed to stdout
            ↓
    JavaScript Code Node parses output
            ↓
    Report files written to disk
            ↓
    Optional alerts for high severity events

------------------------------------------------------------------------

# What the Program Detects

The scanner detects the following events:

  -----------------------------------------------------------------------
  Event Type                          Description
  ----------------------------------- -----------------------------------
  **missing**                         A file previously present no longer
                                      exists

  **changed**                         File contents changed to a new
                                      version

  **reverted**                        File contents match an **older
                                      previously recorded version**

  **mtime_went_back**                 File modification timestamp moved
                                      backwards
  -----------------------------------------------------------------------

High severity alerts typically include:

-   deleted files
-   reverted file versions

------------------------------------------------------------------------

# Performance Design

The scanner is optimized for **very large file systems**.

Key performance techniques:

### Metadata-first scanning

The scanner initially collects only:

-   path
-   size
-   modification time

Hashing is performed **only when metadata indicates a change**.

### Partial hashing

Large files are hashed using:

    first N bytes + last N bytes + file size

instead of hashing the entire file.

### Parallel hashing

Hash calculations are executed using:

    --max-workers 6

This significantly speeds up scanning without overwhelming storage I/O.

### Directory pruning

Directories are excluded early during traversal to avoid unnecessary
scanning.

Examples:

-   directories starting with numbers
-   archive folders
-   system folders

------------------------------------------------------------------------

# Repository Structure

    project/
    │
    ├── watch_s_drive.py
    │     Python scanner
    │
    ├── reports/
    │     Output reports and latest run JSON
    │
    ├── n8n.png
    │     Workflow diagram
    │
    └── README.md

------------------------------------------------------------------------

# Installation

## Install Node.js

Download from:

https://nodejs.org/

## Install n8n

``` bash
npm install n8n -g
```

------------------------------------------------------------------------

# Running n8n

Set environment variables before starting.

PowerShell:

``` powershell
$env:NODES_EXCLUDE='[]'

$env:N8N_RESTRICT_FILE_ACCESS_TO="C:\...\project\file_check;C:\...\reports"

n8n start
```

Open the n8n interface:

    http://localhost:5678

------------------------------------------------------------------------

# Python Scanner Execution

Example command used in the **Execute Command** node:

``` bash
cmd /c python "C:\...\file_check\watch_s_drive.py" ^
    --root "C:\\" ^
    --max-workers 6 ^
    --no-hash-new-files ^
    --latest-json "C:\...\file_check\reports\latest.json"
```

### Arguments

  Argument                Description
  ----------------------- ------------------------------------------
  `--root`                Root directory to scan
  `--max-workers`         Number of threads used for hashing
  `--no-hash-new-files`   Skip hashing for newly discovered files
  `--latest-json`         Path where latest run summary is written

------------------------------------------------------------------------

# Output Files

### JSON summary

`reports/latest.json`

Contains:

-   run id
-   scan statistics
-   list of detected events

Example:

``` json
{
  "run_id": "2026-03-06T01-00",
  "root": "S:\\",
  "stats": {
    "scanned_files": 145233,
    "hashed_files": 431,
    "events": 2,
    "high": 1
  }
}
```

### CSV report

    events_<runid>.csv

Contains all detected events for the run.

------------------------------------------------------------------------

# Quick Start (5 Minute Setup)

1.  Install **Node.js**
2.  Install **n8n**

```{=html}
<!-- -->
```
    npm install n8n -g

3.  Clone this repository

```{=html}
<!-- -->
```
    git clone https://github.com/yourusername/file_integrity_check.git

4.  Start n8n

```{=html}
<!-- -->
```
    n8n start

5.  Open the n8n UI

```{=html}
<!-- -->
```
    http://localhost:5678

6.  Import the workflow and configure the **Execute Command node** to
    run:

```{=html}
<!-- -->
```
    python watch_s_drive.py --root "S:\" --max-workers 6 --no-hash-new-files --latest-json "reports/latest.json"

7.  Run the workflow manually once to verify output.

------------------------------------------------------------------------

# Troubleshooting

## S: Drive Not Found

If the script runs as a service or under n8n, the `S:\` mapped drive may
not exist.

Use the **UNC path instead**:

    \\server\share

Example:

    --root "\\server\share"

Mapped drives are tied to user sessions and may not be visible to
services.

------------------------------------------------------------------------

## n8n Cannot Access Files

If n8n cannot read or write files, check the environment variable:

    N8N_RESTRICT_FILE_ACCESS_TO

Example:

    $env:N8N_RESTRICT_FILE_ACCESS_TO="C:\project\file_check;C:\reports"

This restricts file access to specific directories for security.

------------------------------------------------------------------------

## Python Script Produces No Output

If the n8n node reports:

    ERROR: No stdout from Python run

Check:

-   Python path is correct
-   Script runs manually
-   Output JSON is printed to stdout

Test manually:

    python watch_s_drive.py --root "S:\"

------------------------------------------------------------------------

## Slow Scans

For very large file systems:

-   reduce hashing using

```{=html}
<!-- -->
```
    --no-hash-new-files

-   reduce worker threads

```{=html}
<!-- -->
```
    --max-workers 4

-   exclude archive directories

This greatly improves performance.

------------------------------------------------------------------------

# Use Cases

This system is useful for:

-   detecting silent data corruption
-   identifying unintended file version rollbacks
-   auditing large shared storage environments
-   monitoring research or production data directories

------------------------------------------------------------------------

# License

MIT License
