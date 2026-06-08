from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .config import ExclusionConfig, PipelineSettings, ScanSettings
from .pipeline import run_pipeline
from .progress import ProgressCallback, TerminalProgress
from .scanner import ScanError, scan_files
from .scheduling import next_weekly_run, parse_time_of_day, parse_weekday


def _add_common_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True, help="Root directory to scan, for example S:\\")
    parser.add_argument("--db", default="file_watch_state.sqlite3", help="SQLite state database path.")
    parser.add_argument("--outdir", default="reports", help="Directory for reports and CSV output.")
    parser.add_argument("--latest-json", default=None, help="Write the latest JSON payload to this path.")
    parser.add_argument("--algo", default="sha256", help="Hash algorithm supported by hashlib.")
    parser.add_argument("--sample-bytes", type=int, default=1024 * 1024, help="Sample size for large-file hashing.")
    parser.add_argument("--max-workers", type=int, default=6, help="Thread workers for fingerprinting.")
    parser.add_argument("--history-retention-per-path", type=int, default=5, help="Keep this many unique fingerprints per path; 0 keeps all.")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Extra directory name to exclude.")
    parser.add_argument("--exclude-prefix", action="append", default=[], help="Extra full path prefix to exclude.")
    parser.add_argument("--exclude-file", action="append", default=[], help="Plain text file of extra directory names to skip.")
    parser.add_argument("--clear-default-exclusions", action="store_true", help="Use only exclusions passed on the CLI.")
    parser.add_argument("--include-numbered-dirs", action="store_true", help="Do not skip directories beginning with a digit.")
    parser.add_argument("--no-progress", action="store_true", help="Disable the interactive terminal progress bar.")

    hash_group = parser.add_mutually_exclusive_group()
    hash_group.add_argument("--hash-new-files", dest="hash_new_files", action="store_true", help="Fingerprint new files and backfill missing fingerprints.")
    hash_group.add_argument("--no-hash-new-files", dest="hash_new_files", action="store_false", help="Store new or fingerprint-missing files without hashing them.")


def _settings_from_args(
    args: argparse.Namespace,
    *,
    default_hash_new_files: bool,
    progress_callback: ProgressCallback | None = None,
) -> ScanSettings:
    """Build validated scan settings from parsed CLI arguments."""

    hash_new_files = args.hash_new_files
    if hash_new_files is None:
        hash_new_files = default_hash_new_files

    exclusions = ExclusionConfig.from_cli(
        clear_defaults=args.clear_default_exclusions,
        exclude_dirs=args.exclude_dir,
        exclude_prefixes=args.exclude_prefix,
        exclude_files=[Path(item) for item in args.exclude_file],
        include_numbered_dirs=args.include_numbered_dirs,
    )

    return ScanSettings(
        root=Path(args.root),
        db=Path(args.db),
        outdir=Path(args.outdir),
        latest_json=Path(args.latest_json) if args.latest_json else None,
        algo=args.algo,
        sample_bytes=args.sample_bytes,
        max_workers=args.max_workers,
        hash_new_files=hash_new_files,
        history_retention_per_path=args.history_retention_per_path,
        exclusions=exclusions,
        progress_callback=progress_callback,
    )


def _print_payload(payload: dict[str, object], *, indent: int | None) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=indent))


def build_parser() -> argparse.ArgumentParser:
    """Build the complete command-line parser."""

    parser = argparse.ArgumentParser(
        prog="file-watch",
        description="Python-only file integrity monitor and n8n workflow replacement.",
    )
    parser.add_argument("--version", action="version", version="file-integrity-monitor 0.1.0")

    subcommands = parser.add_subparsers(dest="command")

    run_parser = subcommands.add_parser("run", help="Run the complete workflow once.")
    _add_common_scan_options(run_parser)
    run_parser.set_defaults(hash_new_files=None)
    run_parser.add_argument("--archive-policy", choices=("high", "always", "never"), default="high")
    run_parser.add_argument("--json-detail", choices=("compact", "full"), default="compact", help="Use compact JSON outputs by default; CSV/HTML still contain event detail.")
    run_parser.add_argument("--fail-on-high", action="store_true", help="Return exit code 1 when critical or high severity events are found.")
    run_parser.add_argument("--no-root-alert-latest", action="store_true", help="Do not write reports/ALERT_latest.txt.")
    run_parser.add_argument("--json-indent", type=int, default=None, help="Pretty-print CLI JSON with this indent.")

    scan_parser = subcommands.add_parser("scan", help="Run only the scanner and write events CSV.")
    _add_common_scan_options(scan_parser)
    scan_parser.set_defaults(hash_new_files=None)
    scan_parser.add_argument("--json-indent", type=int, default=None, help="Pretty-print CLI JSON with this indent.")

    schedule_parser = subcommands.add_parser("schedule", help="Run the complete workflow repeatedly.")
    _add_common_scan_options(schedule_parser)
    schedule_parser.set_defaults(hash_new_files=None)
    schedule_parser.add_argument("--interval-seconds", type=float, default=3600.0, help="Delay between runs.")
    schedule_parser.add_argument("--runs", type=int, default=0, help="Stop after this many runs; 0 means forever.")
    schedule_parser.add_argument("--archive-policy", choices=("high", "always", "never"), default="high")
    schedule_parser.add_argument("--json-detail", choices=("compact", "full"), default="compact")
    schedule_parser.add_argument("--fail-on-high", action="store_true")
    schedule_parser.add_argument("--no-root-alert-latest", action="store_true")
    schedule_parser.add_argument("--json-indent", type=int, default=None)

    weekly_parser = subcommands.add_parser("weekly", help="Run the complete workflow once per week.")
    _add_common_scan_options(weekly_parser)
    weekly_parser.set_defaults(hash_new_files=None)
    weekly_parser.add_argument("--weekday", default="monday", help="Weekday to run, default monday.")
    weekly_parser.add_argument("--time", default="09:00", help="Local time to run in HH:MM, default 09:00.")
    weekly_parser.add_argument("--runs", type=int, default=0, help="Stop after this many runs; 0 means forever.")
    weekly_parser.add_argument("--archive-policy", choices=("high", "always", "never"), default="high")
    weekly_parser.add_argument("--json-detail", choices=("compact", "full"), default="compact")
    weekly_parser.add_argument("--fail-on-high", action="store_true")
    weekly_parser.add_argument("--no-root-alert-latest", action="store_true")
    weekly_parser.add_argument("--json-indent", type=int, default=None)
    weekly_parser.add_argument("--dry-run", action="store_true", help="Print the next run time and exit.")

    return parser


def _run_once(args: argparse.Namespace) -> int:
    progress = TerminalProgress(enabled=False if args.no_progress else None)
    try:
        scan_settings = _settings_from_args(
            args,
            default_hash_new_files=False,
            progress_callback=progress,
        )
    except (FileNotFoundError, ValueError) as exc:
        progress.fail(str(exc))
        _print_payload({"ok": False, "error": str(exc)}, indent=getattr(args, "json_indent", None))
        return 2
    if scan_settings.latest_json is None:
        scan_settings = replace(
            scan_settings,
            latest_json=Path(scan_settings.outdir) / "latest.json",
        )
    try:
        result = run_pipeline(
            PipelineSettings(
                scan=scan_settings,
                archive_policy=args.archive_policy,
                fail_on_high=args.fail_on_high,
                write_root_alert_latest=not args.no_root_alert_latest,
                json_detail=args.json_detail,
            )
        )
    except Exception as exc:
        message = f"Workflow failed before a report could be completed: {exc}"
        progress.fail(message)
        _print_payload({"ok": False, "error": message}, indent=args.json_indent)
        return 1

    if result.payload.get("ok"):
        progress.finish(int(result.payload.get("stats", {}).get("scanned_files", 0)))
    else:
        progress.fail(str(result.payload.get("error", "Workflow failed.")))
    _print_payload(result.payload, indent=args.json_indent)
    return result.exit_code


def _scan_once(args: argparse.Namespace) -> int:
    progress = TerminalProgress(enabled=False if args.no_progress else None)
    try:
        settings = _settings_from_args(
            args,
            default_hash_new_files=True,
            progress_callback=progress,
        )
    except (FileNotFoundError, ValueError) as exc:
        progress.fail(str(exc))
        _print_payload({"error": str(exc)}, indent=args.json_indent)
        return 2
    try:
        payload = scan_files(settings)
    except ScanError as exc:
        progress.fail(str(exc))
        _print_payload({"error": str(exc)}, indent=args.json_indent)
        return exc.exit_code
    except Exception as exc:
        message = f"Scan failed unexpectedly: {exc}"
        progress.fail(message)
        _print_payload({"error": message}, indent=args.json_indent)
        return 1
    progress.finish(int(payload.get("stats", {}).get("scanned_files", 0)))
    _print_payload(payload, indent=args.json_indent)
    return 0


def _schedule(args: argparse.Namespace) -> int:
    runs_completed = 0
    last_exit_code = 0

    while True:
        started = time.monotonic()
        last_exit_code = _run_once(args)
        runs_completed += 1

        if args.runs and runs_completed >= args.runs:
            return last_exit_code

        elapsed = time.monotonic() - started
        sleep_for = max(0.0, args.interval_seconds - elapsed)
        time.sleep(sleep_for)


def _weekly(args: argparse.Namespace) -> int:
    try:
        weekday = parse_weekday(args.weekday)
        at_time = parse_time_of_day(args.time)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    runs_completed = 0
    last_exit_code = 0

    while True:
        next_run = next_weekly_run(datetime.now().astimezone(), weekday=weekday, at_time=at_time)
        if args.dry_run:
            _print_payload(
                {
                    "next_run_local": next_run.isoformat(timespec="seconds"),
                    "weekday": args.weekday,
                    "time": args.time,
                },
                indent=args.json_indent,
            )
            return 0

        sleep_for = max(0.0, (next_run - datetime.now().astimezone()).total_seconds())
        time.sleep(sleep_for)
        last_exit_code = _run_once(args)
        runs_completed += 1

        if args.runs and runs_completed >= args.runs:
            return last_exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested CLI command and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    if args.command == "run":
        return _run_once(args)
    if args.command == "scan":
        return _scan_once(args)
    if args.command == "schedule":
        return _schedule(args)
    if args.command == "weekly":
        return _weekly(args)

    parser.error(f"Unknown command: {args.command}")
    return 2
