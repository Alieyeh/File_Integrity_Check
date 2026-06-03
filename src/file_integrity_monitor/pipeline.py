from __future__ import annotations

import json
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import PipelineSettings
from .reporting import alert_level, build_error_html_report, build_human_html_report
from .scanner import ScanError, scan_files


@dataclass(frozen=True)
class PipelineResult:
    payload: dict[str, Any]
    exit_code: int
    written_files: tuple[Path, ...]


REPORT_SUBDIRS = ("events", "human", "status", "alerts", "archive", "errors")


def _stats_value(payload: dict[str, Any], key: str, default: int = 0) -> int:
    stats = payload.get("stats")
    if not isinstance(stats, dict):
        return default
    value = stats.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _reports_dir(settings: PipelineSettings) -> Path:
    return Path(settings.scan.outdir).expanduser().resolve()


def _latest_json_path(settings: PipelineSettings) -> Path | None:
    if settings.scan.latest_json is None:
        return None
    return Path(settings.scan.latest_json).expanduser().resolve()


def ensure_report_layout(reports_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name in REPORT_SUBDIRS:
        (reports_dir / name).mkdir(parents=True, exist_ok=True)


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp_path.write_text(text, encoding="utf-8")
    temp_path.replace(path)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temp_path.replace(path)


def _remove_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def _ensure_reports(payload: dict[str, Any]) -> dict[str, Any]:
    reports = payload.get("reports")
    if not isinstance(reports, dict):
        reports = {}
        payload["reports"] = reports
    return reports


def build_ops_report(data: dict[str, Any]) -> str:
    critical = _stats_value(data, "critical")
    high = _stats_value(data, "high")
    medium = _stats_value(data, "medium")
    low = _stats_value(data, "low")
    scanned_files = _stats_value(data, "scanned_files")
    scanned_directories = _stats_value(data, "scanned_directories")
    hashed_files = _stats_value(data, "hashed_files")
    metadata_only_files = _stats_value(data, "metadata_only_files")
    reversion_unprotected_files = _stats_value(data, "reversion_unprotected_files")
    skipped_missing_fingerprint_hashes = _stats_value(data, "skipped_missing_fingerprint_hashes")
    events_count = _stats_value(data, "events")

    reports = data.get("reports") if isinstance(data.get("reports"), dict) else {}
    events_csv = reports.get("events_csv", "") if isinstance(reports, dict) else ""
    events = data.get("events") if isinstance(data.get("events"), list) else []
    level, _, subtitle = alert_level(data)

    lines = [
        f"Alert level: {level}",
        f"Summary: {subtitle}",
        f"File Watch Run: {data.get('run_id', '')}",
        f"Started (UTC): {data.get('started_at_utc', '')}",
        f"Root: {data.get('root', '')}",
        f"Scanned files: {scanned_files}",
        f"Scanned directories: {scanned_directories}",
        f"Hashed files: {hashed_files}",
        f"Metadata-only files: {metadata_only_files}",
        f"Reversion-unprotected files: {reversion_unprotected_files}",
        f"Skipped missing-fingerprint hash backfills: {skipped_missing_fingerprint_hashes}",
        f"Events: {events_count} (critical={critical}, high={high}, medium={medium}, low={low})",
        f"CSV: {events_csv}",
        "",
        "Risk model:",
        "- Extremely High: version reversion; review before deletion/unavailability items.",
        "- High: likely deletion/unavailability, likely directory deletion/unavailability, possible file metadata reversion with size+mtime match, or possible directory metadata reversion with mtime+child-count match.",
        "- Medium: likely move, likely moved-and-renamed, content changed, size-only metadata reversion pattern, directory child-count reversion pattern, or metadata changed without fingerprint evidence; check against expected activity.",
        "- Low: likely same-folder rename or timestamp-only signal.",
        "- Move is ranked higher than rename because a location change has more operational impact.",
        "- Exact reversion detection requires historical fingerprints; metadata-only files are reported as reversion-unprotected.",
        "",
    ]

    alert_count = critical + high
    if alert_count > 0:
        lines.append("CRITICAL/HIGH SEVERITY EVENTS (up to 50):")
        shown = 0
        for event in events:
            if not isinstance(event, dict) or event.get("severity") not in {"critical", "high"}:
                continue
            event_path = event.get("path") or event.get("old_path") or ""
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            assessment = details.get("assessment") if isinstance(details, dict) else {}
            if not isinstance(assessment, dict):
                assessment = {}
            action = assessment.get("action_likelihood", "Unassessed")
            intent = assessment.get("intent_likelihood", "Unassessed")
            lines.append(f"- {event.get('type', '')}: {event_path}")
            lines.append(f"  Action likelihood: {action}")
            lines.append(f"  Intent signal: {intent}")
            if event.get("new_path"):
                lines.append(f"  Possible new path: {event.get('new_path')}")
            shown += 1
            if shown >= 50:
                break
    else:
        lines.append("No critical or high severity events detected.")

    directory_impacts = data.get("directory_impacts")
    if isinstance(directory_impacts, list) and directory_impacts:
        lines.extend(["", "DIRECTORY-LEVEL SIGNALS (up to 20):"])
        for impact in directory_impacts[:20]:
            if not isinstance(impact, dict):
                continue
            lines.append(
                f"- {impact.get('path', '')}: {impact.get('missing_files', 0)} missing file(s); "
                f"{impact.get('action_likelihood', '')}; intent signal: {impact.get('intent_likelihood', '')}"
            )

    return "\r\n".join(lines)


def make_error_report(
    title: str,
    details: str,
    *,
    exit_code: int,
    stdout: str = "",
    stderr: str = "",
) -> str:
    lines = [
        title,
        f"Time (local): {datetime.now().isoformat(timespec='seconds')}",
        f"Exit code: {exit_code}",
        "",
        "Details:",
        details,
        "",
    ]

    if stderr:
        lines.extend(["stderr:", stderr[:4000]])
    if stdout:
        lines.extend(["", "stdout (preview):", stdout[:2000]])
    return "\r\n".join(lines)


def _attach_full_json(payload: dict[str, Any]) -> dict[str, Any]:
    payload.pop("full_json_text", None)
    payload["full_json_text"] = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
    )
    return payload


def _event_sample(events: list[Any], *, limit: int = 100) -> list[Any]:
    if len(events) <= limit:
        return events

    alert_events = [
        event
        for event in events
        if isinstance(event, dict) and event.get("severity") in {"critical", "high"}
    ]
    remainder = [event for event in events if event not in alert_events]
    return [*alert_events[:limit], *remainder[: max(0, limit - len(alert_events[:limit]))]]


def compact_payload(payload: dict[str, Any], *, event_limit: int = 100) -> dict[str, Any]:
    compact = dict(payload)
    events = compact.get("events")
    if isinstance(events, list):
        compact["events_sample"] = _event_sample(events, limit=event_limit)
        compact["events_omitted"] = max(0, len(events) - len(compact["events_sample"]))
        compact.pop("events", None)
    compact.pop("full_json_text", None)
    compact["json_detail"] = "compact"
    compact["detail_note"] = "Detailed events are written to the events CSV and human HTML report."
    return _attach_full_json(compact)


def payload_for_json(payload: dict[str, Any], *, json_detail: str) -> dict[str, Any]:
    if json_detail == "full":
        full = dict(payload)
        full["json_detail"] = "full"
        return _attach_full_json(full)
    if json_detail != "compact":
        raise ValueError("json_detail must be one of: compact, full")
    return compact_payload(payload)


def _success_payload(summary: dict[str, Any]) -> dict[str, Any]:
    payload = dict(summary)
    payload["ok"] = True
    payload["ops_report"] = build_ops_report(payload)
    return _attach_full_json(payload)


def _error_payload(message: str, *, exit_code: int, stderr: str = "") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": False,
        "exitCode": exit_code,
        "stderr": stderr,
        "error": message,
        "ops_report": make_error_report(
            "ERROR: Python file integrity workflow failed",
            message,
            exit_code=exit_code,
            stderr=stderr,
        ),
    }
    return _attach_full_json(payload)


def _local_date_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def run_pipeline(settings: PipelineSettings) -> PipelineResult:
    reports_dir = _reports_dir(settings)
    ensure_report_layout(reports_dir)
    latest_json = _latest_json_path(settings)
    written: list[Path] = []

    try:
        summary = scan_files(settings.scan)
        payload = _success_payload(summary)
    except ScanError as exc:
        payload = _error_payload(str(exc), exit_code=exc.exit_code)
        error_path = reports_dir / "errors" / f"error_{_local_date_stamp()}.txt"
        error_html_path = reports_dir / "errors" / f"error_{_local_date_stamp()}.html"
        _ensure_reports(payload)["human_html"] = str(error_html_path)
        _attach_full_json(payload)
        _write_text_atomic(error_path, payload["ops_report"])
        _write_text_atomic(error_html_path, build_error_html_report(payload))
        written.append(error_path)
        written.append(error_html_path)
        if latest_json is not None:
            _write_json_atomic(latest_json, payload)
            written.append(latest_json)
        return PipelineResult(payload=payload, exit_code=exc.exit_code, written_files=tuple(written))
    except Exception as exc:
        stderr = traceback.format_exc()
        payload = _error_payload(str(exc), exit_code=1, stderr=stderr)
        error_path = reports_dir / "errors" / f"error_{_local_date_stamp()}.txt"
        error_html_path = reports_dir / "errors" / f"error_{_local_date_stamp()}.html"
        _ensure_reports(payload)["human_html"] = str(error_html_path)
        _attach_full_json(payload)
        _write_text_atomic(error_path, payload["ops_report"])
        _write_text_atomic(error_html_path, build_error_html_report(payload))
        written.append(error_path)
        written.append(error_html_path)
        if latest_json is not None:
            _write_json_atomic(latest_json, payload)
            written.append(latest_json)
        return PipelineResult(payload=payload, exit_code=1, written_files=tuple(written))

    critical = _stats_value(payload, "critical")
    high = _stats_value(payload, "high")
    alert_count = critical + high
    archive = settings.archive_policy.lower()
    if archive not in {"high", "always", "never"}:
        raise ValueError("archive_policy must be one of: high, always, never")

    reports = _ensure_reports(payload)
    human_latest = reports_dir / "HUMAN_latest.html"
    human_run = reports_dir / "human" / f"run_{payload['run_id']}.html"
    reports["human_html"] = str(human_latest)
    reports["human_run_html"] = str(human_run)

    if archive == "always" or (archive == "high" and alert_count > 0):
        archive_path = reports_dir / "archive" / f"run_{payload['run_id']}.json"
        reports["archive_json"] = str(archive_path)

    if alert_count > 0:
        alert_path = reports_dir / "alerts" / f"ALERT_{payload['run_id']}.txt"
        alert_html_path = reports_dir / "alerts" / f"ALERT_{payload['run_id']}.html"
        reports["alert_text"] = str(alert_path)
        reports["alert_html"] = str(alert_html_path)
        if settings.write_root_alert_latest:
            reports["latest_alert_text"] = str(reports_dir / "ALERT_latest.txt")
            reports["latest_alert_html"] = str(reports_dir / "ALERT_latest.html")
    else:
        status_path = reports_dir / "status" / f"STATUS_{payload['run_id']}.txt"
        status_html_path = reports_dir / "status" / f"STATUS_{payload['run_id']}.html"
        reports["status_text"] = str(status_path)
        reports["status_html"] = str(status_html_path)
        reports["latest_status_text"] = str(reports_dir / "STATUS_latest.txt")
        reports["latest_status_html"] = str(reports_dir / "STATUS_latest.html")

    payload["ops_report"] = build_ops_report(payload)
    html_report = build_human_html_report(payload)
    _write_text_atomic(human_latest, html_report)
    _write_text_atomic(human_run, html_report)
    written.append(human_latest)
    written.append(human_run)

    if archive == "always" or (archive == "high" and alert_count > 0):
        archive_path = Path(reports["archive_json"])
        _write_json_atomic(archive_path, payload_for_json(payload, json_detail=settings.json_detail))
        written.append(archive_path)

    if alert_count > 0:
        alert_path = Path(reports["alert_text"])
        alert_html_path = Path(reports["alert_html"])
        _write_text_atomic(alert_path, payload["ops_report"])
        _write_text_atomic(alert_html_path, html_report)
        written.append(alert_path)
        written.append(alert_html_path)
        if settings.write_root_alert_latest:
            latest_alert = Path(reports["latest_alert_text"])
            latest_alert_html = Path(reports["latest_alert_html"])
            _write_text_atomic(latest_alert, payload["ops_report"])
            _write_text_atomic(latest_alert_html, html_report)
            written.append(latest_alert)
            written.append(latest_alert_html)
        _remove_if_exists(reports_dir / "STATUS_latest.txt")
        _remove_if_exists(reports_dir / "STATUS_latest.html")
    else:
        status_path = Path(reports["status_text"])
        status_html_path = Path(reports["status_html"])
        _write_text_atomic(status_path, payload["ops_report"])
        _write_text_atomic(status_html_path, html_report)
        written.append(status_path)
        written.append(status_html_path)
        latest_status = Path(reports["latest_status_text"])
        latest_status_html = Path(reports["latest_status_html"])
        _write_text_atomic(latest_status, payload["ops_report"])
        _write_text_atomic(latest_status_html, html_report)
        written.append(latest_status)
        written.append(latest_status_html)
        _remove_if_exists(reports_dir / "ALERT_latest.txt")
        _remove_if_exists(reports_dir / "ALERT_latest.html")

    if latest_json is not None:
        _write_json_atomic(latest_json, payload_for_json(payload, json_detail=settings.json_detail))
        written.append(latest_json)

    exit_code = 1 if settings.fail_on_high and alert_count > 0 else 0
    return PipelineResult(payload=payload, exit_code=exit_code, written_files=tuple(written))
