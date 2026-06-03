from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any


def stats_value(payload: dict[str, Any], key: str, default: int = 0) -> int:
    stats = payload.get("stats")
    if not isinstance(stats, dict):
        return default
    value = stats.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def alert_level(payload: dict[str, Any]) -> tuple[str, str, str]:
    critical = stats_value(payload, "critical")
    high = stats_value(payload, "high")
    medium = stats_value(payload, "medium")
    low = stats_value(payload, "low")
    if critical:
        return "Extremely High Risk", "critical", "Version reversion detected; urgent review recommended"
    if high:
        return "High Risk", "high", "Immediate review recommended"
    if medium:
        return "Review", "medium", "Changes found; check they are expected"
    if low:
        return "Low", "low", "Low-risk rename or timestamp signals found"
    return "Clear", "clear", "No alert-level integrity events detected"


def _events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    events = payload.get("events")
    if not isinstance(events, list):
        return []
    return [event for event in events if isinstance(event, dict)]


def _reports(payload: dict[str, Any]) -> dict[str, Any]:
    reports = payload.get("reports")
    return reports if isinstance(reports, dict) else {}


def _assessment(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get("details")
    if not isinstance(details, dict):
        return {}
    assessment = details.get("assessment")
    return assessment if isinstance(assessment, dict) else {}


def _path_for_event(event: dict[str, Any]) -> str:
    return str(event.get("path") or event.get("old_path") or "")


def _severity_class(severity: Any) -> str:
    value = str(severity or "review").lower()
    return value if value in {"critical", "high", "medium", "low"} else "review"


def _count_by_event_type(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(event.get("type", "unknown")) for event in events)


def _count_actions(events: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for event in events:
        counts[str(_assessment(event).get("action_likelihood", "Unassessed"))] += 1
    return counts


def _bar_rows(counts: Counter[str], *, total: int) -> str:
    if not counts:
        return '<p class="muted">No events in this section.</p>'

    rows: list[str] = []
    total = max(total, 1)
    for label, count in counts.most_common(8):
        percent = min(100.0, (count / total) * 100)
        rows.append(
            f"""
            <div class="bar-row">
              <div class="bar-label">{escape(label)}</div>
              <div class="bar-track"><span style="width: {percent:.1f}%"></span></div>
              <div class="bar-count">{count}</div>
            </div>
            """
        )
    return "\n".join(rows)


def _severity_card(label: str, value: int, css_class: str) -> str:
    return (
        f'<div class="metric {css_class}">'
        f'<span class="metric-label">{escape(label)}</span>'
        f'<strong>{value}</strong>'
        f"</div>"
    )


def _directory_rows(payload: dict[str, Any]) -> str:
    impacts = payload.get("directory_impacts")
    if not isinstance(impacts, list) or not impacts:
        return '<tr><td colspan="6" class="muted">No direct directory disappearance or directory-level missing-file pattern detected.</td></tr>'

    rows: list[str] = []
    for impact in impacts[:12]:
        if not isinstance(impact, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{escape(str(impact.get('path', '')))}</td>"
            f"<td>{escape(str(impact.get('missing_files', '')))}</td>"
            f"<td>{escape(str(impact.get('matched_new_paths', '')))}</td>"
            f"<td>{escape(str(impact.get('action_likelihood', '')))}</td>"
            f"<td>{escape(str(impact.get('action_confidence', '')))}</td>"
            f"<td>{escape(str(impact.get('intent_likelihood', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _event_rows(events: list[dict[str, Any]], *, limit: int = 50) -> str:
    if not events:
        return '<tr><td colspan="7" class="muted">No events detected.</td></tr>'

    rows: list[str] = []
    sorted_events = sorted(
        events,
        key=lambda event: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            _severity_class(event.get("severity")),
            4,
        ),
    )
    for event in sorted_events[:limit]:
        assessment = _assessment(event)
        severity = _severity_class(event.get("severity"))
        new_path = str(event.get("new_path") or "")
        possible_new_path = (
            f'<br><span class="muted">Possible new path: {escape(new_path)}</span>'
            if new_path
            else ""
        )
        rows.append(
            "<tr>"
            f'<td><span class="pill {severity}">{escape(severity.title())}</span></td>'
            f"<td>{escape(str(event.get('type', '')))}</td>"
            f"<td>{escape(str(assessment.get('action_likelihood', 'Unassessed')))}</td>"
            f"<td>{escape(str(assessment.get('action_confidence', '')))}</td>"
            f"<td>{escape(str(assessment.get('intent_likelihood', '')))}</td>"
            f"<td>{escape(_path_for_event(event))}{possible_new_path}</td>"
            f"<td>{escape(str(assessment.get('review_note', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _lay_summary(payload: dict[str, Any]) -> str:
    critical = stats_value(payload, "critical")
    high = stats_value(payload, "high")
    medium = stats_value(payload, "medium")
    low = stats_value(payload, "low")
    scanned = stats_value(payload, "scanned_files")
    reversion_unprotected = stats_value(payload, "reversion_unprotected_files")
    events = stats_value(payload, "events")
    event_list = _events(payload)
    reverted = sum(1 for event in event_list if event.get("type") == "reverted")
    missing = sum(1 for event in event_list if event.get("type") == "missing")

    coverage_note = ""
    if reversion_unprotected:
        coverage_note = (
            f" {reversion_unprotected:,} file(s) are metadata-only, so exact version reversion detection is not available for them until fingerprints are captured."
        )

    if critical or high:
        return (
            f"This run scanned {scanned:,} files and found {critical:,} extremely high-risk item(s) and {high:,} high-risk item(s). "
            f"There were {missing:,} missing-file signal(s) and {reverted:,} version reversion signal(s). "
            "Version reversions are treated as extremely high risk. Missing items are assessed for whether they look deleted or unavailable versus renamed in the same folder, moved to a different folder, or both moved and renamed; likely rename and move signals are review items rather than high-risk alerts."
            f"{coverage_note}"
        )
    if events:
        return (
            f"This run scanned {scanned:,} files and found {events:,} event(s): "
            f"{medium:,} medium-risk and {low:,} low-risk. No high-risk missing event or extremely high-risk reversion was detected."
            f"{coverage_note}"
        )
    return f"This run scanned {scanned:,} files and did not detect integrity events.{coverage_note}"


def build_human_html_report(payload: dict[str, Any]) -> str:
    level, level_class, subtitle = alert_level(payload)
    events = _events(payload)
    reports = _reports(payload)
    event_type_counts = _count_by_event_type(events)
    action_counts = _count_actions(events)
    critical = stats_value(payload, "critical")
    high = stats_value(payload, "high")
    medium = stats_value(payload, "medium")
    low = stats_value(payload, "low")
    scanned = stats_value(payload, "scanned_files")
    scanned_directories = stats_value(payload, "scanned_directories")
    hashed = stats_value(payload, "hashed_files")
    metadata_only = stats_value(payload, "metadata_only_files")
    reversion_unprotected = stats_value(payload, "reversion_unprotected_files")
    skipped_backfills = stats_value(payload, "skipped_missing_fingerprint_hashes")
    duration = payload.get("stats", {}).get("duration_s", "") if isinstance(payload.get("stats"), dict) else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>File Integrity Report - {escape(str(payload.get('run_id', '')))}</title>
  <style>
    :root {{
      --ink: #25142f;
      --muted: #765c86;
      --line: #ded0f0;
      --panel: #fffbff;
      --bg: #f1e9ff;
      --critical: #b42318;
      --critical-soft: #fff0ed;
      --high: #b54708;
      --high-soft: #fff3e0;
      --medium: #8a6a00;
      --medium-soft: #fff8d6;
      --low: #3156a3;
      --low-soft: #e9f0ff;
      --clear: #24744f;
      --clear-soft: #e6f5ee;
      --accent: #8b3a9c;
      --accent-soft: #f5d8f0;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      color: var(--ink);
      background: var(--bg);
      line-height: 1.45;
    }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    .hero {{
      color: #fff;
      background: linear-gradient(135deg, #5b2b69, #b83280);
      border-radius: 10px;
      padding: 28px;
      box-shadow: 0 16px 38px rgba(94, 30, 100, 0.18);
    }}
    .hero.critical {{ background: linear-gradient(135deg, #8f1d15, #c83a2e); }}
    .hero.high {{ background: linear-gradient(135deg, #8a3f06, #d65f00); }}
    .hero.medium {{ background: linear-gradient(135deg, #735600, #b78a00); }}
    .hero.low {{ background: linear-gradient(135deg, #194185, #175cd3); }}
    .hero.clear {{ background: linear-gradient(135deg, #14532d, #23814b); }}
    .eyebrow {{ text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; opacity: 0.84; }}
    h1 {{ margin: 8px 0 6px; font-size: 34px; line-height: 1.1; }}
    h2 {{ margin: 0 0 14px; font-size: 20px; }}
    .subtitle {{ margin: 0; opacity: 0.9; }}
    .grid {{ display: grid; gap: 16px; }}
    .metrics {{ grid-template-columns: repeat(5, minmax(0, 1fr)); margin: 18px 0; }}
    .two {{ grid-template-columns: 1fr 1fr; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 8px 22px rgba(94, 30, 100, 0.08);
    }}
    .metric {{
      border: 1px solid var(--line);
      border-top: 5px solid var(--accent);
      background: linear-gradient(180deg, #fffaff, #ffffff);
      border-radius: 8px;
      padding: 14px 16px;
      min-height: 88px;
      box-shadow: 0 8px 20px rgba(94, 30, 100, 0.08);
    }}
    .metric.critical {{ border-color: #f3c7c1; border-top-color: var(--critical); background: linear-gradient(180deg, var(--critical-soft), #fff); }}
    .metric.high {{ border-color: #f2d0a8; border-top-color: var(--high); background: linear-gradient(180deg, var(--high-soft), #fff); }}
    .metric.medium {{ border-color: #eadb91; border-top-color: var(--medium); background: linear-gradient(180deg, var(--medium-soft), #fff); }}
    .metric.low {{ border-color: #ccd8f2; border-top-color: var(--low); background: linear-gradient(180deg, var(--low-soft), #fff); }}
    .metric.clear {{ border-color: #c4e3d2; border-top-color: var(--clear); background: linear-gradient(180deg, var(--clear-soft), #fff); }}
    .metric-label {{ display: block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 28px; }}
    .facts {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 22px; margin-top: 14px; }}
    .fact-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .fact-value {{ overflow-wrap: anywhere; }}
    .bar-row {{ display: grid; grid-template-columns: minmax(160px, 1fr) 2fr 44px; gap: 10px; align-items: center; margin: 10px 0; }}
    .bar-label {{ overflow-wrap: anywhere; }}
    .bar-track {{ height: 12px; background: #f0d7ee; border-radius: 999px; overflow: hidden; }}
    .bar-track span {{ display: block; height: 100%; background: linear-gradient(90deg, #a855b5, #db4a95); }}
    .bar-count {{ text-align: right; color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ color: #5b2b69; background: #f9eafa; font-size: 12px; text-transform: uppercase; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 3px 9px; font-weight: 700; }}
    .pill.critical {{ color: var(--critical); background: var(--critical-soft); }}
    .pill.high {{ color: var(--high); background: var(--high-soft); }}
    .pill.medium {{ color: var(--medium); background: var(--medium-soft); }}
    .pill.low {{ color: var(--low); background: var(--low-soft); }}
    .muted {{ color: var(--muted); }}
    .note {{ border-left: 4px solid #a855b5; padding-left: 12px; color: #5b2b69; }}
    @media (max-width: 880px) {{
      .metrics, .two, .facts {{ grid-template-columns: 1fr; }}
      .page {{ padding: 16px; }}
      h1 {{ font-size: 28px; }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero {level_class}">
      <div class="eyebrow">File integrity monitor</div>
      <h1>{escape(level)}</h1>
      <p class="subtitle">{escape(subtitle)}</p>
      <div class="facts">
        <div><div class="fact-label">Run ID</div><div class="fact-value">{escape(str(payload.get('run_id', '')))}</div></div>
        <div><div class="fact-label">Started UTC</div><div class="fact-value">{escape(str(payload.get('started_at_utc', '')))}</div></div>
        <div><div class="fact-label">Root</div><div class="fact-value">{escape(str(payload.get('root', '')))}</div></div>
        <div><div class="fact-label">CSV</div><div class="fact-value">{escape(str(reports.get('events_csv', '')))}</div></div>
      </div>
    </section>

    <section class="grid metrics">
      {_severity_card("Extreme risk", critical, "critical")}
      {_severity_card("High risk", high, "high")}
      {_severity_card("Medium risk", medium, "medium")}
      {_severity_card("Low risk", low, "low")}
      {_severity_card("Scanned files", scanned, "clear" if not (critical or high) else "")}
    </section>

    <section class="grid two">
      <div class="panel">
        <h2>Lay Summary</h2>
        <p>{escape(_lay_summary(payload))}</p>
        <p class="note">Intent likelihood is an evidence signal, not proof. Use it to prioritise review, then confirm with the data owner, audit trail, or approved change record.</p>
      </div>
      <div class="panel">
        <h2>Run Profile</h2>
        <div class="facts">
          <div><div class="fact-label">Hashed files</div><div class="fact-value">{hashed:,}</div></div>
          <div><div class="fact-label">Metadata-only files</div><div class="fact-value">{metadata_only:,}</div></div>
          <div><div class="fact-label">Reversion unprotected</div><div class="fact-value">{reversion_unprotected:,}</div></div>
          <div><div class="fact-label">Skipped hash backfills</div><div class="fact-value">{skipped_backfills:,}</div></div>
          <div><div class="fact-label">Scanned directories</div><div class="fact-value">{scanned_directories:,}</div></div>
          <div><div class="fact-label">Duration seconds</div><div class="fact-value">{escape(str(duration))}</div></div>
          <div><div class="fact-label">Events</div><div class="fact-value">{stats_value(payload, 'events'):,}</div></div>
          <div><div class="fact-label">Database</div><div class="fact-value">{escape(str(payload.get('db', '')))}</div></div>
        </div>
      </div>
    </section>

    <section class="grid two" style="margin-top:16px">
      <div class="panel">
        <h2>Event Mix</h2>
        {_bar_rows(event_type_counts, total=max(len(events), 1))}
      </div>
      <div class="panel">
        <h2>Action Likelihood</h2>
        {_bar_rows(action_counts, total=max(len(events), 1))}
      </div>
    </section>

    <section class="panel" style="margin-top:16px">
      <h2>Directory-Level Signals</h2>
      <table>
        <thead><tr><th>Directory</th><th>Missing files</th><th>Possible new paths</th><th>Action likelihood</th><th>Confidence</th><th>Intent signal</th></tr></thead>
        <tbody>{_directory_rows(payload)}</tbody>
      </table>
    </section>

    <section class="panel" style="margin-top:16px">
      <h2>Prioritised Event Review</h2>
      <table>
        <thead><tr><th>Alert</th><th>Type</th><th>Action likelihood</th><th>Confidence</th><th>Intent signal</th><th>Path</th><th>Review note</th></tr></thead>
        <tbody>{_event_rows(events)}</tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""


def build_error_html_report(payload: dict[str, Any]) -> str:
    report = escape(str(payload.get("ops_report", ""))).replace("\n", "<br>")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>File Integrity Error</title>
  <style>
    body {{ margin: 0; font-family: "Segoe UI", Arial, sans-serif; background: #fff5f5; color: #1f2933; }}
    main {{ max-width: 980px; margin: 0 auto; padding: 28px; }}
    section {{ background: #fff; border: 1px solid #fecdca; border-radius: 8px; padding: 20px; }}
    h1 {{ color: #b42318; margin-top: 0; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>File integrity workflow error</h1>
      <pre>{report}</pre>
    </section>
  </main>
</body>
</html>
"""
