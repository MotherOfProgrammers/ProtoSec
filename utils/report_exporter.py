import html
import json
from datetime import datetime, timezone
from pathlib import Path


def export_json_report(report: dict, output_path: str | Path) -> None:
    Path(output_path).write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def export_html_report(report: dict, project_path: str, output_path: str | Path) -> None:
    findings = report.get("findings", [])
    score = int(report.get("security_score", 100))
    summary = report.get("summary", {})
    score_color = "#27c89a" if score >= 80 else "#e7b54a" if score >= 50 else "#ed6079"
    rows = []

    for finding in findings:
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        severity_color = {
            "CRITICAL": "#f25c79",
            "HIGH": "#ed9a4f",
            "MEDIUM": "#cfaa44",
            "LOW": "#40ad8a",
        }.get(severity, "#728396")
        rows.append(
            "<tr>"
            f'<td><span class="severity" style="--severity:{severity_color}">{html.escape(severity)}</span></td>'
            f'<td><strong>{html.escape(str(finding.get("rule_id", "")))}</strong> · '
            f'{html.escape(str(finding.get("title", "")))}<br>'
            f'<code>{html.escape(str(finding.get("file_path", "")))}:'
            f'{html.escape(str(finding.get("line_number", "")))}</code></td>'
            f'<td><pre>{html.escape(str(finding.get("snippet", "")))}</pre></td>'
            f'<td><pre>{html.escape(str(finding.get("fix_prompt", "")))}</pre></td>'
            "</tr>"
        )

    if not rows:
        rows.append('<tr><td colspan="4" class="empty">No findings were reported by the enabled rules.</td></tr>')

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = int(summary.get("total", report.get("total_issues", len(findings))))
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ProtoSec v1.0.0 — Security Report</title>
<style>
  :root {{ color-scheme: dark; font-family: Inter, "Segoe UI", sans-serif; background: #080d16; color: #e6f0ff; }}
  body {{ max-width: 1200px; margin: 0 auto; padding: 40px 24px; }}
  .card {{ background: #111c2c; border: 1px solid #1d2c40; border-radius: 14px; padding: 24px; margin: 0 0 22px; }}
  .brand {{ color: #55e6c1; font-weight: 800; letter-spacing: 1px; }}
  .muted, code {{ color: #8294aa; }}
  .score {{ color: {score_color}; font-size: 34px; font-weight: 800; margin: 16px 0 4px; }}
  .metrics {{ display: flex; flex-wrap: wrap; gap: 18px; color: #a7b9cc; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; color: #8294aa; font-size: 11px; letter-spacing: .08em; }}
  th, td {{ border-bottom: 1px solid #1d2c40; padding: 14px 10px; text-align: left; vertical-align: top; }}
  pre {{ white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; font: 12px/1.5 "Cascadia Code", Consolas, monospace; }}
  .severity {{ color: var(--severity); font-weight: 800; }}
  .empty {{ text-align: center; padding: 40px; color: #8294aa; }}
  @media print {{ :root {{ color-scheme: light; background: white; color: #172635; }} body {{ max-width: none; }} .card {{ border-color: #ccd7df; background: white; }} }}
</style>
</head>
<body>
  <section class="card">
    <div class="brand">PROTOSEC · LOCAL SECURITY REPORT</div>
    <h1>Security audit</h1>
    <p class="muted">Project: <code>{html.escape(project_path)}</code><br>Generated {html.escape(generated)}</p>
    <div class="score">Security score: {score} / 100</div>
    <div class="metrics">
      <span>Total findings: <strong>{total}</strong></span>
      <span>Critical: <strong>{int(summary.get("critical", 0))}</strong></span>
      <span>High: <strong>{int(summary.get("high", 0))}</strong></span>
      <span>Medium: <strong>{int(summary.get("medium", 0))}</strong></span>
      <span>Low: <strong>{int(summary.get("low", 0))}</strong></span>
    </div>
  </section>
  <section class="card">
    <table>
      <thead><tr><th>SEVERITY</th><th>FINDING</th><th>EVIDENCE</th><th>REMEDIATION PROMPT</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </section>
</body>
</html>
"""
    Path(output_path).write_text(document, encoding="utf-8")
