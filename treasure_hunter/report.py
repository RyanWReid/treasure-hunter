"""
HTML REPORT GENERATOR — Self-contained engagement deliverable

Converts scan results to a single-file HTML report with:
- Executive summary with severity breakdown
- Top findings table sorted by score
- Extracted credentials table
- Grabber module results
- Full finding details with signals and snippets

The report is self-contained (no external CSS/JS) for easy sharing.

Usage:
    treasure-hunter -p full --html report.html
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from .models import ScanResult, Severity


def generate_html_report(results: ScanResult, output_path: str) -> None:
    """Generate a self-contained HTML report from scan results."""
    # Pre-compute stats
    severity_counts = {
        "CRITICAL": len([f for f in results.findings if f.severity == Severity.CRITICAL]),
        "HIGH": len([f for f in results.findings if f.severity == Severity.HIGH]),
        "MEDIUM": len([f for f in results.findings if f.severity == Severity.MEDIUM]),
        "LOW": len([f for f in results.findings if f.severity == Severity.LOW]),
        "INFO": len([f for f in results.findings if f.severity == Severity.INFO]),
    }

    total_creds = results.total_credentials_harvested
    duration = ""
    if results.completed_at and results.started_at:
        secs = (results.completed_at - results.started_at).total_seconds()
        duration = f"{secs:.1f}s"

    sorted_findings = sorted(results.findings, key=lambda f: f.total_score, reverse=True)

    # Build HTML
    findings_rows = ""
    for i, f in enumerate(sorted_findings[:100], 1):
        sev_class = f.severity.name.lower()
        path_display = html.escape(f.file_path)
        if len(path_display) > 80:
            path_display = "..." + path_display[-77:]
        signals_text = html.escape("; ".join(s.description for s in f.signals[:3]))
        snippets_text = html.escape(" | ".join(f.content_snippets[:2])) if f.content_snippets else ""

        findings_rows += f"""<tr class="{sev_class}">
            <td>{i}</td>
            <td><span class="badge {sev_class}">{f.severity.name}</span></td>
            <td>{f.total_score}</td>
            <td class="path">{path_display}</td>
            <td>{signals_text}</td>
            <td class="snippet">{snippets_text}</td>
        </tr>\n"""

    # Credential rows
    cred_rows = ""
    cred_idx = 0
    for gr in results.grabber_results:
        if not hasattr(gr, "credentials"):
            continue
        for cred in gr.credentials:
            cred_idx += 1
            if cred_idx > 100:
                break
            cred_rows += f"""<tr>
                <td>{cred_idx}</td>
                <td>{html.escape(str(getattr(cred, 'source_module', '')))}</td>
                <td>{html.escape(str(getattr(cred, 'target_application', '')))}</td>
                <td>{html.escape(str(getattr(cred, 'credential_type', '')))}</td>
                <td>{html.escape(str(getattr(cred, 'username', '')) or html.escape(str(getattr(cred, 'url', ''))))}</td>
                <td>{"Yes" if getattr(cred, 'decrypted_value', '') else ("Encrypted" if getattr(cred, 'encrypted_value', b'') else "N/A")}</td>
            </tr>\n"""

    # Grabber summary rows
    grabber_rows = ""
    for gr in results.grabber_results:
        status = getattr(gr, 'status', None)
        status_str = status.value if status else 'unknown'
        creds_count = len(gr.credentials) if hasattr(gr, 'credentials') else 0
        dur = f"{gr.duration_seconds:.2f}s" if hasattr(gr, 'duration_seconds') else ""
        errors = len(gr.errors) if hasattr(gr, 'errors') else 0
        grabber_rows += f"""<tr>
            <td>{html.escape(gr.module_name)}</td>
            <td>{status_str}</td>
            <td>{creds_count}</td>
            <td>{dur}</td>
            <td>{errors}</td>
        </tr>\n"""

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Treasure Hunter Report — {results.scan_id}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
           background: #0d1117; color: #c9d1d9; padding: 20px; line-height: 1.5; }}
    h1 {{ color: #f0883e; margin-bottom: 5px; }}
    h2 {{ color: #58a6ff; margin: 30px 0 15px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
    .meta {{ color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; text-align: center; }}
    .stat-card .number {{ font-size: 2em; font-weight: bold; }}
    .stat-card .label {{ color: #8b949e; font-size: 0.85em; }}
    .stat-card.critical .number {{ color: #f85149; }}
    .stat-card.high .number {{ color: #f0883e; }}
    .stat-card.medium .number {{ color: #d29922; }}
    .stat-card.low .number {{ color: #3fb950; }}
    .stat-card.info .number {{ color: #58a6ff; }}
    .stat-card.creds .number {{ color: #bc8cff; }}
    table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 0.85em; }}
    th {{ background: #161b22; color: #58a6ff; text-align: left; padding: 10px; border-bottom: 2px solid #30363d; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; }}
    tr:hover {{ background: #161b22; }}
    .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
    .badge.critical {{ background: #f8514922; color: #f85149; }}
    .badge.high {{ background: #f0883e22; color: #f0883e; }}
    .badge.medium {{ background: #d2992222; color: #d29922; }}
    .badge.low {{ background: #3fb95022; color: #3fb950; }}
    .badge.info {{ background: #58a6ff22; color: #58a6ff; }}
    .path {{ font-family: monospace; font-size: 0.85em; word-break: break-all; }}
    .snippet {{ font-family: monospace; font-size: 0.8em; color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; }}
    footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; color: #484f58; font-size: 0.8em; text-align: center; }}
</style>
</head>
<body>
<h1>Treasure Hunter Report</h1>
<div class="meta">
    Scan ID: {results.scan_id} | Duration: {duration} |
    Files: {results.total_files_scanned:,} | Dirs: {results.total_dirs_scanned:,} |
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>

<h2>Summary</h2>
<div class="stats">
    <div class="stat-card critical"><div class="number">{severity_counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="number">{severity_counts['HIGH']}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="number">{severity_counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="number">{severity_counts['LOW']}</div><div class="label">Low</div></div>
    <div class="stat-card info"><div class="number">{severity_counts['INFO']}</div><div class="label">Info</div></div>
    <div class="stat-card creds"><div class="number">{total_creds}</div><div class="label">Credentials</div></div>
</div>

<h2>Top Findings</h2>
<table>
<thead><tr><th>#</th><th>Severity</th><th>Score</th><th>Path</th><th>Signals</th><th>Snippets</th></tr></thead>
<tbody>
{findings_rows}
</tbody>
</table>

{"<h2>Extracted Credentials</h2>" + '''
<table>
<thead><tr><th>#</th><th>Module</th><th>Application</th><th>Type</th><th>Identity</th><th>Decrypted</th></tr></thead>
<tbody>
''' + cred_rows + "</tbody></table>" if cred_rows else ""}

{"<h2>Grabber Modules</h2>" + '''
<table>
<thead><tr><th>Module</th><th>Status</th><th>Credentials</th><th>Duration</th><th>Errors</th></tr></thead>
<tbody>
''' + grabber_rows + "</tbody></table>" if grabber_rows else ""}

<footer>
    Generated by Treasure Hunter v0.1.0 | For authorized security testing only
</footer>
</body>
</html>"""

    Path(output_path).write_text(report_html, encoding="utf-8")
