"""
report.py
=========

Renders detection findings as JSON (machine-readable, for SIEM ingestion),
Markdown (for tickets/PRs), or a self-contained HTML page (for analyst
review). No external template engine dependency -- kept dependency-light
so the tool installs cleanly in constrained SOC environments.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

from .detector import Finding

_SEVERITY_COLOR = {
    "high": "#c0392b",
    "medium": "#e67e22",
    "low": "#f1c40f",
    "info": "#7f8c8d",
}


def to_json(findings: List[Finding], source: str = "") -> str:
    payload = {
        "tool": "doh-exfil-detector",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "flow_count": len(findings),
        "flagged_count": sum(1 for f in findings if f.risk.total >= 15),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_markdown(findings: List[Finding], source: str = "") -> str:
    lines = [
        f"# DoH Exfiltration Detection Report",
        "",
        f"- **Source:** `{source}`",
        f"- **Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"- **Flows analyzed:** {len(findings)}",
        f"- **Flagged (score >= 15):** {sum(1 for f in findings if f.risk.total >= 15)}",
        "",
        "| Severity | Score | Flow | SNI / Resolver | ML Outlier | Top Reason |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        top_reason = f.risk.components[0].rule if f.risk.components else "-"
        resolver = f.flow.resolver_name or f.flow.sni or f.flow.dst_ip
        lines.append(
            f"| {f.risk.severity} | {f.risk.total} | `{f.flow.flow_id}` | "
            f"{resolver} | {'yes' if f.ml_outlier else 'no'} | {top_reason} |"
        )

    lines.append("")
    lines.append("## Details")
    for f in findings:
        if f.risk.total < 15:
            continue
        lines.append(f"\n### {f.flow.flow_id} -- {f.risk.severity.upper()} ({f.risk.total}/100)")
        lines.append(f"- Destination: `{f.flow.dst_ip}:{f.flow.dst_port}` "
                      f"(SNI: `{f.flow.sni or 'n/a'}`, resolver: {f.flow.resolver_name or 'unrecognized'})")
        lines.append(f"- JA3: `{f.flow.ja3 or 'n/a'}`")
        if f.ml_outlier:
            lines.append(f"- Flagged as statistical outlier by Isolation Forest "
                          f"(anomaly score {f.ml_outlier_score})")
        for c in f.risk.components:
            lines.append(f"  - **{c.rule}** (+{c.points}): {c.detail}")
    return "\n".join(lines)


def to_html(findings: List[Finding], source: str = "") -> str:
    rows = []
    for f in findings:
        color = _SEVERITY_COLOR.get(f.risk.severity, "#7f8c8d")
        resolver = f.flow.resolver_name or "unrecognized"
        reasons_html = "".join(
            f"<li><b>{c.rule}</b> (+{c.points}): {c.detail}</li>" for c in f.risk.components
        )
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.risk.severity}</span></td>
          <td>{f.risk.total}</td>
          <td><code>{f.flow.flow_id}</code></td>
          <td>{f.flow.sni or f.flow.dst_ip}</td>
          <td>{resolver}</td>
          <td>{'Yes' if f.ml_outlier else 'No'}</td>
          <td><ul>{reasons_html or '<li>-</li>'}</ul></td>
        </tr>""")

    flagged = sum(1 for f in findings if f.risk.total >= 15)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DoH Exfiltration Detection Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background:#0d1117; color:#c9d1d9; }}
  h1 {{ color:#f0f6fc; }}
  .meta {{ color:#8b949e; margin-bottom: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 10px; text-align: left; vertical-align: top; font-size: 0.9rem; }}
  th {{ background: #161b22; }}
  tr:nth-child(even) {{ background: #10151c; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; text-transform: uppercase; }}
  code {{ color: #79c0ff; }}
  ul {{ margin: 0; padding-left: 1.1rem; }}
</style>
</head>
<body>
  <h1>DoH Exfiltration Detection Report</h1>
  <div class="meta">
    Source: <code>{source}</code><br>
    Generated: {datetime.now(timezone.utc).isoformat()}<br>
    Flows analyzed: {len(findings)} &middot; Flagged: {flagged}
  </div>
  <table>
    <tr><th>Severity</th><th>Score</th><th>Flow</th><th>SNI / Dest</th><th>Resolver</th><th>ML Outlier</th><th>Reasons</th></tr>
    {"".join(rows)}
  </table>
</body>
</html>"""
