from __future__ import annotations
import html
from typing import Any, Dict, List
from .types import Finding, ScoreSnapshot

def build_report(findings: List[Finding], score: ScoreSnapshot, observation: Dict[str, Any]) -> Dict[str, Any]:
    # Sort findings: critical/high first
    sev_rank = {"critical":0,"high":1,"medium":2,"low":3}
    findings_sorted = sorted(findings, key=lambda f: (sev_rank.get(f.severity, 9), f.rule_id))

    return {
        "meta": {
            "tenant_id": score.tenant_id,
            "scan_run_id": score.scan_run_id,
            "surface": observation.get("surface"),
            "scan_time_epoch": observation.get("meta", {}).get("scan_time_epoch"),
            "benchmark_version": observation.get("benchmark", {}).get("version") or observation.get("benchmark_version")
        },
        "scores": {
            "security_score": score.security_score,
            "pq_score": score.pq_score,
            "counts_by_severity": score.counts_by_severity,
            "counts_by_surface": score.counts_by_surface
        },
        "top_findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "pq_tag": f.pq_tag,
                "remediation": f.remediation,
                "endpoint": f.endpoint
            } for f in findings_sorted[:10]
        ],
        "findings": [
            {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "pq_tag": f.pq_tag,
                "status": f.status,
                "remediation": f.remediation,
                "endpoint": f.endpoint,
                "evidence": f.evidence
            } for f in findings_sorted
        ]
    }

def render_html(report: Dict[str, Any]) -> str:
    meta = report.get("meta", {})
    scores = report.get("scores", {})
    findings = report.get("findings", [])

    def esc(x: Any) -> str:
        return html.escape("" if x is None else str(x))

    rows = []
    for f in findings:
        rows.append(
            f"<tr>"
            f"<td>{esc(f.get('severity'))}</td>"
            f"<td>{esc(f.get('pq_tag'))}</td>"
            f"<td>{esc(f.get('rule_id'))}</td>"
            f"<td>{esc(f.get('title'))}</td>"
            f"<td>{esc((f.get('endpoint') or {}).get('host'))}:{esc((f.get('endpoint') or {}).get('port'))}</td>"
            f"<td>{esc(f.get('remediation'))}</td>"
            f"</tr>"
        )

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>PQ Readiness Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .scores {{ display: flex; gap: 24px; margin: 12px 0 24px 0; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 12px 16px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #eee; text-align: left; padding: 8px; vertical-align: top; }}
    th {{ background: #fafafa; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <h1>PQ Readiness Report</h1>
  <div class="muted">
    Tenant: <b>{esc(meta.get('tenant_id'))}</b> |
    Scan: <b>{esc(meta.get('scan_run_id'))}</b> |
    Surface: <b>{esc(meta.get('surface'))}</b> |
    Benchmark: <b>{esc(meta.get('benchmark_version'))}</b>
  </div>

  <div class="scores">
    <div class="card"><div class="muted">Security Score</div><div style="font-size:28px"><b>{esc(scores.get('security_score'))}</b></div></div>
    <div class="card"><div class="muted">PQ Readiness Score</div><div style="font-size:28px"><b>{esc(scores.get('pq_score'))}</b></div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>PQ Tag</th><th>Rule</th><th>Title</th><th>Endpoint</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""
