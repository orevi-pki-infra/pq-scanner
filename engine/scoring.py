from __future__ import annotations
import time
from typing import Dict, List

from .types import Finding, ScoreSnapshot

ACTIVE_STATUSES = {"open","acknowledged","in_progress"}

def score_findings(findings: List[Finding], benchmark: dict) -> ScoreSnapshot:
    tenant_id = findings[0].tenant_id if findings else "unknown"
    scan_run_id = findings[0].scan_run_id if findings else "unknown"
    penalties = benchmark["scoring_models"]["security_posture"]["severity_penalties"]

    security = int(benchmark["scoring_models"]["security_posture"]["start"])
    pq = int(benchmark["scoring_models"]["pq_readiness"]["start"])

    counts_by_sev: Dict[str, int] = {"critical":0,"high":0,"medium":0,"low":0}
    counts_by_surface: Dict[str, int] = {"tls":0,"kms":0,"vault":0,"repo":0,"ssh":0}

    for f in findings:
        if f.status not in ACTIVE_STATUSES:
            continue
        counts_by_sev[f.severity] = counts_by_sev.get(f.severity, 0) + 1
        counts_by_surface[f.surface] = counts_by_surface.get(f.surface, 0) + 1

        security -= int(f.score_impact_security)
        pq -= int(f.score_impact_pq)

    security = max(int(benchmark["scoring_models"]["security_posture"].get("floor", 0)), security)
    pq = max(int(benchmark["scoring_models"]["pq_readiness"].get("floor", 0)), pq)

    return ScoreSnapshot(
        tenant_id=tenant_id,
        scan_run_id=scan_run_id,
        calculated_epoch=int(time.time()),
        security_score=security,
        pq_score=pq,
        counts_by_severity=counts_by_sev,
        counts_by_surface=counts_by_surface
    )
