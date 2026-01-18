from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Literal

Severity = Literal["critical","high","medium","low"]
Status = Literal["open","acknowledged","in_progress","resolved","false_positive"]
Surface = Literal["tls","kms","vault","repo","ssh"]
PQTag = Literal["none","pq_signal","pq_blocker","agility_gap"]

@dataclass
class Finding:
    finding_id: str
    tenant_id: str
    scan_run_id: str
    benchmark_version: str
    surface: Surface
    rule_id: str
    severity: Severity
    status: Status
    first_seen_epoch: int
    last_seen_epoch: int
    pq_tag: PQTag
    score_impact_security: int
    score_impact_pq: int
    category: Optional[str] = None
    title: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    endpoint: Optional[Dict[str, Any]] = None
    asset: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    references: Optional[List[str]] = None

@dataclass
class ScoreSnapshot:
    tenant_id: str
    scan_run_id: str
    calculated_epoch: int
    security_score: int
    pq_score: int
    counts_by_severity: Dict[str, int]
    counts_by_surface: Dict[str, int]
