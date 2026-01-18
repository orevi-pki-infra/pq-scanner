from __future__ import annotations
import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple

from .types import Finding
from . import dsl_ops
from .benchmark_loader import resolve_denylist

def _sha(s: str, n: int) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:n]

def _endpoint_key(obs: Dict[str, Any]) -> str:
    ep = obs.get("endpoint", {}) or {}
    host = str(ep.get("host",""))
    port = str(ep.get("port",""))
    return _sha(f"{host}:{port}", 16)

def _finding_id(tenant_id: str, scan_run_id: str, surface: str, endpoint_key: str, rule_id: str) -> str:
    return _sha(f"{tenant_id}:{scan_run_id}:{surface}:{endpoint_key}:{rule_id}", 24)

def _get_value(obs: Dict[str, Any], path: str) -> Any:
    return dsl_ops.extract(obs, path)

def _get_value_path(obs: Dict[str, Any], path: str) -> Any:
    return dsl_ops.extract(obs, path)

def _sanitize_for_json(x: Any) -> Any:
    """Remove internal sentinel values from evidence before JSON serialization."""
    if x is dsl_ops.MISSING:
        return None
    if isinstance(x, list):
        return [_sanitize_for_json(v) for v in x if v is not dsl_ops.MISSING]
    if isinstance(x, dict):
        return {k: _sanitize_for_json(v) for k, v in x.items() if v is not dsl_ops.MISSING}
    return x

def _build_evidence(obs: Dict[str, Any], evidence_keys: List[str]) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    # Always include endpoint if present
    ep = obs.get("endpoint")
    if isinstance(ep, dict):
        ev["endpoint"] = {"host": ep.get("host"), "port": ep.get("port"), "is_public": ep.get("is_public")}
    for k in evidence_keys:
        # store under the key string; downstream can render nicely
        val = dsl_ops.extract(obs, "$." + k) if not k.startswith("$.") else dsl_ops.extract(obs, k)
        if val is dsl_ops.MISSING:
            continue
        ev[k] = _sanitize_for_json(val)
    return ev

def _severity_penalty(benchmark: Dict[str, Any], severity: str) -> int:
    return int(benchmark["scoring_models"]["security_posture"]["severity_penalties"][severity])

def _pq_penalty(benchmark: Dict[str, Any], pq_tag: str, severity: str) -> int:
    if pq_tag not in ["pq_blocker","agility_gap"]:
        return 0
    return int(benchmark["scoring_models"]["pq_readiness"]["penalties"][pq_tag][severity])

def _eval_clause(obs: Dict[str, Any], clause: Dict[str, Any], benchmark: Dict[str, Any], policy_index: Dict[str, Any]) -> bool:
    op = clause.get("op")
    path = clause.get("path")
    if not op or not path:
        return False

    value = _get_value(obs, path)

    # Resolve comparison value
    if "value_path" in clause:
        rhs = _get_value_path(obs, clause["value_path"])
    else:
        rhs = clause.get("value", dsl_ops.MISSING)

    if op == "contains":
        return dsl_ops.contains(value, rhs)
    if op == "not_contains":
        return dsl_ops.not_contains(value, rhs)
    if op == "regex_any":
        return dsl_ops.regex_any(value, str(rhs))
    if op == "intersects_denylist":
        dl_name = clause.get("denylist")
        if not dl_name:
            return False
        dl = resolve_denylist(benchmark, policy_index, dl_name)
        return dsl_ops.intersects_denylist(value, dl)
    if op == "in_denylist":
        dl_name = clause.get("denylist")
        if not dl_name:
            return False
        dl = resolve_denylist(benchmark, policy_index, dl_name)
        return dsl_ops.in_denylist(value, dl)
    if op == "eq":
        return dsl_ops.eq(value, rhs)
    if op == "eq_any":
        return dsl_ops.eq_any(value, rhs)
    if op == "lt":
        return dsl_ops.lt(value, rhs)
    if op == "lte":
        return dsl_ops.lte(value, rhs)
    if op == "gte":
        return dsl_ops.gte(value, rhs)
    if op == "missing_or_empty":
        return dsl_ops.missing_or_empty(value)
    if op == "missing_or_zero":
        return dsl_ops.missing_or_zero(value)
    if op == "any_object_match":
        crit = clause.get("value", {})
        return dsl_ops.any_object_match(value, crit)

    return False

def _eval_logic(obs: Dict[str, Any], logic: Dict[str, Any], benchmark: Dict[str, Any], policy_index: Dict[str, Any]) -> bool:
    if "any_of" in logic:
        return any(_eval_clause(obs, c, benchmark, policy_index) for c in logic["any_of"])
    if "all_of" in logic:
        return all(_eval_clause(obs, c, benchmark, policy_index) for c in logic["all_of"])
    return False

def evaluate_observation(obs: Dict[str, Any], benchmark: Dict[str, Any], policy_index: Dict[str, Any]) -> List[Finding]:
    surface = obs.get("surface")
    if surface not in ["tls","kms","vault","repo","ssh"]:
        return []
    rules = [r for r in benchmark.get("rules", []) if r.get("surface") == surface]
    tenant_id = obs.get("meta", {}).get("tenant_id", "unknown")
    scan_run_id = obs.get("meta", {}).get("scan_run_id", "unknown")
    ts = int(obs.get("meta", {}).get("scan_time_epoch", int(time.time())))

    ep_key = _endpoint_key(obs)
    findings: List[Finding] = []

    for r in rules:
        logic = r.get("logic", {})
        if not isinstance(logic, dict):
            continue
        if _eval_logic(obs, logic, benchmark, policy_index):
            rule_id = r.get("rule_id", "UNKNOWN")
            severity = r.get("severity_default", "medium")
            pq_tag = r.get("pq_tag", "none")

            f = Finding(
                finding_id=_finding_id(tenant_id, scan_run_id, surface, ep_key, rule_id),
                tenant_id=str(tenant_id),
                scan_run_id=str(scan_run_id),
                benchmark_version=str(benchmark.get("benchmark_version")),
                surface=surface,
                rule_id=str(rule_id),
                severity=severity,
                status="open",
                first_seen_epoch=ts,
                last_seen_epoch=ts,
                pq_tag=pq_tag,
                score_impact_security=_severity_penalty(benchmark, severity),
                score_impact_pq=_pq_penalty(benchmark, pq_tag, severity),
                category=r.get("category"),
                title=r.get("title"),
                remediation=r.get("remediation"),
                endpoint=obs.get("endpoint"),
                evidence=_build_evidence(obs, r.get("evidence_keys", [])),
            )
            findings.append(f)

    return findings
