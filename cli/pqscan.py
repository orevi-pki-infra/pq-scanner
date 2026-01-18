from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time
from typing import List, Dict, Any

from engine.benchmark_loader import load_benchmark, load_policies
from engine.schema_validate import validate_observation
from engine.evaluator import evaluate_observation
from engine.scoring import score_findings
from engine.report import build_report, render_html

def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    def _default(o):
        d = getattr(o, "__dict__", None)
        if isinstance(d, dict):
            return d
        return str(o)

    path.write_text(json.dumps(obj, indent=2, default=_default), encoding="utf-8")

def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def _write_outputs(out_dir: Path, obs: Dict[str, Any], findings, score, report_json, report_html) -> Path:
    scan_run_id = obs.get("meta", {}).get("scan_run_id", "unknown")
    surface = obs.get("surface", "unknown")
    host = (obs.get("endpoint", {}) or {}).get("host", "na")
    port = (obs.get("endpoint", {}) or {}).get("port", 0)
    endpoint_key = f"{host}_{port}".replace(":","_")

    write_json(out_dir / "findings" / scan_run_id / surface / f"{endpoint_key}.findings.json", findings)
    write_json(out_dir / "scores" / scan_run_id / "score_snapshot.json", score)
    write_json(out_dir / "reports" / scan_run_id / "latest.json", report_json)

    html_path = out_dir / "reports" / scan_run_id / "latest.html"
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(report_html, encoding="utf-8")
    return html_path

def _write_aggregate_outputs(out_dir: Path, scan_run_id: str, findings_all, score, report_json, report_html) -> Path:
    # Consolidated artifacts
    write_json(out_dir / "findings" / scan_run_id / "all.findings.json", findings_all)
    write_json(out_dir / "scores" / scan_run_id / "score_snapshot.json", score)
    write_json(out_dir / "reports" / scan_run_id / "latest.json", report_json)

    html_path = out_dir / "reports" / scan_run_id / "latest.html"
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(report_html, encoding="utf-8")
    return html_path

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pqscan", description="PQ Readiness MVP+ evaluator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ev = sub.add_parser("evaluate", help="Validate, evaluate rules, score, and generate report for ONE observation.")
    ev.add_argument("--benchmark", required=True)
    ev.add_argument("--policies", required=True)
    ev.add_argument("--schemas", required=True)
    ev.add_argument("--observation", required=True)
    ev.add_argument("--out", required=True)
    ev.add_argument("--strict", action="store_true")

    ag = sub.add_parser("aggregate", help="Validate/evaluate ALL observations in a folder and generate ONE consolidated report.")
    ag.add_argument("--benchmark", required=True)
    ag.add_argument("--policies", required=True)
    ag.add_argument("--schemas", required=True)
    ag.add_argument("--observations", required=True, help="Folder containing observation JSON files.")
    ag.add_argument("--out", required=True)
    ag.add_argument("--strict", action="store_true")

    args = parser.parse_args(argv)

    # Load benchmark + policies once
    try:
        benchmark = load_benchmark(args.benchmark)
        policy_index = load_policies(args.policies)
    except Exception as e:
        print(f"[ERROR] Benchmark/policy load failed: {e}", file=sys.stderr)
        return 3

    if args.cmd == "evaluate":
        try:
            obs = _load_json(Path(args.observation))
        except Exception as e:
            print(f"[ERROR] Observation load failed: {e}", file=sys.stderr)
            return 2

        errors = validate_observation(obs, args.schemas)
        if errors:
            print("[ERROR] Schema validation failed:", file=sys.stderr)
            for er in errors:
                print(f"  - {er['path']}: {er['message']}", file=sys.stderr)
            return 2 if args.strict else 0

        try:
            findings = evaluate_observation(obs, benchmark, policy_index)
            score = score_findings(findings, benchmark)
            report_json = build_report(findings, score, obs)
            report_html = render_html(report_json)
        except Exception as e:
            print(f"[ERROR] Evaluation failed: {e}", file=sys.stderr)
            return 4

        out_dir = Path(args.out)
        html_path = _write_outputs(out_dir, obs, findings, score, report_json, report_html)

        print(f"[OK] Wrote findings, scores, and report to {out_dir.resolve()}")
        print(f"     HTML report: {html_path.resolve()}")
        return 0

    if args.cmd == "aggregate":
        obs_dir = Path(args.observations)
        if not obs_dir.exists() or not obs_dir.is_dir():
            print(f"[ERROR] observations folder not found: {obs_dir}", file=sys.stderr)
            return 2

        obs_files = sorted([p for p in obs_dir.glob("*.json") if p.is_file()])
        if not obs_files:
            print(f"[ERROR] No .json observation files found in: {obs_dir}", file=sys.stderr)
            return 2

        observations: List[Dict[str, Any]] = []
        for p in obs_files:
            try:
                observations.append(_load_json(p))
            except Exception as e:
                print(f"[ERROR] Failed to read {p.name}: {e}", file=sys.stderr)
                return 2

        # Validate all observations first
        any_errors = False
        for obs, p in zip(observations, obs_files):
            errors = validate_observation(obs, args.schemas)
            if errors:
                any_errors = True
                print(f"[ERROR] Schema validation failed for {p.name}:", file=sys.stderr)
                for er in errors:
                    print(f"  - {er['path']}: {er['message']}", file=sys.stderr)

        if any_errors:
            return 2 if args.strict else 0

        # Evaluate + collect findings
        findings_all = []
        for obs in observations:
            findings_all.extend(evaluate_observation(obs, benchmark, policy_index))

        # Choose scan_run_id and tenant_id for consolidated report
        scan_run_ids = {o.get("meta", {}).get("scan_run_id") for o in observations}
        scan_run_ids.discard(None)
        scan_run_id = list(scan_run_ids)[0] if len(scan_run_ids) == 1 else f"aggregate_{int(time.time())}"

        tenant_ids = {o.get("meta", {}).get("tenant_id") for o in observations}
        tenant_ids.discard(None)
        tenant_id = list(tenant_ids)[0] if len(tenant_ids) == 1 else "mixed"

        # Patch findings' scan_run_id/tenant_id if we created an aggregate id (keeps outputs coherent)
        if scan_run_id.startswith("aggregate_") or tenant_id == "mixed":
            for f in findings_all:
                f.scan_run_id = scan_run_id
                f.tenant_id = tenant_id

        score = score_findings(findings_all, benchmark)

        # Build a synthetic "observation" meta for the report
        report_context = {
            "meta": {"tenant_id": tenant_id, "scan_run_id": scan_run_id, "scan_time_epoch": int(time.time())},
            "surface": "aggregate",
            "benchmark": {"version": benchmark.get("benchmark_version")}
        }
        report_json = build_report(findings_all, score, report_context)
        report_html = render_html(report_json)

        out_dir = Path(args.out)
        html_path = _write_aggregate_outputs(out_dir, scan_run_id, findings_all, score, report_json, report_html)

        print(f"[OK] Wrote consolidated findings, score, and report to {out_dir.resolve()}")
        print(f"     HTML report: {html_path.resolve()}")
        return 0

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
