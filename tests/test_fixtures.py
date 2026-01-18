from __future__ import annotations
import json
from pathlib import Path

from engine.benchmark_loader import load_benchmark, load_policies
from engine.evaluator import evaluate_observation
from engine.schema_validate import validate_observation

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"

# The spec zip extracts as spec/pqreadiness_mvpplus_spec/...
SPEC_ROOT = next(SPEC.iterdir())

BENCHMARK = SPEC_ROOT / "benchmarks" / "pqreadiness-mvpplus-1.1.0.json"
POLICIES = SPEC_ROOT / "policies"
SCHEMAS = SPEC_ROOT / "schemas"
FIXTURES_OBS = SPEC_ROOT / "fixtures" / "observations"
FIXTURES_EXPECT = SPEC_ROOT / "fixtures" / "expected_findings"

def _pairs(findings):
    return sorted([(f.rule_id, f.severity) for f in findings])

def test_fixtures():
    benchmark = load_benchmark(BENCHMARK)
    policies = load_policies(POLICIES)

    for obs_path in FIXTURES_OBS.glob("*_sample.json"):
        obs = json.loads(obs_path.read_text(encoding="utf-8"))
        errs = validate_observation(obs, SCHEMAS)
        assert errs == [], f"Schema errors for {obs_path.name}: {errs}"

        findings = evaluate_observation(obs, benchmark, policies)
        surface = obs["surface"]
        expected_path = FIXTURES_EXPECT / f"{surface}_sample_findings.json"
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        expected_pairs = sorted([(x["rule_id"], x["severity"]) for x in expected])

        assert _pairs(findings) == expected_pairs, f"Mismatch for {obs_path.name}"
