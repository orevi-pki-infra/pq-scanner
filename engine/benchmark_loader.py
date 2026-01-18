from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

class BenchmarkLoadError(Exception): ...
class PolicyNotFoundError(Exception): ...

def load_json(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise BenchmarkLoadError(f"File not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))

def load_benchmark(path: str | Path) -> Dict[str, Any]:
    bench = load_json(path)
    # Minimal sanity checks
    for k in ["benchmark_version","rules","scoring_models","thresholds","denylists"]:
        if k not in bench:
            raise BenchmarkLoadError(f"Benchmark missing required key '{k}'")
    if not isinstance(bench["rules"], list):
        raise BenchmarkLoadError("Benchmark 'rules' must be a list")
    return bench

def load_policies(policies_dir: str | Path) -> Dict[str, Any]:
    """Load all JSON policies under a directory into an index keyed by basename and relative path."""
    policies_dir = Path(policies_dir)
    if not policies_dir.exists():
        raise BenchmarkLoadError(f"Policies directory not found: {policies_dir}")
    index: Dict[str, Any] = {}
    for p in policies_dir.rglob("*.json"):
        try:
            index[str(p.relative_to(policies_dir))] = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            raise BenchmarkLoadError(f"Failed to load policy {p}: {e}")
    return index

def resolve_denylist(benchmark: Dict[str, Any], policy_index: Dict[str, Any], denylist_name: str) -> List[str]:
    """Resolve denylist values by name. For MVP we support:
    - embedded denylists in benchmark['denylists'][denylist_name]
    - OR policy files if you later switch to referencing policies by path.
    """
    denylists = benchmark.get("denylists", {})
    if denylist_name in denylists:
        v = denylists[denylist_name]
        if not isinstance(v, list):
            raise BenchmarkLoadError(f"Denylist '{denylist_name}' must be a list in benchmark")
        return v

    # Optional policy lookup (if denylist_name is a relative path under policies/)
    if denylist_name in policy_index:
        data = policy_index[denylist_name]
        # Heuristic: first list-like value among common keys
        for key in ["cipher_suites","algorithms","runtimes","items","values"]:
            if key in data and isinstance(data[key], list):
                return data[key]
        raise PolicyNotFoundError(f"Policy '{denylist_name}' exists but no list field found")

    raise PolicyNotFoundError(f"Denylist '{denylist_name}' not found in benchmark or policies")
