from __future__ import annotations
import re
from typing import Any, Dict, List

MISSING = object()

def extract(observation: Dict[str, Any], path: str) -> Any:
    """Minimal JSONPath-lite extractor.

    Supported:
    - $.a.b.c
    - $.a.b[*]
    - $.a.b[*].c
    - $.a.b[*].c.d (arbitrary depth after one or more [*] expansions)

    Behavior:
    - If the path uses [*] anywhere, the result is always a list (possibly containing MISSING)
      so downstream ops can apply "any element" semantics.
    - Missing keys are represented as MISSING entries when mapping over a list.
    """
    if not path.startswith("$."):
        return MISSING

    parts = path[2:].split(".")  # strip "$."
    current: List[Any] = [observation]
    used_wildcard = False

    for part in parts:
        if not current:
            return [] if used_wildcard else MISSING

        if part.endswith("[*]"):
            used_wildcard = True
            key = part[:-3]
            expanded: List[Any] = []
            for node in current:
                if isinstance(node, dict) and key in node and isinstance(node[key], list):
                    expanded.extend(node[key])
            current = expanded
            continue

        mapped: List[Any] = []
        for node in current:
            if isinstance(node, dict):
                mapped.append(node.get(part, MISSING))
            else:
                mapped.append(MISSING)
        current = mapped

    if used_wildcard:
        return current
    # Scalar path
    if not current:
        return MISSING
    if len(current) == 1:
        return current[0]
    return current

def contains(value: Any, needle: Any) -> bool:
    return isinstance(value, list) and needle in value

def not_contains(value: Any, needle: Any) -> bool:
    return isinstance(value, list) and needle not in value

def regex_any(value: Any, pattern: str) -> bool:
    if not isinstance(value, list):
        return False
    rx = re.compile(pattern)
    return any(isinstance(x, str) and rx.search(x) for x in value)

def intersects_denylist(value: Any, denylist: List[str]) -> bool:
    if not isinstance(value, list):
        return False
    deny = set(denylist)
    return any((v in deny) for v in value if isinstance(v, str))

def in_denylist(value: Any, denylist: List[str]) -> bool:
    return isinstance(value, str) and value in set(denylist)

def eq(value: Any, expected: Any) -> bool:
    return value is not MISSING and value == expected

def eq_any(value: Any, expected: Any) -> bool:
    if isinstance(value, list):
        return any(v == expected for v in value)
    if value is MISSING:
        return False
    return value == expected

def _cmp_any(value: Any, rhs: Any, op) -> bool:
    """Compare scalar or list. If list, returns True if ANY element compares True."""
    if value is MISSING or rhs is MISSING:
        return False
    if isinstance(value, list):
        for v in value:
            if v is MISSING:
                continue
            try:
                if op(v, rhs):
                    return True
            except Exception:
                continue
        return False
    try:
        return op(value, rhs)
    except Exception:
        return False

def lt(a: Any, b: Any) -> bool:
    return _cmp_any(a, b, lambda x, y: x < y)

def lte(a: Any, b: Any) -> bool:
    return _cmp_any(a, b, lambda x, y: x <= y)

def gte(a: Any, b: Any) -> bool:
    return _cmp_any(a, b, lambda x, y: x >= y)

def missing_or_empty(value: Any) -> bool:
    # Scalar semantics
    if value is MISSING or value is None:
        return True
    if value == "":
        return True
    if isinstance(value, list):
        if len(value) == 0:
            return True
        # Any element missing/empty -> True
        for v in value:
            if v is MISSING or v is None or v == "":
                return True
            if isinstance(v, list) and len(v) == 0:
                return True
        return False
    return False

def missing_or_zero(value: Any) -> bool:
    if value is MISSING or value is None:
        return True
    if value == 0:
        return True
    if isinstance(value, list):
        if len(value) == 0:
            return True
        for v in value:
            if v is MISSING or v is None or v == 0:
                return True
        return False
    return False

def any_object_match(objs: Any, criteria: Dict[str, Any]) -> bool:
    if not isinstance(objs, list):
        return False
    for o in objs:
        if not isinstance(o, dict):
            continue
        ok = True
        if "type" in criteria and o.get("type") != criteria["type"]:
            ok = False
        if ok and "bits_lt" in criteria:
            bits = o.get("bits", MISSING)
            try:
                if bits is MISSING or not (bits < criteria["bits_lt"]):
                    ok = False
            except Exception:
                ok = False
        if ok:
            return True
    return False
