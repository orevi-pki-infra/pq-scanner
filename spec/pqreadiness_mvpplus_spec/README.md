# PQ Readiness MVP+ Spec Pack

This zip contains the artifacts we defined so far:
- Versioned benchmark rule pack (JSON)
- Observation/evidence schemas (JSON Schema)
- Finding output schema (JSON Schema)
- Policy denylists (versioned)
- Sample fixtures for each scan surface and expected findings (illustrative)

## Layout
- benchmarks/
- schemas/
- policies/
- fixtures/
- docs/

## Notes
- Observations are wrapped in a common envelope with a surface-specific payload.
- Rules in the benchmark reference threshold and denylist names; you can either embed denylists (as in the benchmark JSON)
  or reference the versioned policy files under policies/.

## Next steps (optional)
- Implement a rule evaluator for the DSL operations used in `benchmarks/*.json`:
  contains, not_contains, regex_any, intersects_denylist, in_denylist, eq_any, missing_or_empty, missing_or_zero,
  gte, lte, lt, eq, any_object_match.
