# Engine MVP Starter

This repository includes:
- The spec pack under `spec/` (benchmark, schemas, policies, fixtures)
- A minimal Engine MVP that:
  - validates an observation (JSON Schema)
  - evaluates rules (DSL)
  - emits findings (Finding schema)
  - computes security + PQ scores
  - generates a JSON + HTML report

## Quick start

### 1) Install deps
```bash
pip install -r requirements.txt
```

### 2) Run on a fixture observation (TLS example)
```bash
python -m cli.pqscan evaluate \
  --benchmark spec/pqreadiness_mvpplus_spec/benchmarks/pqreadiness-mvpplus-1.1.0.json \
  --policies  spec/pqreadiness_mvpplus_spec/policies \
  --schemas   spec/pqreadiness_mvpplus_spec/schemas \
  --observation spec/pqreadiness_mvpplus_spec/fixtures/observations/tls_sample.json \
  --out out
```

Open the HTML report:
- `out/reports/<scan_run_id>/latest.html`

### 3) Run tests
```bash
pytest -q
```

## Notes
- The JSONPath implementation is intentionally minimal; extend only as needed.
- `pq_signal` findings do not impact PQ score by default (scored as 0); adjust if desired.

## Aggregate run (all fixtures at once)
```bash
python -m cli.pqscan aggregate       --benchmark spec/pqreadiness_mvpplus_spec/benchmarks/pqreadiness-mvpplus-1.1.0.json       --policies  spec/pqreadiness_mvpplus_spec/policies       --schemas   spec/pqreadiness_mvpplus_spec/schemas       --observations spec/pqreadiness_mvpplus_spec/fixtures/observations       --out out
```
