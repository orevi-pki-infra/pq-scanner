# Scoring Model (v1)

We maintain two independent scores:

1) Security Posture Score (0–100)
- Start at 100
- Subtract severity penalties per *open* finding
- Optionally multiply by confidence (0.6–1.0) at finding level, or apply at aggregate level

2) PQ Readiness Score (0–100)
- Start at 100
- Subtract penalties by pq_tag class:
  - pq_blocker: strongest penalty
  - agility_gap: medium penalty
  - pq_signal: informational; may be tracked but not necessarily scored

Rationale: customers can be “secure enough today” but still “not PQ-ready.”
