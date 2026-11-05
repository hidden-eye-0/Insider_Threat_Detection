"""Transparent weighted risk scoring (0-100) -> review priority.

score = 100 * ( w_rules*S_rules + w_ml*S_ml + w_dev*S_dev + w_corr*S_corr + w_sens*S_sens )
        * (1 - context_discount * approved_coverage)

Signals are each normalised to [0, 1]:
  S_rules = 1 - prod(1 - sev_weight[rule])  over DISTINCT rule ids (noisy-OR; repeated hits of the
            same rule do not add, so one behaviour is not counted many times)
  S_ml    = ml_norm (0 at training median anomaly score, 1 at training 99.9th percentile)
  S_dev   = min(1, largest positive robust z of the employee-day / dev_z_cap)
  S_corr  = (core_stages - 1) / 4, x0.8 if stages are out of order; 0 for isolated groups
  S_sens  = highest sensitivity weight among the group's event types
The score is a prioritisation index, NOT a calibrated probability of malicious intent.
"""
from __future__ import annotations

import numpy as np

from .config import SENSITIVITY_WEIGHT, priority_for


def rule_signal(severities: dict[str, str], cfg: dict) -> float:
    w = cfg["severity_weight"]
    prod = 1.0
    for sev in severities.values():
        prod *= 1.0 - w[sev]
    return 1.0 - prod


def score_signals(rule_sev: dict[str, str], ml_norm: float | None, max_z: float, core_stages: int,
                  ordered: bool, event_types: list[str], approved_coverage: float, cfg: dict) -> dict:
    """Combine signals into a 0-100 score. ``ml_norm=None`` means ML unavailable (weights renormalised)."""
    r = cfg["risk"]
    w = dict(r["weights"])
    s = {
        "rules": rule_signal(rule_sev, cfg),
        "ml": float(ml_norm) if ml_norm is not None else 0.0,
        "deviation": float(np.clip(max_z / r["dev_z_cap"], 0, 1)),
        "correlation": 0.0 if core_stages < 2 else min(1.0, (core_stages - 1) / 4) * (1.0 if ordered else 0.8),
        "sensitivity": max([SENSITIVITY_WEIGHT.get(t, 0.2) for t in event_types] or [0.0]),
    }
    if ml_norm is None:
        total_w = 1.0 - w.pop("ml")
        w = {k: v / total_w for k, v in w.items()}
        w["ml"] = 0.0
    contrib = {k: 100.0 * w[k] * s[k] for k in s}
    raw = sum(contrib.values())
    discount = r["context_discount"] * float(np.clip(approved_coverage, 0, 1))
    final = float(np.clip(raw * (1.0 - discount), 0, 100))
    return {"signals": s, "weights": w, "contributions": contrib, "raw_score": raw,
            "context_discount": discount, "risk_score": round(final, 1), "priority": priority_for(final, cfg)}
