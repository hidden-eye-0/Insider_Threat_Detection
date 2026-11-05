"""Employee-day feature engineering for ML anomaly detection.

Raw behavioural counts are combined with robust deviation (z) features computed against
each employee's own baseline (role baseline for employees with insufficient history).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .baseline import daily_metrics, robust_z

ROLES = ["teller", "loan_officer", "support", "auditor", "admin"]
Z_METRICS = ["n_events", "n_failed", "distinct_accounts", "download_mb", "n_priv", "max_sens_30min",
             "distinct_resources"]
RAW_FEATURES = ["n_events", "n_logins", "n_failed", "distinct_accounts", "unfamiliar_accounts",
                "distinct_resources", "unfamiliar_resources", "download_mb", "max_download_mb", "n_bulk",
                "n_priv", "n_sensitive", "max_sens_30min", "n_transfer", "transfer_mb", "off_hours_events",
                "off_hours_logins", "new_device_events", "new_location_events"]
Z_FEATURES = [f"z_{m}" for m in Z_METRICS]
FEATURE_COLUMNS = RAW_FEATURES + Z_FEATURES + [f"role_{r}" for r in ROLES]


def employee_day_features(enriched: pd.DataFrame, baselines: dict, z_cap: float = 8.0) -> pd.DataFrame:
    """One row per (employee_id, date) with FEATURE_COLUMNS + identifying columns."""
    if enriched.empty:
        return pd.DataFrame(columns=["employee_id", "date", "role"] + FEATURE_COLUMNS)
    dm = daily_metrics(enriched).set_index(["employee_id", "date"])
    rows = []
    for (emp, date), g in enriched.groupby(["employee_id", "date"]):
        et = g["event_type"]
        bulk = g[et == "bulk_download"]
        tr = g[et == "data_transfer"]
        r = {
            "employee_id": emp, "date": date, "role": g["role"].iloc[0],
            "n_events": len(g), "n_logins": int((et == "login_success").sum()),
            "n_failed": int((et == "login_failed").sum()),
            "distinct_accounts": dm.at[(emp, date), "distinct_accounts"],
            "unfamiliar_accounts": g.loc[g["unfamiliar_customer"], "customer_id"].nunique(),
            "distinct_resources": dm.at[(emp, date), "distinct_resources"],
            "unfamiliar_resources": g.loc[g["unfamiliar_resource"], "resource"].nunique(),
            "download_mb": dm.at[(emp, date), "download_mb"],
            "max_download_mb": float(bulk["volume_mb"].max()) if len(bulk) and bulk["volume_mb"].notna().any() else 0.0,
            "n_bulk": len(bulk), "n_priv": int((et == "privileged_op").sum()),
            "n_sensitive": int((et == "sensitive_search").sum()),
            "max_sens_30min": dm.at[(emp, date), "max_sens_30min"],
            "n_transfer": len(tr), "transfer_mb": float(tr["volume_mb"].fillna(0).sum()),
            "off_hours_events": int(g["off_hours"].sum()), "off_hours_logins": int(g["off_hours_login"].sum()),
            "new_device_events": int(g["new_device"].sum()), "new_location_events": int(g["new_location"].sum()),
        }
        base = baselines["employees"].get(emp)
        for m in Z_METRICS:
            if base and "stats" in base:
                scale_floor = max(1.0, 0.1 * base["stats"][m]["median"])
                r[f"z_{m}"] = float(np.clip(robust_z(r[m], base["stats"][m], scale_floor), -z_cap, z_cap * 2.5))
            else:
                r[f"z_{m}"] = 0.0
        for role in ROLES:
            r[f"role_{role}"] = int(r["role"] == role)
        rows.append(r)
    return pd.DataFrame(rows)


def top_deviations(row: pd.Series, n: int = 3) -> list[tuple[str, float]]:
    """Largest positive z-score features for an employee-day row (used in explanations)."""
    zs = {f: float(row[f]) for f in Z_FEATURES}
    return sorted(((k[2:], v) for k, v in zs.items() if v > 0), key=lambda kv: -kv[1])[:n]
