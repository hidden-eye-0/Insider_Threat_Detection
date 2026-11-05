"""Employee-specific behavioural baselines and event enrichment.

Baseline construction (documented in docs/DETECTION_METHODOLOGY.md):
* built only from events *before* ``baseline_end`` (the historical window);
* events/days carrying an exception ``context_tag`` (approved overtime, tickets, change
  windows) are excluded so approved exceptional behaviour does not widen the baseline;
* robust statistics (median, MAD, percentiles) are used so a few outliers cannot
  dominate;
* employees with fewer than ``min_history_days`` active days are marked ``insufficient``
  and fall back to the pooled role baseline; novelty checks that need personal history
  (familiar accounts, devices, locations) are skipped for them rather than fabricated.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

MAD_SCALE = 1.4826
METRICS = ["n_events", "n_failed", "distinct_accounts", "distinct_resources",
           "download_mb", "n_priv", "max_sens_30min"]


def _max_in_window(ts: pd.Series, minutes: int) -> int:
    """Max number of events falling in any ``minutes``-long window (sorted timestamps)."""
    if ts.empty:
        return 0
    v = ts.sort_values().values.astype("datetime64[s]").astype("int64")
    right = np.searchsorted(v, v + minutes * 60, side="right")
    return int((right - np.arange(len(v))).max())


def daily_metrics(ev: pd.DataFrame) -> pd.DataFrame:
    """Per employee-day behavioural metrics for a (single-employee or multi) event frame."""
    if ev.empty:
        return pd.DataFrame(columns=["employee_id", "date"] + METRICS)
    rows = []
    for (emp, date), g in ev.groupby(["employee_id", "date"]):
        sens = g.loc[g["event_type"] == "sensitive_search", "timestamp"]
        rows.append({
            "employee_id": emp, "date": date, "n_events": len(g),
            "n_failed": int((g["event_type"] == "login_failed").sum()),
            "distinct_accounts": g["customer_id"].nunique(),
            "distinct_resources": g["resource"].nunique(),
            "download_mb": float(g.loc[g["event_type"] == "bulk_download", "volume_mb"].fillna(0).sum()),
            "n_priv": int((g["event_type"] == "privileged_op").sum()),
            "max_sens_30min": _max_in_window(sens, 30),
        })
    return pd.DataFrame(rows)


def _stat(series: pd.Series) -> dict:
    s = series.dropna().astype(float)
    if s.empty:
        return {"median": 0.0, "mad": 0.0, "p95": 0.0, "max": 0.0, "mean": 0.0}
    med = float(s.median())
    return {"median": med, "mad": float((s - med).abs().median()), "p95": float(s.quantile(.95)),
            "max": float(s.max()), "mean": float(s.mean())}


def upper_fence(stat: dict, k: float, floor_scale: float = 1.0) -> float:
    """Robust upper fence: max(p95, median + k * scaled MAD)."""
    return max(stat["p95"], stat["median"] + k * max(MAD_SCALE * stat["mad"], floor_scale))


def robust_z(x: float, stat: dict, floor_scale: float = 1.0) -> float:
    return (x - stat["median"]) / max(MAD_SCALE * stat["mad"], floor_scale)


def _hour_f(ts: pd.Series) -> pd.Series:
    return ts.dt.hour + ts.dt.minute / 60 + ts.dt.second / 3600


def prepare_events(events: pd.DataFrame) -> pd.DataFrame:
    ev = events.copy()
    ev["timestamp"] = pd.to_datetime(ev["timestamp"])
    ev["date"] = ev["timestamp"].dt.date.astype(str)
    ev["hour_f"] = _hour_f(ev["timestamp"])
    ev["weekday"] = ev["timestamp"].dt.weekday
    return ev


def _profile_from(hist: pd.DataFrame, cfg: dict) -> dict:
    """Baseline statistics from a (possibly pooled) clean history frame."""
    b = cfg["baseline"]
    dm = daily_metrics(hist)
    logins = hist[hist["event_type"] == "login_success"]
    allh = hist["hour_f"]
    lh = logins["hour_f"] if len(logins) else allh
    prof = {
        "login_hour_lo": float(lh.quantile(.01)) - b["hour_margin"] if len(lh) else 6.0,
        "login_hour_hi": float(lh.quantile(.99)) + b["hour_margin"] if len(lh) else 20.0,
        "active_hour_lo": float(allh.quantile(.005)) - b["hour_margin"] if len(allh) else 6.0,
        "active_hour_hi": float(allh.quantile(.995)) + b["hour_margin"] if len(allh) else 20.0,
        "usual_weekdays": sorted(int(x) for x in logins["weekday"].unique()) if len(logins) else [0, 1, 2, 3, 4],
        "logins_per_day": float(len(logins) / max(hist["date"].nunique(), 1)),
        "stats": {m: _stat(dm[m]) for m in METRICS} if len(dm) else {m: _stat(pd.Series(dtype=float)) for m in METRICS},
        "known_resources": sorted(hist["resource"].dropna().unique().tolist()),
    }
    return prof


def build_baselines(events: pd.DataFrame, baseline_end: pd.Timestamp, cfg: dict) -> dict:
    """Build per-employee baselines and pooled role baselines from history before ``baseline_end``.

    Returns ``{"employees": {...}, "roles": {...}, "meta": {...}}``.
    """
    ev = prepare_events(events)
    hist_all = ev[ev["timestamp"] < baseline_end]
    n_excluded = 0
    if cfg["baseline"]["exclude_tagged_days"]:
        tagged = hist_all[hist_all["context_tag"].notna()]
        n_excluded = len(tagged)
        keys = set(zip(tagged["employee_id"], tagged["date"]))
        mask = np.array([(e, d) not in keys for e, d in zip(hist_all["employee_id"], hist_all["date"])], dtype=bool)
        hist_clean = hist_all[mask]
    else:
        hist_clean = hist_all
    roles: dict = {}
    for role, g in hist_clean.groupby("role"):
        p = _profile_from(g, cfg)
        p["n_employees"] = int(g["employee_id"].nunique())
        roles[role] = p
    emps: dict = {}
    min_days = cfg["baseline"]["min_history_days"]
    for emp_id, role in ev.groupby("employee_id")["role"].first().items():
        g = hist_clean[hist_clean["employee_id"] == emp_id]
        n_days = int(g["date"].nunique())
        status = "established" if n_days >= min_days else "insufficient"
        prof = _profile_from(g, cfg) if n_days > 0 else {}
        if status == "insufficient" and role in roles:   # fall back to role-level behaviour
            fb = roles[role]
            prof = {k: fb[k] for k in ("login_hour_lo", "login_hour_hi", "active_hour_lo", "active_hour_hi",
                                      "usual_weekdays", "stats", "known_resources", "logins_per_day")}
        prof.update({
            "employee_id": emp_id, "role": role, "status": status, "history_days": n_days,
            "history_events": int(len(g)),
            "window_start": str(g["timestamp"].min()) if len(g) else None,
            "window_end": str(baseline_end),
            "known_devices": sorted(g["device_id"].dropna().unique().tolist()) if status == "established" else [],
            "known_locations": sorted(g["location"].dropna().unique().tolist()) if status == "established" else [],
            "familiar_customers": sorted(g["customer_id"].dropna().unique().tolist()) if status == "established" else [],
            "fallback": "role baseline" if status == "insufficient" else "none",
        })
        emps[emp_id] = prof
    return {"employees": emps, "roles": roles,
            "meta": {"baseline_end": str(baseline_end), "events_in_history": int(len(hist_all)),
                     "tagged_events_excluded": int(n_excluded), "min_history_days": min_days}}


def enrich_events(events: pd.DataFrame, baselines: dict) -> pd.DataFrame:
    """Add per-event deviation flags relative to each employee's baseline."""
    ev = prepare_events(events)
    n = len(ev)
    off_login = np.zeros(n, bool); off_active = np.zeros(n, bool)
    unf_cust = np.zeros(n, bool); unf_res = np.zeros(n, bool)
    new_dev = np.zeros(n, bool); new_loc = np.zeros(n, bool)
    pos = {i: k for k, i in enumerate(ev.index)}
    for emp, g in ev.groupby("employee_id"):
        b = baselines["employees"].get(emp)
        if not b or "login_hour_lo" not in b:
            continue
        idx = np.array([pos[i] for i in g.index])
        h, wd = g["hour_f"].values, g["weekday"].values
        wd_bad = ~np.isin(wd, b["usual_weekdays"])
        off_login[idx] = (h < b["login_hour_lo"]) | (h > b["login_hour_hi"]) | wd_bad
        off_active[idx] = (h < b["active_hour_lo"]) | (h > b["active_hour_hi"]) | wd_bad
        unf_res[idx] = (g["resource"].notna() & ~g["resource"].isin(b["known_resources"])).values
        if b["status"] == "established":
            unf_cust[idx] = (g["customer_id"].notna() & ~g["customer_id"].isin(b["familiar_customers"])).values
            new_dev[idx] = (g["device_id"].notna() & ~g["device_id"].isin(b["known_devices"])).values
            new_loc[idx] = (g["location"].notna() & ~g["location"].isin(b["known_locations"])).values
    ev["off_hours_login"], ev["off_hours"] = off_login, off_active
    ev["unfamiliar_customer"], ev["unfamiliar_resource"] = unf_cust, unf_res
    ev["new_device"], ev["new_location"] = new_dev, new_loc
    return ev
