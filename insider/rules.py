"""Configurable, independently testable rule-based detections.

Every rule is a function ``(ev, baseline, params, ctx) -> list[Hit]`` operating on the
enriched events of ONE employee (sorted by time). Thresholds come from the config.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable

import numpy as np
import pandas as pd

from .baseline import METRICS, robust_z, upper_fence  # noqa: F401


@dataclass
class Hit:
    rule_id: str
    rule_name: str
    severity: str
    employee_id: str
    ts_start: pd.Timestamp
    ts_end: pd.Timestamp
    event_ids: list[str]
    evidence: dict
    explanation: str
    low_confidence: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts_start"], d["ts_end"] = str(self.ts_start), str(self.ts_end)
        return d


@dataclass
class Rule:
    rule_id: str
    requires: list[str]                 # event columns that must contain data
    func: Callable
    description: str = ""
    condition: str = ""


def _mk(rule_id, cfg, ev_rows: pd.DataFrame, evidence: dict, explanation: str, low_conf: bool) -> Hit:
    rc = cfg["rules"][rule_id]
    return Hit(rule_id, rc["name"], rc["severity"], ev_rows["employee_id"].iloc[0],
               ev_rows["timestamp"].min(), ev_rows["timestamp"].max(), ev_rows["event_id"].tolist(),
               evidence, explanation, low_conf)


def _stat(base, metric):
    return base["stats"][metric]


def _densest_burst(first: pd.DataFrame, minutes: int = 120) -> pd.DataFrame:
    """Rows (sorted by time) inside the densest ``minutes``-long window -> the evidence burst."""
    first = first.sort_values("timestamp")
    v = first["timestamp"].values.astype("datetime64[s]").astype("int64")
    right = np.searchsorted(v, v + minutes * 60, side="right")
    i = int((right - np.arange(len(v))).argmax())
    return first.iloc[i:right[i]]


# ---------------------------------------------------------------------------
def r01(ev, base, p, cfg):
    off = ev[(ev["event_type"] == "login_success") & ev["off_hours_login"]]
    hits = []
    for date, g in off.groupby("date"):
        # include the off-hours session activity that follows the login (within 2 h)
        t0 = g["timestamp"].min()
        sess = ev[(ev["timestamp"] >= t0) & (ev["timestamp"] <= t0 + pd.Timedelta(hours=2)) & ev["off_hours"]]
        g = pd.concat([g, sess]).drop_duplicates("event_id").sort_values("timestamp")
        hrs = ", ".join(f"{h:05.2f}h" for h in g["hour_f"].head(3))
        hits.append(_mk("R01", cfg, g, {
            "login_hours": [round(float(h), 2) for h in g["hour_f"]],
            "usual_login_window": [round(base["login_hour_lo"], 2), round(base["login_hour_hi"], 2)],
            "usual_weekdays": base["usual_weekdays"]},
            f"Login(s) on {date} at {hrs} fall outside this employee's usual login window "
            f"({base['login_hour_lo']:.1f}h-{base['login_hour_hi']:.1f}h) or usual weekdays.",
            base["status"] != "established"))
    return hits


def r02(ev, base, p, cfg):
    hits = []
    fails = ev[ev["event_type"] == "login_failed"]
    if len(fails) < p["min_failed"]:
        return hits
    used_until = pd.Timestamp.min
    for i in range(len(fails)):
        t0 = fails["timestamp"].iloc[i]
        if t0 <= used_until:
            continue
        win = fails[(fails["timestamp"] >= t0) & (fails["timestamp"] <= t0 + pd.Timedelta(minutes=p["fail_window_min"]))]
        if len(win) < p["min_failed"]:
            continue
        t_last = win["timestamp"].max()
        after = ev[(ev["timestamp"] > t_last) & (ev["timestamp"] <= t_last + pd.Timedelta(minutes=p["follow_window_min"]))]
        succ = after[after["event_type"] == "login_success"]
        sens = after[after["event_type"].isin(["sensitive_search", "bulk_download", "account_access", "data_transfer"])]
        if succ.empty or sens.empty:
            continue
        rows = pd.concat([win, succ.head(1), sens]).drop_duplicates("event_id")
        used_until = rows["timestamp"].max()
        hits.append(_mk("R02", cfg, rows, {
            "failed_logins": len(win), "window_min": p["fail_window_min"],
            "followed_by": sens["event_type"].value_counts().to_dict()},
            f"{len(win)} failed logins within {p['fail_window_min']} min were followed by a successful login and "
            f"{len(sens)} sensitive event(s) within {p['follow_window_min']} min.", base["status"] != "established"))
    return hits


def r03(ev, base, p, cfg):
    hits = []
    st = _stat(base, "distinct_accounts")
    thr = max(p["abs_min"], upper_fence(st, p["k_mad"]))
    acc = ev[ev["customer_id"].notna() & ev["event_type"].isin(["account_access", "transaction_view", "sensitive_search"])]
    for date, g in acc.groupby("date"):
        n = g["customer_id"].nunique()
        if n > thr:
            beyond = _densest_burst(g.drop_duplicates("customer_id"))   # densest 2-hour burst of new accounts
            hits.append(_mk("R03", cfg, beyond, {
                "distinct_accounts": int(n), "threshold": round(float(thr), 1),
                "baseline_median": st["median"], "baseline_p95": st["p95"], "burst_accounts": len(beyond)},
                f"{n} distinct customer accounts were touched on {date}; threshold for this employee is "
                f"{thr:.0f} (baseline median {st['median']:.0f}, p95 {st['p95']:.0f}).", base["status"] != "established"))
    return hits


def r04(ev, base, p, cfg):
    if base["status"] != "established":
        return []                      # familiarity needs personal history; skipped, not fabricated
    hits = []
    acc = ev[ev["customer_id"].notna() & ev["event_type"].isin(["account_access", "transaction_view", "sensitive_search"])]
    for date, g in acc.groupby("date"):
        unf_all = g[g["unfamiliar_customer"]].drop_duplicates("customer_id")
        n_all = g["customer_id"].nunique()
        if len(unf_all) >= p["min_count"] and len(unf_all) / max(n_all, 1) >= p["min_ratio"]:
            unf = _densest_burst(unf_all)
            hits.append(_mk("R04", cfg, unf, {
                "unfamiliar_accounts": len(unf_all), "burst_accounts": len(unf), "distinct_accounts": int(n_all),
                "ratio": round(len(unf) / n_all, 2), "familiar_set_size": len(base["familiar_customers"])},
                f"{len(unf_all)} of {n_all} accounts accessed on {date} were never seen in this employee's history "
                f"({len(base['familiar_customers'])} familiar accounts).", False))
    return hits


def r05(ev, base, p, cfg):
    unf = ev[ev["unfamiliar_resource"]]
    hits = []
    for date, g in unf.groupby("date"):
        if len(g) >= p["min_count"]:
            res = sorted(g["resource"].unique())
            hits.append(_mk("R05", cfg, g, {"resources": res},
                            f"Accessed resource(s) never used in this employee's baseline or role profile: {', '.join(res)}.",
                            base["status"] != "established"))
    return hits


def r06(ev, base, p, cfg):
    s = ev[ev["event_type"] == "sensitive_search"].sort_values("timestamp")
    if s.empty:
        return []
    thr = max(p["abs_min"], int(np.ceil(_stat(base, "max_sens_30min")["max"] * p["hist_mult"])))
    v = s["timestamp"].values.astype("datetime64[s]").astype("int64")
    right = np.searchsorted(v, v + p["window_min"] * 60, side="right")
    cnt = right - np.arange(len(v))
    hits, i = [], 0
    while i < len(v):
        if cnt[i] >= thr:
            rows = s.iloc[i:right[i]]
            hits.append(_mk("R06", cfg, rows, {"searches_in_window": int(cnt[i]), "window_min": p["window_min"],
                                              "threshold": int(thr)},
                            f"{cnt[i]} sensitive searches within {p['window_min']} min (threshold {thr}; "
                            f"personal historic max in a window: {_stat(base, 'max_sens_30min')['max']:.0f}).",
                            base["status"] != "established"))
            i = right[i]
        else:
            i += 1
    return hits


def r07(ev, base, p, cfg):
    st = _stat(base, "download_mb")
    d = ev[(ev["event_type"] == "bulk_download") & ev["volume_mb"].notna()]
    thr = max(p["abs_min_mb"], p["p95_mult"] * st["p95"])
    hits = []
    for _, row in d[d["volume_mb"] >= thr].iterrows():
        hits.append(_mk("R07", cfg, d.loc[[row.name]], {"volume_mb": float(row["volume_mb"]),
                                                       "threshold_mb": round(float(thr), 1), "baseline_p95_daily_mb": st["p95"]},
                        f"Download of {row['volume_mb']:.0f} MB exceeds threshold {thr:.0f} MB "
                        f"(baseline p95 daily volume {st['p95']:.0f} MB).", base["status"] != "established"))
    return hits


def r08(ev, base, p, cfg):
    st = _stat(base, "n_priv")
    priv = ev[ev["event_type"] == "privileged_op"]
    hits = []
    typical = st["p95"] > 0 or st["median"] > 0
    for date, g in priv.groupby("date"):
        reasons = []
        if not typical:
            reasons.append("this employee/role has no history of privileged operations")
        elif len(g) > max(p["abs_min_daily"], p["p95_mult"] * st["p95"]):
            reasons.append(f"{len(g)} privileged operations exceed daily threshold")
        off = g[g["off_hours"]]
        if len(off) and typical:
            reasons.append(f"{len(off)} privileged operation(s) outside usual working hours")
        if reasons:
            rows = g if not typical or len(g) > max(p["abs_min_daily"], p["p95_mult"] * st["p95"]) else off
            hits.append(_mk("R08", cfg, rows, {"privileged_ops": len(g), "reasons": reasons,
                                              "baseline_daily_p95": st["p95"]},
                            f"Unusual privileged activity on {date}: " + "; ".join(reasons) + ".",
                            base["status"] != "established"))
    return hits


def r09(ev, base, p, cfg):
    if base["status"] != "established":
        return []
    hits = []
    logins = ev[ev["event_type"].isin(["login_success"]) & (ev["new_device"] | ev["new_location"])]
    for date, g in logins.groupby("date"):
        nd, nl = bool(g["new_device"].any()), bool(g["new_location"].any())
        what = " and ".join(x for x, f in (("device", nd), ("location", nl)) if f)
        hits.append(_mk("R09", cfg, g, {"new_device": sorted(g.loc[g["new_device"], "device_id"].unique().tolist()),
                                       "new_location": sorted(g.loc[g["new_location"], "location"].unique().tolist())},
                        f"Login from a previously unseen {what} (known: {len(base['known_devices'])} device(s), "
                        f"{len(base['known_locations'])} location(s)).", False))
    return hits


def r10(ev, base, p, cfg):
    t = ev[(ev["event_type"] == "data_transfer") & ev["resource"].fillna("").str.startswith(p["prefix"])]
    return [_mk("R10", cfg, t.loc[[i]], {"destination": r["resource"], "volume_mb": r["volume_mb"]},
                f"Data transfer of {r['volume_mb']} MB to external destination '{r['resource']}'.", False)
            for i, r in t.iterrows()]


RULES: dict[str, Rule] = {
    "R01": Rule("R01", ["timestamp"], r01, "Login outside the employee's usual hours/weekdays.",
                "login_success hour outside [p1-margin, p99+margin] of own logins, or weekday never used"),
    "R02": Rule("R02", ["outcome"], r02, "Failed-login burst followed by successful login and sensitive activity.",
                ">= min_failed login_failed within window, then login_success + sensitive event within follow window"),
    "R03": Rule("R03", ["customer_id"], r03, "Distinct accounts touched in a day exceed personal robust upper fence.",
                "distinct customer_id/day > max(abs_min, max(p95, median + k*1.4826*MAD))"),
    "R04": Rule("R04", ["customer_id"], r04, "Many accounts never seen in the employee's history.",
                "unfamiliar accounts >= min_count AND ratio >= min_ratio (established baselines only)"),
    "R05": Rule("R05", ["resource"], r05, "Resource outside own and role baseline.",
                "resource not in employee's known resources"),
    "R06": Rule("R06", [], r06, "Burst of sensitive searches in a sliding window.",
                "sensitive_search count in window >= max(abs_min, hist_max*hist_mult)"),
    "R07": Rule("R07", ["volume_mb"], r07, "Download volume far above personal norm.",
                "bulk_download volume >= max(abs_min_mb, p95_mult*personal p95 daily volume)"),
    "R08": Rule("R08", [], r08, "Privileged operations unusual for this employee/role.",
                "no privileged history, or count > threshold, or outside usual hours"),
    "R09": Rule("R09", ["device_id", "location"], r09, "Login from device/location not previously seen.",
                "login_success with device/location not in baseline (established baselines only)"),
    "R10": Rule("R10", ["resource"], r10, "Data transfer to an external destination.",
                "data_transfer whose destination starts with the external prefix"),
}


def available_rules(events: pd.DataFrame, cfg: dict) -> tuple[list[str], dict[str, str]]:
    """Return (runnable rule ids, {skipped rule id: reason}) based on columns with data."""
    ok, skipped = [], {}
    for rid, rule in RULES.items():
        if not cfg["rules"][rid]["enabled"]:
            skipped[rid] = "disabled in configuration"
            continue
        missing = [c for c in rule.requires if c not in events.columns or events[c].notna().sum() == 0]
        if rid == "R09":
            missing = [c for c in rule.requires if c in missing] if len(missing) == len(rule.requires) else []
        if missing:
            skipped[rid] = f"required data missing: {', '.join(missing)}"
        else:
            ok.append(rid)
    return ok, skipped


def run_rules(enriched: pd.DataFrame, baselines: dict, cfg: dict, since: pd.Timestamp | None = None
              ) -> tuple[list[Hit], dict[str, str]]:
    """Run all runnable rules for each employee. ``since`` limits hits to the monitoring period.

    Rules evaluate the full employee history of enriched events but only keep hits whose
    events start at or after ``since``.
    """
    ok, skipped = available_rules(enriched, cfg)
    hits: list[Hit] = []
    for emp, g in enriched.groupby("employee_id"):
        base = baselines["employees"].get(emp)
        if not base or "login_hour_lo" not in base:
            continue
        g = g.sort_values("timestamp")
        if since is not None:
            g = g[g["timestamp"] >= since]
        if g.empty:
            continue
        for rid in ok:
            params = cfg["rules"][rid]["params"]
            hits.extend(RULES[rid].func(g, base, params, cfg))
    return hits, skipped


def describe_rules(cfg: dict) -> pd.DataFrame:
    rows = []
    for rid, rule in RULES.items():
        rc = cfg["rules"][rid]
        rows.append({"rule_id": rid, "name": rc["name"], "severity": rc["severity"], "enabled": rc["enabled"],
                     "condition": rule.condition, "parameters": rc["params"], "description": rule.description})
    return pd.DataFrame(rows)
