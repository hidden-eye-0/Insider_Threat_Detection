"""End-to-end analysis pipeline and persistence.

``analyze`` is pure (DataFrames in, results out) so it is unit-testable;
``process_workspace`` / ``ingest_events`` wire it to SQLite.
"""
from __future__ import annotations

import hashlib
import json
import logging

import numpy as np
import pandas as pd

from . import db
from .baseline import build_baselines, enrich_events
from .config import load_config
from .correlation import Group, correlate, find_missing_stages
from .evaluation import compare_methods
from .features import employee_day_features, top_deviations
from .ml import AnomalyModel, InsufficientDataError
from .risk import score_signals
from .rules import Hit, run_rules

log = logging.getLogger("insider.pipeline")


def alert_id_for(employee_id: str, kind: str, first_event_id: str) -> str:
    return "ALR-" + hashlib.sha1(f"{employee_id}|{kind}|{first_event_id}".encode()).hexdigest()[:8].upper()


def compute_split(events: pd.DataFrame, cfg: dict, meta: dict | None = None) -> dict:
    """Return train_end / val_end timestamps (explicit from dataset meta, else by time fractions)."""
    if meta and meta.get("train_end") and meta.get("val_end"):
        return {"train_end": pd.Timestamp(meta["train_end"]), "val_end": pd.Timestamp(meta["val_end"]), "source": "dataset metadata"}
    ts = pd.to_datetime(events["timestamp"])
    t0, t1 = ts.min().normalize(), ts.max().normalize() + pd.Timedelta(days=1)
    span = t1 - t0
    s = cfg["split"]
    return {"train_end": (t0 + span * s["train_frac"]).normalize(),
            "val_end": (t0 + span * (s["train_frac"] + s["val_frac"])).normalize(), "source": "time fractions"}


def _partition(date_str: str, split: dict) -> str:
    d = pd.Timestamp(date_str)
    return "train" if d < split["train_end"] else "validation" if d < split["val_end"] else "test"


def analyze(events: pd.DataFrame, cfg: dict | None = None, split: dict | None = None,
            gt: pd.DataFrame | None = None) -> dict:
    """Run baselines, rules, ML, correlation and risk scoring over a clean event frame."""
    cfg = cfg or load_config()
    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"])
    split = split or compute_split(events, cfg)
    warnings: list[str] = []

    baselines = build_baselines(events, split["train_end"], cfg)
    enriched = enrich_events(events, baselines)
    hits, skipped = run_rules(enriched, baselines, cfg, since=split["train_end"])

    feats = employee_day_features(enriched, baselines, cfg["ml"]["z_cap"])
    feats["partition"] = [_partition(d, split) for d in feats["date"]]
    model, ml_ok = AnomalyModel(n_estimators=cfg["ml"]["n_estimators"]), True
    train = feats[feats["partition"] == "train"]
    gt_days = _day_labels(enriched, gt) if gt is not None else None
    try:
        model.fit(train, cfg["ml"]["min_train_rows"], cfg["ml"]["default_threshold_quantile"])
        if gt_days is not None:
            _select_threshold(model, feats, gt_days, cfg)
        scores = model.score(feats)
        feats = pd.concat([feats, scores], axis=1)
    except InsufficientDataError as exc:
        ml_ok = False
        warnings.append(f"ML disabled: {exc} Risk weights renormalised.")
        feats[["anomaly_score", "ml_norm", "lof_score"]] = 0.0
        feats[["ml_flag", "lof_flag"]] = False

    groups = correlate(enriched, hits, cfg)
    alerts = build_alerts(groups, enriched, feats, baselines, cfg, ml_ok, split)
    return {"cfg": cfg, "split": split, "baselines": baselines, "enriched": enriched, "hits": hits,
            "skipped_rules": skipped, "feats": feats, "model": model if ml_ok else None, "ml_ok": ml_ok,
            "groups": groups, "alerts": alerts, "warnings": warnings}


def _day_labels(enriched: pd.DataFrame, gt: pd.DataFrame) -> pd.DataFrame:
    m = enriched[["event_id", "employee_id", "date"]].merge(gt[["event_id", "is_malicious"]], on="event_id", how="left")
    d = m.groupby(["employee_id", "date"])["is_malicious"].max().fillna(0).astype(bool).reset_index()
    return d.rename(columns={"is_malicious": "label"})


def _select_threshold(model: AnomalyModel, feats: pd.DataFrame, gt_days: pd.DataFrame, cfg: dict) -> None:
    """Choose the ML threshold quantile by F1 on the VALIDATION partition only."""
    val = feats[feats["partition"] == "validation"].merge(gt_days, on=["employee_id", "date"], how="left")
    if val.empty or not val["label"].fillna(False).astype(bool).any():
        return
    best, best_f1 = cfg["ml"]["default_threshold_quantile"], -1.0
    from .evaluation import confusion_metrics
    for q in cfg["ml"]["threshold_quantile_candidates"]:
        model.set_threshold_quantile(q)
        flag = model.score(val)["ml_flag"].values
        f1 = confusion_metrics(val["label"].fillna(False), flag)["f1"] or 0.0
        if f1 > best_f1:
            best, best_f1 = q, f1
    model.set_threshold_quantile(best)
    model.info["threshold_selected_on"] = "validation"
    model.info["validation_f1_at_selection"] = round(best_f1, 4)


# --------------------------------------------------------------------------- alerts
def build_alerts(groups: list[Group], enriched: pd.DataFrame, feats: pd.DataFrame, baselines: dict,
                 cfg: dict, ml_ok: bool, split: dict) -> list[dict]:
    fi = feats.set_index(["employee_id", "date"])
    by_id = enriched.set_index("event_id")
    alerts: list[dict] = []
    covered: set[tuple[str, str]] = set()
    for g in groups:
        sub = by_id.loc[g.event_ids].sort_values("timestamp")
        dates = sorted({str(d) for d in sub["date"]})
        rows = [fi.loc[(g.employee_id, d)] for d in dates if (g.employee_id, d) in fi.index]
        for d in dates:
            covered.add((g.employee_id, d))
        ml_norm = max((float(r["ml_norm"]) for r in rows), default=0.0)
        ml_raw = max((float(r["anomaly_score"]) for r in rows), default=0.0)
        max_z = max((max([v for _, v in top_deviations(r, 1)] or [0.0]) for r in rows), default=0.0)
        sev = {}
        for h in g.hits:
            if h.rule_id not in sev or cfg["severity_weight"][h.severity] > cfg["severity_weight"][sev[h.rule_id]]:
                sev[h.rule_id] = h.severity
        coverage = float(sub["context_tag"].notna().mean())
        sc = score_signals(sev, ml_norm if ml_ok else None, max_z, g.core_stages, g.ordered,
                           sub["event_type"].tolist(), coverage, cfg)
        base = baselines["employees"].get(g.employee_id, {})
        alerts.append(_alert_dict(g, sub, sc, rows, ml_raw, ml_norm, coverage, base, cfg, max_z))
    # ML-only alerts: flagged employee-days not covered by any rule group
    if ml_ok:
        fl = feats[(feats["ml_flag"]) & (feats["partition"] != "train")]
        for _, r in fl.iterrows():
            if (r["employee_id"], r["date"]) in covered:
                continue
            day = enriched[(enriched["employee_id"] == r["employee_id"]) & (enriched["date"] == r["date"])]
            flagged = day[day[["off_hours", "unfamiliar_customer", "unfamiliar_resource", "new_device", "new_location"]].any(axis=1)]
            sub = (flagged if len(flagged) else day).sort_values("timestamp").head(300)
            sc = score_signals({}, float(r["ml_norm"]), max([v for _, v in top_deviations(r, 1)] or [0.0]), 0, True,
                               sub["event_type"].tolist(), float(sub["context_tag"].notna().mean()), cfg)
            g = Group(r["employee_id"], sub["timestamp"].min(), sub["timestamp"].max(), sub["event_id"].tolist(), [], [], 0, True, "ml_only", "")
            devs = ", ".join(f"{k} (z={v:.1f})" for k, v in top_deviations(r, 3)) or "no single dominant feature"
            g.explanation = ("No detection rule fired, but this employee-day is statistically unusual for the model "
                             f"(anomaly score {r['anomaly_score']:.3f}). Largest deviations from the employee's baseline: {devs}.")
            base = baselines["employees"].get(r["employee_id"], {})
            alerts.append(_alert_dict(g, sub, sc, [r], float(r["anomaly_score"]), float(r["ml_norm"]),
                                      float(sub["context_tag"].notna().mean()), base, cfg,
                                      max([v for _, v in top_deviations(r, 1)] or [0.0]), alert_type="ml_anomaly"))
    alerts = [a for a in alerts if a["risk_score"] >= cfg["risk"]["alert_min_score"]]
    alerts.sort(key=lambda a: (-a["risk_score"], a["ts_detect"]))
    return alerts


def _alert_dict(g: Group, sub: pd.DataFrame, sc: dict, rows, ml_raw, ml_norm, coverage, base, cfg, max_z,
                alert_type: str = "rule_correlation") -> dict:
    first_id = sub.index[0] if sub.index.name == "event_id" else sub["event_id"].iloc[0]
    event_ids = sub.index.tolist() if sub.index.name == "event_id" else sub["event_id"].tolist()
    window_start, window_end = g.ts_start - pd.Timedelta(minutes=30), g.ts_end + pd.Timedelta(minutes=30)
    why = [f"{h.rule_id} {h.rule_name}: {h.explanation}" for h in _dedupe_hits(g.hits)]
    parts = [f"Risk {sc['risk_score']:.0f}/100 ({sc['priority']} priority) for {g.employee_id}.", g.explanation]
    if why:
        parts.append("Triggered rules: " + " | ".join(why))
    if ml_ok_flag(ml_norm):
        parts.append(f"ML anomaly score {ml_raw:.3f} (severity index {ml_norm:.2f}; not a probability).")
    if coverage > 0:
        tags = sorted(sub["context_tag"].dropna().unique())[:3]
        parts.append(f"{coverage:.0%} of contributing events carry an approval/context tag ({', '.join(tags)}); "
                     f"score reduced by {sc['context_discount']:.0%}. Tags are claims and must be verified by the analyst.")
    if base.get("status") == "insufficient":
        parts.append(f"Limited history ({base.get('history_days', 0)} days): role baseline used; confidence is lower.")
    return {
        "alert_id": alert_id_for(g.employee_id, alert_type, first_id), "employee_id": g.employee_id,
        "role": base.get("role", "unknown"), "alert_type": alert_type, "kind": g.kind,
        "ts_detect": str(g.ts_end), "window_start": str(window_start), "window_end": str(window_end),
        "risk_score": sc["risk_score"], "priority": sc["priority"], "ml_anomaly_score": float(ml_raw),
        "ml_norm": float(ml_norm), "explanation": " ".join(parts), "signals": sc, "stages": g.stages,
        "missing_stages": find_missing_stages(g) if g.kind != "ml_only" else [],
        "context_coverage": coverage, "baseline_status": base.get("status", "unknown"),
        "event_ids": event_ids, "hits": [h.to_dict() for h in g.hits], "max_z": max_z,
        "dates": sorted({str(d) for d in sub["date"]}),
    }


def ml_ok_flag(ml_norm: float) -> bool:
    return ml_norm is not None and ml_norm > 0


def _dedupe_hits(hits: list[Hit]) -> list[Hit]:
    out, seen = [], set()
    for h in hits:
        if (h.rule_id, h.explanation) not in seen:
            seen.add((h.rule_id, h.explanation)); out.append(h)
    return out


# ------------------------------------------------------------------- evaluation
def evaluate(res: dict, gt: pd.DataFrame, scenarios: list[dict] | None = None) -> dict:
    """Employee-day level evaluation on validation and test partitions + extra operational metrics."""
    enriched, feats, alerts = res["enriched"], res["feats"], res["alerts"]
    labels = _day_labels(enriched, gt)
    d = feats.merge(labels, on=["employee_id", "date"], how="left")
    d["label"] = d["label"].fillna(False).astype(bool)
    key = lambda e, dt: (e, dt)  # noqa: E731
    rule_days = {key(h.employee_id, str(x)) for h in res["hits"] for x in pd.to_datetime(enriched.loc[enriched["event_id"].isin(h.event_ids), "timestamp"]).dt.date.astype(str).unique()}
    alert_days, high_days = set(), set()
    for a in alerts:
        for dt in a["dates"]:
            alert_days.add(key(a["employee_id"], dt))
            if a["priority"] in ("High", "Critical"):
                high_days.add(key(a["employee_id"], dt))
    keys = list(zip(d["employee_id"], d["date"]))
    d["rule_only"] = [k in rule_days for k in keys]
    d["ml_only"] = d["ml_flag"].astype(bool)
    d["lof_only"] = d["lof_flag"].astype(bool)
    d["combined"] = [k in alert_days for k in keys]
    d["combined_high"] = [k in high_days for k in keys]
    methods = {"Rule-only (any rule hit)": "rule_only", "ML-only (Isolation Forest)": "ml_only",
               "ML-only (LOF, 2nd detector)": "lof_only",
               "Combined (rules+ML+correlation+risk, any alert)": "combined",
               "Combined (High/Critical alerts only)": "combined_high"}
    out: dict = {"methods": {}, "partitions": {}, "label_method": "employee-day is positive if it contains >=1 event from a simulated malicious incident"}
    for part in ("validation", "test"):
        p = d[d["partition"] == part]
        tbl = compare_methods(p, methods)
        out["methods"][part] = tbl.to_dict("records")
        out["partitions"][part] = {"employee_days": int(len(p)), "positive_days": int(p["label"].sum()),
                                   "negative_days": int((~p["label"]).sum()), "start": p["date"].min(), "end": p["date"].max()}
    # alert-level quality in test
    test_alerts = [a for a in alerts if pd.Timestamp(a["dates"][0]) >= res["split"]["val_end"]]
    gt_idx = gt.set_index("event_id")
    mal = gt_idx["is_malicious"].astype(bool)
    n_tp_alerts = sum(any(mal.get(e, False) for e in a["event_ids"]) for a in test_alerts)
    n_emp = enriched["employee_id"].nunique()
    t_start = res["split"]["val_end"]
    t_end = pd.to_datetime(enriched["date"]).max() + pd.Timedelta(days=1)
    weeks = max((t_end - t_start).days / 7, 1e-9)
    fa = len(test_alerts) - n_tp_alerts
    out["alert_quality_test"] = {
        "alerts": len(test_alerts), "alerts_containing_malicious_events": int(n_tp_alerts),
        "alert_precision": (n_tp_alerts / len(test_alerts)) if test_alerts else None,
        "false_alerts": int(fa), "false_alerts_per_employee_week": fa / n_emp / weeks,
        "alerts_with_explanation": sum(bool(a["explanation"].strip()) for a in test_alerts),
        "alerts_with_timeline": sum(len(a["event_ids"]) > 0 for a in test_alerts),
        "alerts_with_source_refs": sum(bool(enriched[enriched["event_id"].isin(a["event_ids"])]["source_ref"].notna().all()) for a in test_alerts),
        "employees": int(n_emp), "test_weeks": round(weeks, 2),
    }
    # incident-level detection
    inc = []
    scen_events = gt[gt["is_malicious"] == 1].groupby("scenario_id")["event_id"].apply(set).to_dict()
    kind_of = gt[gt["is_malicious"] == 1].drop_duplicates("scenario_id").set_index("scenario_id")["scenario_type"].to_dict()
    ev_dates = enriched.set_index("event_id")["date"]
    for sid, eids in scen_events.items():
        part = _partition(ev_dates[next(iter(eids))], res["split"])
        if part == "train":
            continue
        best_cov, best_alert = 0.0, None
        for a in alerts:
            cov = len(eids & set(a["event_ids"])) / len(eids)
            if cov > best_cov:
                best_cov, best_alert = cov, a
        emp = enriched.set_index("event_id").loc[next(iter(eids)), "employee_id"]
        day = ev_dates[next(iter(eids))]
        rule_det = (emp, day) in rule_days
        ml_det = bool(((feats["employee_id"] == emp) & (feats["date"] == day) & feats["ml_flag"]).any())
        inc.append({"scenario_id": sid, "type": kind_of[sid], "partition": part, "events": len(eids),
                    "detected_rule_only": rule_det, "detected_ml_only": ml_det,
                    "detected_combined": best_cov > 0, "event_coverage_in_best_alert": round(best_cov, 3),
                    "best_alert": best_alert["alert_id"] if best_alert else None,
                    "best_alert_priority": best_alert["priority"] if best_alert else None,
                    "best_alert_kind": best_alert["kind"] if best_alert else None})
    out["incidents"] = inc
    chains = [i for i in inc if i["type"] == "full_chain"]
    out["multi_event_scenarios"] = {
        "full_chain_incidents": len(chains),
        "detected_as_correlated_sequence": sum(i["best_alert_kind"] == "sequence" for i in chains),
        "mean_event_coverage": float(np.mean([i["event_coverage_in_best_alert"] for i in chains])) if chains else None,
        "critical_or_high": sum(i["best_alert_priority"] in ("High", "Critical") for i in chains),
    }
    return out


# -------------------------------------------------------------------- persistence
def ingest_events(con, events: pd.DataFrame, report: dict, gt: pd.DataFrame | None, meta: dict | None,
                  actor: str = "system") -> None:
    """Replace the workspace's event data (workspace is a fresh/local simulated environment)."""
    for t in ("alert_events", "alert_rules", "notes", "investigations", "alerts", "baselines", "ground_truth", "events"):
        con.execute(f"DELETE FROM {t}")
    cols = ["event_id", "timestamp", "employee_id", "role", "event_type", "resource", "customer_id", "device_id",
            "location", "volume_mb", "record_count", "outcome", "context_tag", "source_ref", "record_hash"]
    ev = events[cols].copy()
    ev["timestamp"] = pd.to_datetime(ev["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    ev = ev.astype(object).where(ev.notna(), None)
    con.executemany(f"INSERT INTO events({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", ev.values.tolist())
    if gt is not None:
        con.executemany("INSERT OR REPLACE INTO ground_truth VALUES (?,?,?,?)",
                        gt[["event_id", "is_malicious", "scenario_type", "scenario_id"]].astype(object).where(gt.notna(), None).values.tolist())
    db.set_json(con, "quality_report", report)
    db.set_json(con, "dataset_meta", meta or {"synthetic": False})
    db.audit(con, actor, "ingest_events", "events", {"rows": len(ev), "has_ground_truth": gt is not None})


def load_events(con) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM events ORDER BY timestamp, event_id", con, parse_dates=["timestamp"])


def process_workspace(con, cfg: dict | None = None, actor: str = "system", model_name: str = "model") -> dict:
    """Run the analysis on the events in ``con``; persist baselines, alerts, metrics. Idempotent."""
    cfg = cfg or load_config()
    events = load_events(con)
    if events.empty:
        raise ValueError("Workspace has no events. Load the demo dataset or upload a CSV first.")
    gt = pd.read_sql_query("SELECT * FROM ground_truth", con)
    gt = gt if len(gt) else None
    meta = db.get_json(con, "dataset_meta", {})
    split = compute_split(events, cfg, meta if meta.get("train_end") else None)
    res = analyze(events, cfg, split, gt)
    # baselines
    con.execute("DELETE FROM baselines")
    con.executemany("INSERT INTO baselines VALUES (?,?,?,?,?)",
                    [(e, b["role"], b["status"], b["history_days"], json.dumps(b)) for e, b in res["baselines"]["employees"].items()])
    db.set_json(con, "role_baselines", res["baselines"]["roles"])
    db.set_json(con, "baseline_meta", res["baselines"]["meta"])
    # employee-day scores
    feats = res["feats"].copy()
    feats.to_sql("employee_days", con, if_exists="replace", index=False)
    # alerts (upsert; keep analyst work)
    new_ids = {a["alert_id"] for a in res["alerts"]}
    old = {r["alert_id"] for r in con.execute("SELECT alert_id FROM alerts")}
    for aid in old - new_ids:
        touched = con.execute("SELECT 1 FROM notes WHERE alert_id=? UNION SELECT 1 FROM investigations WHERE alert_id=? AND status!='Pending review'", (aid, aid)).fetchone()
        if touched:
            con.execute("UPDATE alerts SET stale=1 WHERE alert_id=?", (aid,))
        else:
            con.execute("DELETE FROM alerts WHERE alert_id=?", (aid,))
    for a in res["alerts"]:
        con.execute("DELETE FROM alert_events WHERE alert_id=?", (a["alert_id"],))
        con.execute("DELETE FROM alert_rules WHERE alert_id=?", (a["alert_id"],))
        con.execute("""INSERT INTO alerts(alert_id, employee_id, role, alert_type, kind, ts_detect, window_start, window_end,
                       risk_score, priority, ml_anomaly_score, ml_norm, explanation, signals_json, stages_json,
                       context_coverage, baseline_status, stale, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)
                       ON CONFLICT(alert_id) DO UPDATE SET role=excluded.role, alert_type=excluded.alert_type, kind=excluded.kind,
                       ts_detect=excluded.ts_detect, window_start=excluded.window_start, window_end=excluded.window_end,
                       risk_score=excluded.risk_score, priority=excluded.priority, ml_anomaly_score=excluded.ml_anomaly_score,
                       ml_norm=excluded.ml_norm, explanation=excluded.explanation, signals_json=excluded.signals_json,
                       stages_json=excluded.stages_json, context_coverage=excluded.context_coverage,
                       baseline_status=excluded.baseline_status, stale=0""",
                    (a["alert_id"], a["employee_id"], a["role"], a["alert_type"], a["kind"], a["ts_detect"], a["window_start"],
                     a["window_end"], a["risk_score"], a["priority"], a["ml_anomaly_score"], a["ml_norm"], a["explanation"],
                     json.dumps({"signals": a["signals"], "missing_stages": a["missing_stages"], "max_z": a["max_z"],
                                 "dates": a["dates"]}), json.dumps(a["stages"]), a["context_coverage"],
                     a["baseline_status"], db.now()))
        con.executemany("INSERT INTO alert_events VALUES (?,?,?)", [(a["alert_id"], e, i) for i, e in enumerate(a["event_ids"])])
        con.executemany("""INSERT INTO alert_rules(alert_id, rule_id, rule_name, severity, explanation, evidence_json,
                           low_confidence, event_ids_json) VALUES (?,?,?,?,?,?,?,?)""",
                        [(a["alert_id"], h["rule_id"], h["rule_name"], h["severity"], h["explanation"],
                          json.dumps(h["evidence"], default=str), int(h["low_confidence"]), json.dumps(h["event_ids"])) for h in a["hits"]])
        con.execute("INSERT OR IGNORE INTO investigations(alert_id, status, disposition, conclusion, updated_at) VALUES (?, 'Pending review','Not set','',?)",
                    (a["alert_id"], db.now()))
    # model info
    model_path = None
    info = {"ml_enabled": res["ml_ok"], "warnings": res["warnings"], "skipped_rules": res["skipped_rules"],
            "split": {k: str(v) for k, v in res["split"].items()}, "trained_at": db.now()}
    if res["ml_ok"]:
        m = res["model"]
        model_path = m.save(model_name)
        info.update(m.info)
        info.update({"threshold_quantile": m.threshold_quantile, "threshold": m.threshold, "score_q50": m.q_lo,
                     "score_q999": m.q_hi, "model_path": model_path,
                     "train_range": [str(feats[feats.partition == 'train']['date'].min()), str(feats[feats.partition == 'train']['date'].max())]})
    db.set_json(con, "model_info", info)
    if gt is not None:
        ev_res = evaluate(res, gt)
        db.set_json(con, "evaluation", ev_res)
    db.audit(con, actor, "process_workspace", "alerts", {"alerts": len(res["alerts"]), "hits": len(res["hits"])})
    return res
