"""Forensic investigation helpers: alert detail, timeline reconstruction, integrity checks,
structured investigation summary and report generation (HTML / CSV / JSON)."""
from __future__ import annotations

import html
import json
from datetime import datetime

import pandas as pd

from .preprocess import record_hash


def alerts_df(con) -> pd.DataFrame:
    q = """SELECT a.alert_id, a.employee_id, a.role, a.alert_type, a.kind, a.ts_detect, a.risk_score, a.priority,
                  a.ml_anomaly_score, a.ml_norm, a.context_coverage, a.baseline_status, a.stale,
                  i.status, i.disposition,
                  (SELECT group_concat(DISTINCT rule_id) FROM alert_rules r WHERE r.alert_id = a.alert_id) AS rules,
                  (SELECT COUNT(*) FROM alert_events e WHERE e.alert_id = a.alert_id) AS n_events,
                  a.explanation
           FROM alerts a LEFT JOIN investigations i ON i.alert_id = a.alert_id ORDER BY a.risk_score DESC, a.ts_detect"""
    df = pd.read_sql_query(q, con)
    df["rules"] = df["rules"].fillna("")
    return df


def get_alert(con, alert_id: str) -> dict:
    a = con.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if a is None:
        raise KeyError(f"Unknown alert {alert_id}")
    alert = dict(a)
    meta = json.loads(alert.pop("signals_json") or "{}")
    alert["signals"] = meta.get("signals", {})
    alert["missing_stages"] = meta.get("missing_stages", [])
    alert["max_z"] = meta.get("max_z")
    alert["stages"] = json.loads(alert.pop("stages_json") or "[]")
    rules = [dict(r) for r in con.execute("SELECT * FROM alert_rules WHERE alert_id=? ORDER BY id", (alert_id,))]
    for r in rules:
        r["evidence"] = json.loads(r.pop("evidence_json") or "{}")
        r["event_ids"] = json.loads(r.pop("event_ids_json") or "[]")
    inv = dict(con.execute("SELECT * FROM investigations WHERE alert_id=?", (alert_id,)).fetchone() or {})
    notes = [dict(n) for n in con.execute("SELECT * FROM notes WHERE alert_id=? ORDER BY id", (alert_id,))]
    base = con.execute("SELECT baseline_json FROM baselines WHERE employee_id=?", (alert["employee_id"],)).fetchone()
    return {"alert": alert, "rules": rules, "investigation": inv, "notes": notes,
            "baseline": json.loads(base["baseline_json"]) if base else None,
            "timeline": timeline(con, alert, rules)}


def timeline(con, alert: dict, rules: list[dict], context_minutes: int = 30) -> pd.DataFrame:
    """Chronological events for the alert window, marking alert members and the rules that cite each event."""
    members = {r["event_id"]: r["seq"] for r in con.execute("SELECT event_id, seq FROM alert_events WHERE alert_id=?", (alert["alert_id"],))}
    ev = pd.read_sql_query(
        "SELECT * FROM events WHERE employee_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp, event_id",
        con, params=(alert["employee_id"], alert["window_start"], alert["window_end"]))
    missing = [e for e in members if e not in set(ev["event_id"])]
    if missing:   # alert events outside the padded window (multi-day groups): fetch explicitly
        ph = ",".join("?" * len(missing))
        ev = pd.concat([ev, pd.read_sql_query(f"SELECT * FROM events WHERE event_id IN ({ph})", con, params=missing)])
        ev = ev.sort_values(["timestamp", "event_id"]).reset_index(drop=True)
    cites: dict[str, list[str]] = {}
    for r in rules:
        for e in r["event_ids"]:
            cites.setdefault(e, []).append(r["rule_id"])
    ev["in_alert"] = ev["event_id"].isin(members)
    ev["contributing_rules"] = ev["event_id"].map(lambda e: ",".join(sorted(set(cites.get(e, [])))))
    return ev


def verify_event_integrity(con, event_ids: list[str]) -> dict:
    """Recompute record hashes of stored events and compare with the hash captured at ingest."""
    if not event_ids:
        return {"checked": 0, "mismatched": [], "ok": True}
    ph = ",".join("?" * len(event_ids))
    df = pd.read_sql_query(f"SELECT * FROM events WHERE event_id IN ({ph})", con, params=list(event_ids))
    bad = []
    for r in df.to_dict("records"):
        row = {k: (None if pd.isna(v) else v) for k, v in r.items()}
        ts = pd.Timestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        row["timestamp"] = ts
        if record_hash(_canon(row)) != r["record_hash"]:
            bad.append(r["event_id"])
    return {"checked": len(df), "mismatched": bad, "ok": not bad}


def _canon(row: dict) -> dict:
    """Mirror the formatting used when the hash was computed at ingest (timestamps as pandas strings)."""
    out = dict(row)
    out["timestamp"] = str(pd.Timestamp(row["timestamp"]))
    for k in ("volume_mb", "record_count"):
        if out.get(k) is not None:
            out[k] = float(out[k])
    return out


def investigation_summary(detail: dict) -> dict:
    """Separate observed facts, detection signals, inferred relationships, missing evidence and analyst conclusions."""
    a, tl, inv = detail["alert"], detail["timeline"], detail["investigation"]
    members = tl[tl["in_alert"]]
    facts = [f"{len(members)} event(s) of employee {a['employee_id']} ({a['role']}) between "
             f"{members['timestamp'].min()} and {members['timestamp'].max()}."]
    for et, n in members["event_type"].value_counts().items():
        facts.append(f"{n} x {et}")
    if members["customer_id"].notna().any():
        facts.append(f"{members['customer_id'].nunique()} distinct customer accounts referenced.")
    if members["volume_mb"].notna().any():
        facts.append(f"Total data volume referenced: {members['volume_mb'].sum():.0f} MB.")
    devs = sorted(members["device_id"].dropna().unique()); locs = sorted(members["location"].dropna().unique())
    facts.append(f"Devices: {', '.join(devs) or 'n/a'}; locations: {', '.join(locs) or 'n/a'}.")
    signals = [f"{r['rule_id']} [{r['severity']}] {r['explanation']}" for r in detail["rules"]]
    if a.get("ml_anomaly_score") is not None:
        signals.append(f"ML anomaly score {a['ml_anomaly_score']:.3f} (severity index {a['ml_norm']:.2f}; an anomaly score, not a probability).")
    sg = a.get("signals", {})
    if sg:
        signals.append("Risk signals (0-1): " + ", ".join(f"{k}={v:.2f}" for k, v in sg.get("signals", {}).items())
                       + f"; context discount {sg.get('context_discount', 0):.0%}; final {a['risk_score']}/100.")
    inferred = []
    if a["stages"]:
        inferred.append("Activity progressed through stages: " + " -> ".join(a["stages"]) + ". This ordering is inferred from timestamps; it does not prove intent.")
    if a["kind"] == "sequence":
        inferred.append("The sequence resembles data-exfiltration preparation (access -> collection -> transfer); other explanations (e.g. an unrecorded authorised task) are not excluded.")
    if a["context_coverage"] and a["context_coverage"] > 0:
        inferred.append("Context tags suggest approved work, but tags are claims recorded in the log and need independent verification.")
    missing = []
    if a["baseline_status"] != "established":
        missing.append("Employee has limited history; comparisons use a role baseline (lower confidence).")
    if a["missing_stages"] and a["kind"] != "ml_only":
        missing.append("Stages not observed in this group: " + ", ".join(a["missing_stages"]) + ".")
    for col in ("customer_id", "device_id", "location", "volume_mb"):
        if members[col].isna().all():
            missing.append(f"No '{col}' values in contributing events.")
    missing.append("No access to HR records, ticketing systems, badge logs or the employee's explanation.")
    concl = [f"Status: {inv.get('status', 'n/a')}; disposition: {inv.get('disposition', 'n/a')}."]
    if inv.get("conclusion"):
        concl.append(inv["conclusion"])
    concl += [f"[{n['created_at']}] {n['author']}: {n['note']}" for n in detail["notes"]]
    return {"observed_facts": facts, "detection_signals": signals, "inferred_relationships": inferred,
            "missing_or_uncertain_evidence": missing, "analyst_conclusions": concl}


def report_html(detail: dict, dataset_info: dict, integrity: dict) -> str:
    a, tl = detail["alert"], detail["timeline"]
    summ = investigation_summary(detail)
    e = html.escape

    def ul(items):
        return "<ul>" + "".join(f"<li>{e(str(i))}</li>" for i in items) + "</ul>"
    rows = "".join(
        f"<tr class='{'in' if r.in_alert else 'ctx'}'><td>{e(str(r.timestamp))}</td><td>{e(r.event_type)}</td>"
        f"<td>{e(str(r.resource or ''))}</td><td>{e(str(r.customer_id or ''))}</td><td>{e(str(r.outcome or ''))}</td>"
        f"<td>{e(r.contributing_rules)}</td><td>{e(r.event_id)}</td><td>{e(str(r.source_ref or ''))}</td></tr>"
        for r in tl.itertuples())
    contrib = a.get("signals", {}).get("contributions", {})
    crow = "".join(f"<tr><td>{e(k)}</td><td>{a['signals']['signals'][k]:.2f}</td><td>{a['signals']['weights'][k]:.2f}</td><td>{v:.1f}</td></tr>" for k, v in contrib.items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Investigation report {e(a['alert_id'])}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1a2233}}
h1{{color:#0b2447}}h2{{border-bottom:2px solid #0b2447;padding-bottom:4px;margin-top:2rem}}table{{border-collapse:collapse;width:100%;font-size:12px}}
td,th{{border:1px solid #ccd;padding:4px 6px;text-align:left}}th{{background:#0b2447;color:#fff}}tr.ctx{{color:#778}}
.banner{{background:#fff4d6;border:1px solid #e0b000;padding:8px;border-radius:4px}}.pill{{padding:2px 8px;border-radius:10px;background:#0b2447;color:#fff}}</style></head><body>
<h1>Insider-Threat Investigation Report</h1>
<p class="banner"><b>Synthetic / simulated environment.</b> Alerts are prioritisation aids that require human review. Risk scores are not probabilities of
malicious intent and must never be used alone to accuse, discipline or block an employee.</p>
<p>Generated: {e(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} &middot; Dataset: {e(json.dumps(dataset_info))}</p>
<h2>Alert</h2><table><tr><th>Alert ID</th><td>{e(a['alert_id'])}</td><th>Employee</th><td>{e(a['employee_id'])} ({e(a['role'])})</td></tr>
<tr><th>Risk score</th><td>{a['risk_score']}/100 <span class="pill">{e(a['priority'])}</span></td><th>Detected</th><td>{e(a['ts_detect'])}</td></tr>
<tr><th>Window</th><td>{e(a['window_start'])} &ndash; {e(a['window_end'])}</td><th>Type / kind</th><td>{e(a['alert_type'])} / {e(a['kind'])}</td></tr>
<tr><th>Status</th><td>{e(detail['investigation'].get('status',''))}</td><th>Disposition</th><td>{e(detail['investigation'].get('disposition',''))}</td></tr></table>
<h2>Explanation</h2><p>{e(a['explanation'])}</p>
<h2>1. Observed facts</h2>{ul(summ['observed_facts'])}
<h2>2. Detection signals</h2>{ul(summ['detection_signals'])}
<h3>Risk score composition</h3><table><tr><th>Signal</th><th>Value (0-1)</th><th>Weight</th><th>Points</th></tr>{crow}</table>
<h2>3. Inferred relationships</h2>{ul(summ['inferred_relationships'] or ['None.'])}
<h2>4. Missing or uncertain evidence</h2>{ul(summ['missing_or_uncertain_evidence'])}
<h2>5. Analyst conclusions</h2>{ul(summ['analyst_conclusions'])}
<h2>Forensic timeline</h2><p>Bold rows are alert members; grey rows are surrounding context events.</p>
<table><tr><th>Timestamp</th><th>Event type</th><th>Resource</th><th>Customer</th><th>Outcome</th><th>Rules</th><th>Event ID</th><th>Source ref</th></tr>{rows}</table>
<h2>Evidence integrity</h2><p>{integrity['checked']} source records re-hashed (SHA-256) against hashes captured at ingest: {'all match' if integrity['ok'] else 'MISMATCH: ' + ', '.join(integrity['mismatched'])}.
This verifies consistency of stored records with their ingest fingerprint; it is not a tamper-proof guarantee.</p>
<h2>Methods and limitations</h2><ul><li>Detection: employee baselines, 10 configurable rules, Isolation Forest anomaly score, correlation, weighted risk score.</li>
<li>Limitations: synthetic data; thresholds tuned on a small synthetic validation split; context tags are unverified claims; no PDF export.</li></ul>
</body></html>"""


def alerts_to_csv(df: pd.DataFrame) -> bytes:
    return df.drop(columns=["explanation"], errors="ignore").to_csv(index=False).encode("utf-8")


def evidence_json(detail: dict) -> str:
    a = detail["alert"]
    payload = {"alert": a, "rules": detail["rules"], "investigation": detail["investigation"], "notes": detail["notes"],
               "summary": investigation_summary(detail),
               "timeline": json.loads(detail["timeline"].to_json(orient="records", date_format="iso"))}
    return json.dumps(payload, indent=2, default=str)
