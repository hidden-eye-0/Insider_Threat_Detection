import json
import shutil

import pandas as pd
import pytest

from insider import db, forensics
from insider.config import load_config
from insider.evaluation import confusion_metrics, compare_methods
from insider.pipeline import process_workspace


@pytest.fixture()
def con(pipeline_env, tmp_path):
    """Writable copy of the processed workspace so tests can mutate it."""
    dst = tmp_path / "copy.db"
    pipeline_env["con"].commit()
    shutil.copy(pipeline_env["path"], dst)
    c = db.connect(dst)
    yield c
    c.close()


def top_alert(con):
    return con.execute("SELECT alert_id FROM alerts ORDER BY risk_score DESC LIMIT 1").fetchone()["alert_id"]


# ---------------------------------------------------------------- persistence
def test_schema_tables_and_indexes(con):
    names = {r["name"] for r in con.execute("SELECT name FROM sqlite_master")}
    for t in ("events", "alerts", "alert_events", "alert_rules", "investigations", "notes", "audit_log", "baselines", "ground_truth"):
        assert t in names
    assert "ix_events_emp_ts" in names and "ix_alerts_emp" in names


def test_status_note_disposition_persist_across_reconnect(con, tmp_path):
    aid = top_alert(con)
    db.update_investigation(con, aid, "Escalated", db.DISPOSITIONS[1], "Escalated to compliance for review", "alice")
    nid = db.add_note(con, aid, "alice", "Checked VPN logs; nothing unusual")
    con.commit()
    path = con.execute("PRAGMA database_list").fetchone()["file"]
    con2 = db.connect(path)
    inv = con2.execute("SELECT * FROM investigations WHERE alert_id=?", (aid,)).fetchone()
    assert inv["status"] == "Escalated" and inv["disposition"] == db.DISPOSITIONS[1]
    note = con2.execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone()
    assert note["alert_id"] == aid and note["author"] == "alice"
    other = [r["alert_id"] for r in con2.execute("SELECT alert_id FROM alerts WHERE alert_id!=? LIMIT 3", (aid,))]
    assert all(con2.execute("SELECT COUNT(*) c FROM notes WHERE alert_id=?", (o,)).fetchone()["c"] == 0 for o in other)
    con2.close()


def test_invalid_inputs_rejected(con):
    aid = top_alert(con)
    with pytest.raises(ValueError):
        db.update_investigation(con, aid, "Bogus", "Not set", "", "x")
    with pytest.raises(KeyError):
        db.add_note(con, "ALR-NOPE", "x", "text")
    with pytest.raises(ValueError):
        db.add_note(con, aid, "x", "   ")


def test_sql_injection_text_is_stored_literally(con):
    aid = top_alert(con)
    evil = "x'); DROP TABLE alerts;--"
    db.add_note(con, aid, evil, evil)
    assert con.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] > 0
    assert con.execute("SELECT note FROM notes WHERE author=?", (evil,)).fetchone()["note"] == evil


def test_reprocessing_does_not_duplicate_and_keeps_analyst_work(con):
    n_alerts = con.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    aid = top_alert(con)
    db.add_note(con, aid, "bob", "keep me")
    db.update_investigation(con, aid, "Under investigation", "Not set", "", "bob")
    process_workspace(con, load_config(), model_name="reprocess")
    assert con.execute("SELECT COUNT(*) c FROM alerts WHERE stale=0").fetchone()["c"] == n_alerts
    assert con.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] == n_alerts
    assert con.execute("SELECT COUNT(*) c FROM notes WHERE alert_id=?", (aid,)).fetchone()["c"] == 1
    assert con.execute("SELECT status FROM investigations WHERE alert_id=?", (aid,)).fetchone()["status"] == "Under investigation"


def test_audit_chain_detects_tampering(con):
    aid = top_alert(con)
    db.add_note(con, aid, "a", "one")
    db.add_note(con, aid, "a", "two")
    assert db.verify_audit_chain(con)[0] is True
    con.execute("UPDATE audit_log SET details='forged' WHERE id=(SELECT MIN(id) + 1 FROM audit_log)")
    ok, bad = db.verify_audit_chain(con)
    assert ok is False and bad is not None


def test_workspace_names_are_validated():
    for bad in ("../evil", "a/b", "", "x" * 50, "a.b"):
        with pytest.raises(ValueError):
            db.safe_workspace_name(bad)
    assert db.safe_workspace_name("ok_name-1") == "ok_name-1"


# ----------------------------------------------------------------- forensics
def test_timeline_ordering_and_membership(con):
    d = forensics.get_alert(con, top_alert(con))
    tl = d["timeline"]
    assert tl["timestamp"].is_monotonic_increasing
    assert tl["in_alert"].sum() == d["alert"]["risk_score"] * 0 + con.execute(
        "SELECT COUNT(*) c FROM alert_events WHERE alert_id=?", (d["alert"]["alert_id"],)).fetchone()["c"]
    assert (tl.loc[tl["in_alert"], "source_ref"].notna()).all()


def test_integrity_check_passes_then_detects_modification(con):
    d = forensics.get_alert(con, top_alert(con))
    ids = d["timeline"]["event_id"].tolist()
    assert forensics.verify_event_integrity(con, ids)["ok"]
    victim = d["timeline"].loc[d["timeline"]["in_alert"], "event_id"].iloc[0]
    con.execute("UPDATE events SET volume_mb = 1.0, customer_id='TAMPERED' WHERE event_id=?", (victim,))
    r = forensics.verify_event_integrity(con, ids)
    assert not r["ok"] and victim in r["mismatched"]


def test_summary_has_five_sections_and_report_is_consistent(con):
    aid = top_alert(con)
    db.add_note(con, aid, "carol", "analyst remark")
    d = forensics.get_alert(con, aid)
    s = forensics.investigation_summary(d)
    assert set(s) == {"observed_facts", "detection_signals", "inferred_relationships", "missing_or_uncertain_evidence", "analyst_conclusions"}
    assert all(s[k] for k in ("observed_facts", "detection_signals", "missing_or_uncertain_evidence", "analyst_conclusions"))
    html = forensics.report_html(d, {"synthetic": True}, forensics.verify_event_integrity(con, d["timeline"]["event_id"].tolist()))
    assert aid in html and d["alert"]["employee_id"] in html and "analyst remark" in html
    assert "not a probability" in html or "not probabilities" in html
    ej = json.loads(forensics.evidence_json(d))
    assert len(ej["timeline"]) == len(d["timeline"]) and ej["alert"]["alert_id"] == aid


def test_alert_csv_export_matches_table(con):
    df = forensics.alerts_df(con)
    out = pd.read_csv(pd.io.common.BytesIO(forensics.alerts_to_csv(df)))
    assert len(out) == len(df) and set(out["alert_id"]) == set(df["alert_id"])


# ---------------------------------------------------------------- evaluation
def test_confusion_metrics_known_values():
    m = confusion_metrics([1, 1, 1, 0, 0, 0, 0, 0], [1, 1, 0, 1, 0, 0, 0, 0])
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (2, 1, 4, 1)
    assert m["precision"] == pytest.approx(2 / 3) and m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 / 3) and m["accuracy"] == pytest.approx(6 / 8)
    assert m["balanced_accuracy"] == pytest.approx((2 / 3 + 4 / 5) / 2)


def test_confusion_metrics_undefined_cases():
    m = confusion_metrics([0, 0, 0], [0, 0, 0])
    assert m["precision"] is None and m["recall"] is None and m["f1"] is None and m["accuracy"] == 1.0
    assert confusion_metrics([1, 1], [0, 0])["f1"] == 0.0 or confusion_metrics([1, 1], [0, 0])["f1"] is None


def test_compare_methods_table():
    d = pd.DataFrame({"label": [1, 0, 1, 0], "a": [1, 0, 1, 1], "b": [0, 0, 1, 0]})
    t = compare_methods(d, {"A": "a", "B": "b"})
    assert list(t["method"]) == ["A", "B"] and t.loc[0, "fp"] == 1 and t.loc[1, "fn"] == 1


def test_evaluation_matches_recomputation(pipeline_env):
    ev = json.loads(pipeline_env["con"].execute("SELECT value FROM json_store WHERE name='evaluation'").fetchone()["value"])
    res, gt = pipeline_env["res"], pipeline_env["gt"]
    feats = res["feats"]
    day_lab = res["enriched"].merge(gt, on="event_id").groupby(["employee_id", "date"])["is_malicious"].max().reset_index()
    t = feats[feats["partition"] == "test"].merge(day_lab, on=["employee_id", "date"], how="left")
    m = confusion_metrics(t["is_malicious"].fillna(0).astype(bool), t["ml_flag"].astype(bool))
    stored = next(r for r in ev["methods"]["test"] if r["method"].startswith("ML-only (Isolation"))
    assert (stored["tp"], stored["fp"], stored["tn"], stored["fn"]) == (m["tp"], m["fp"], m["tn"], m["fn"])
    assert ev["partitions"]["test"]["employee_days"] == len(t)
