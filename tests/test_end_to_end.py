"""End-to-end checks of the demonstration scenario and pipeline invariants."""
import json

import pandas as pd



def test_showcase_chain_is_critical_sequence(pipeline_env):
    alerts = pipeline_env["res"]["alerts"]
    hero = [a for a in alerts if a["employee_id"] == "EMP-1003" and a["dates"][0] == "2026-04-22" and a["kind"] == "sequence"]
    assert len(hero) == 1
    a = hero[0]
    assert a["priority"] == "Critical" and a["risk_score"] >= 75
    assert a["stages"] == ["login_anomaly", "account_access", "sensitive_search", "bulk_download", "data_transfer"]
    assert {"R01", "R03", "R06", "R07", "R10"} <= {h["rule_id"] for h in a["hits"]}


def test_all_simulated_incidents_in_test_are_detected(pipeline_env):
    ev = json.loads(pipeline_env["con"].execute("SELECT value FROM json_store WHERE name='evaluation'").fetchone()["value"])
    inc = pd.DataFrame(ev["incidents"])
    assert len(inc) >= 15
    assert inc["detected_combined"].mean() >= 0.9           # recorded outcome, see docs/EVALUATION.md
    chains = inc[inc["type"] == "full_chain"]
    assert (chains["best_alert_kind"] == "sequence").all()


def test_every_alert_is_explained_and_traceable(pipeline_env):
    con = pipeline_env["con"]
    rows = con.execute("SELECT alert_id, explanation FROM alerts").fetchall()
    assert rows
    for r in rows:
        assert len(r["explanation"]) > 40
        n = con.execute("SELECT COUNT(*) c FROM alert_events WHERE alert_id=?", (r["alert_id"],)).fetchone()["c"]
        assert n > 0
        assert con.execute("SELECT 1 FROM investigations WHERE alert_id=?", (r["alert_id"],)).fetchone()
    orphan = con.execute("SELECT COUNT(*) c FROM alert_events WHERE event_id NOT IN (SELECT event_id FROM events)").fetchone()["c"]
    assert orphan == 0


def test_ground_truth_never_used_as_feature(pipeline_env):
    from insider.features import FEATURE_COLUMNS
    assert not any("malicious" in c or "scenario" in c for c in FEATURE_COLUMNS)
    assert "is_malicious" not in pipeline_env["res"]["enriched"].columns


def test_training_uses_only_baseline_period(pipeline_env):
    res = pipeline_env["res"]
    m = res["model"]
    train = res["feats"][res["feats"]["partition"] == "train"]
    assert m.info["n_train_rows"] == len(train)
    assert train["date"].max() < str(res["split"]["train_end"].date())


def test_alert_ids_deterministic(pipeline_env):
    from insider.pipeline import analyze
    again = analyze(pipeline_env["events"], pipeline_env["res"]["cfg"], pipeline_env["res"]["split"], pipeline_env["gt"])
    assert [a["alert_id"] for a in again["alerts"]] == [a["alert_id"] for a in pipeline_env["res"]["alerts"]]
    assert [a["risk_score"] for a in again["alerts"]] == [a["risk_score"] for a in pipeline_env["res"]["alerts"]]


def test_workspace_import_of_upload_does_not_touch_existing(pipeline_env, tmp_path):
    """Sample CSV can be validated and processed into a separate DB (no ground truth)."""
    from insider import db
    from insider.pipeline import ingest_events, process_workspace
    from insider.preprocess import read_csv_safely, validate_and_clean
    sample = pipeline_env["synth"] / "sample_upload.csv"
    clean, rep = validate_and_clean(read_csv_safely(sample.read_bytes()))
    c2 = db.connect(tmp_path / "upload.db")
    ingest_events(c2, clean, rep, None, {"synthetic": False})
    before = pipeline_env["con"].execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    try:
        process_workspace(c2, model_name="upl")      # tiny history -> ML may be disabled, must not crash
    finally:
        c2.commit()
    assert pipeline_env["con"].execute("SELECT COUNT(*) c FROM events").fetchone()["c"] == before
    assert c2.execute("SELECT COUNT(*) c FROM events").fetchone()["c"] == len(clean)
    info = json.loads(c2.execute("SELECT value FROM json_store WHERE name='model_info'").fetchone()["value"])
    assert "ml_enabled" in info
    c2.close()
