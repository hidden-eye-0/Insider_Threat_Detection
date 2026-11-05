import hashlib

import pandas as pd
import pytest

from insider.generator import generate
from insider.preprocess import IngestError, read_csv_safely, record_hash, validate_and_clean


def test_generator_size_and_labels(pipeline_env):
    m, gt = pipeline_env["meta"], pipeline_env["gt"]
    assert m["n_events"] >= 10000 and m["synthetic"] is True
    assert set(gt["is_malicious"].unique()) == {0, 1}
    assert gt["event_id"].is_unique
    assert "full_chain" in set(gt["scenario_type"])


def test_generator_is_reproducible(tmp_path):
    generate(tmp_path / "a", seed=7)
    generate(tmp_path / "b", seed=7)

    def h(p):
        return hashlib.sha256((p / "bank_events.csv").read_bytes()).hexdigest()
    assert h(tmp_path / "a") == h(tmp_path / "b")


def test_no_incident_leakage_between_partitions(pipeline_env):
    ev, gt, meta = pipeline_env["events"], pipeline_env["gt"], pipeline_env["meta"]
    m = ev.merge(gt, on="event_id")
    mal = m[m["is_malicious"] == 1].copy()
    mal["ts"] = pd.to_datetime(mal["timestamp"])
    assert (mal["ts"] >= pd.Timestamp(meta["train_end"])).all(), "malicious events must not be in training history"
    part = mal["ts"].apply(lambda t: "val" if t < pd.Timestamp(meta["val_end"]) else "test")
    assert (mal.assign(p=part).groupby("scenario_id")["p"].nunique() == 1).all()


def test_missing_required_column():
    with pytest.raises(IngestError, match="Missing required"):
        validate_and_clean(pd.DataFrame({"event_id": ["1"], "timestamp": ["2026-01-01"]}))


def test_validation_rejects_and_normalises():
    raw = pd.DataFrame({
        "event_id": ["1", "2", "3", "3", "4", "5", None],
        "timestamp": ["2026-01-01 10:00:00", "not-a-date", "2026-01-01 11:00:00", "2026-01-01 11:00:00",
                      "2026-01-01 12:00:00", "2026-01-01 13:00:00", "2026-01-01 14:00:00"],
        "employee_id": ["A"] * 7, "event_type": ["LOGIN", "login", "download", "download", "Failed Login", "x_weird", "login"],
        "volume_mb": [None, None, "50", "50", "abc", None, None]})
    clean, rep = validate_and_clean(raw)
    assert rep["exact_duplicates_removed"] == 1
    reasons = {r["reason"] for r in rep["rejected_rows"]}
    assert {"unparseable timestamp", "non-numeric volume_mb", "missing event_id"} <= reasons
    assert set(clean["event_type"]) == {"login_success", "bulk_download", "x_weird"}
    assert rep["unrecognised_event_types"] == ["x_weird"]
    assert any("customer_id" in note for note in rep["limitations"])   # explicit limitation, nothing fabricated
    assert clean["record_hash"].str.len().eq(64).all()


def test_hash_is_deterministic_and_content_sensitive():
    r = {"event_id": "1", "timestamp": "2026-01-01", "employee_id": "A", "event_type": "login_success", "resource": None}
    assert record_hash(r) == record_hash(dict(r))
    assert record_hash(r) != record_hash({**r, "employee_id": "B"})


def test_upload_limits():
    with pytest.raises(IngestError):
        read_csv_safely(b"x" * (21 * 1024 * 1024))
    with pytest.raises(IngestError):
        read_csv_safely(b"")
    df = read_csv_safely(b"event_id,timestamp,employee_id,event_type\n1,2026-01-01,A,login\n")
    assert len(df) == 1
