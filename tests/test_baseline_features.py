import numpy as np
import pandas as pd

from insider.baseline import build_baselines, enrich_events
from insider.features import FEATURE_COLUMNS, employee_day_features
from tests.conftest import history_rows, mk_events


def test_established_and_insufficient_baselines(pipeline_env):
    b = pipeline_env["res"]["baselines"]["employees"]
    assert b["EMP-1001"]["status"] == "established" and b["EMP-1001"]["history_days"] >= 20
    new = b["EMP-1099"]                       # new hire joins after the baseline window
    assert new["status"] == "insufficient" and new["fallback"] == "role baseline"
    assert new["familiar_customers"] == [] and new["known_devices"] == []


def test_baseline_excludes_tagged_events_and_future(cfg):
    rows = history_rows()
    rows.append(dict(timestamp="2026-03-10 21:00", event_type="login_success", device_id="D1", location="B1", context_tag="OT-1"))
    rows.append(dict(timestamp="2026-03-25 03:00", event_type="login_success", device_id="D9", location="B9"))  # after window
    ev = mk_events(rows)
    b = build_baselines(ev, pd.Timestamp("2026-03-21"), cfg)["employees"]["E1"]
    assert b["login_hour_hi"] < 12            # overtime login (21h) did not widen the window
    assert "D9" not in b["known_devices"]     # events after baseline end never used
    assert b["status"] == "established"


def test_enrichment_flags_novelty(cfg):
    ev = mk_events(history_rows() + [
        dict(timestamp="2026-03-23 03:00", event_type="login_success", device_id="D9", location="B9"),
        dict(timestamp="2026-03-23 03:05", event_type="account_access", customer_id="NEW1", resource="hr/payroll",
             device_id="D9", location="B9")])
    bl = build_baselines(ev, pd.Timestamp("2026-03-21"), cfg)
    en = enrich_events(ev, bl)
    last = en[en["timestamp"] >= "2026-03-23"]
    assert last["off_hours_login"].iloc[0] and last["new_device"].all() and last["new_location"].all()
    assert last["unfamiliar_customer"].iloc[1] and last["unfamiliar_resource"].iloc[1]
    assert not en[en["timestamp"] < "2026-03-21"]["new_device"].any()


def test_feature_matrix_consistent(pipeline_env):
    f = pipeline_env["res"]["feats"]
    assert all(c in f.columns for c in FEATURE_COLUMNS)
    assert not f[FEATURE_COLUMNS].isna().any().any()
    assert np.isfinite(f[FEATURE_COLUMNS].astype(float).values).all()
    assert f.duplicated(["employee_id", "date"]).sum() == 0
    again = employee_day_features(pipeline_env["res"]["enriched"], pipeline_env["res"]["baselines"])
    pd.testing.assert_frame_equal(again[FEATURE_COLUMNS].reset_index(drop=True),
                                  f[FEATURE_COLUMNS].reset_index(drop=True), check_dtype=False)
