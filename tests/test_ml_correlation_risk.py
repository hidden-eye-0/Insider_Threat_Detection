import numpy as np
import pandas as pd
import pytest

from insider import ml as mlmod
from insider.baseline import build_baselines, enrich_events
from insider.config import priority_for
from insider.correlation import correlate
from insider.features import FEATURE_COLUMNS
from insider.ml import AnomalyModel, InsufficientDataError
from insider.risk import rule_signal, score_signals
from insider.rules import run_rules
from tests.conftest import history_rows, mk_events

END = pd.Timestamp("2026-03-21")


# ----------------------------------------------------------------- ML
def test_model_trains_scores_and_is_deterministic(pipeline_env):
    feats = pipeline_env["res"]["feats"]
    train = feats[feats["partition"] == "train"]
    a = AnomalyModel(n_estimators=50).fit(train)
    b = AnomalyModel(n_estimators=50).fit(train)
    sa, sb = a.score(feats), b.score(feats)
    assert list(sa.columns) == ["anomaly_score", "ml_norm", "lof_score", "ml_flag", "lof_flag"] or set(sa.columns) >= {"anomaly_score", "ml_norm", "ml_flag"}
    assert len(sa) == len(feats) and sa["ml_norm"].between(0, 1).all()
    np.testing.assert_allclose(sa["anomaly_score"], sb["anomaly_score"])


def test_obvious_anomaly_scores_higher_than_typical_day(pipeline_env):
    feats = pipeline_env["res"]["feats"]
    model = pipeline_env["res"]["model"]
    typical = feats[feats["partition"] == "train"].iloc[[0]].copy()
    weird = typical.copy()
    for c, v in {"n_events": 400, "distinct_accounts": 200, "download_mb": 5000, "max_download_mb": 5000,
                 "n_transfer": 3, "z_distinct_accounts": 20, "z_download_mb": 20, "off_hours_events": 300}.items():
        weird[c] = v
    assert model.score(weird)["anomaly_score"].iloc[0] > model.score(typical)["anomaly_score"].iloc[0]


def test_model_insufficient_data_and_persistence(pipeline_env, tmp_path):
    feats = pipeline_env["res"]["feats"]
    with pytest.raises(InsufficientDataError):
        AnomalyModel().fit(feats.head(10))
    mlmod.MODEL_DIR = tmp_path
    m = pipeline_env["res"]["model"]
    path = m.save("roundtrip")
    loaded = AnomalyModel.load(path)
    np.testing.assert_allclose(loaded.score(feats.head(20))["anomaly_score"], m.score(feats.head(20))["anomaly_score"])
    assert set(FEATURE_COLUMNS) == set(m.info["features"])


# ------------------------------------------------------------ correlation
def _analyse(rows, cfg):
    ev = mk_events(history_rows() + rows)
    bl = build_baselines(ev, END, cfg)
    en = enrich_events(ev, bl)
    hits, _ = run_rules(en, bl, cfg, since=END)
    return en, hits, correlate(en, hits, cfg)


def chain_rows(day="2026-03-23", tag=None):
    t = lambda h, m: f"{day} {h:02d}:{m:02d}"  # noqa: E731
    rows = [dict(timestamp=t(2, 0), event_type="login_success", device_id="D9", location="X1", context_tag=tag)]
    rows += [dict(timestamp=t(2, 5 + i % 40), event_type="account_access", customer_id=f"Z{i}", resource="core/accounts",
                  device_id="D9", location="X1", context_tag=tag) for i in range(30)]
    rows += [dict(timestamp=t(2, 50 + i % 8), event_type="sensitive_search", customer_id=f"Q{i}", device_id="D9", location="X1", context_tag=tag) for i in range(12)]
    rows += [dict(timestamp=t(3, 10), event_type="bulk_download", volume_mb=900.0, resource="db/export", device_id="D9", location="X1", context_tag=tag),
             dict(timestamp=t(3, 20), event_type="data_transfer", volume_mb=850.0, resource="external:fs", device_id="D9", location="X1", context_tag=tag)]
    return rows


def test_suspicious_sequence_is_correlated(cfg):
    en, hits, groups = _analyse(chain_rows(), cfg)
    seq = [g for g in groups if g.kind == "sequence"]
    assert len(seq) == 1
    g = seq[0]
    assert g.core_stages == 5 and g.ordered and g.stages[0] == "login_anomaly" and g.stages[-1] == "data_transfer"
    assert "Complete multi-stage sequence" in g.explanation


def test_events_assigned_to_exactly_one_group(cfg):
    _, _, groups = _analyse(chain_rows() + chain_rows("2026-03-25"), cfg)
    all_ids = [e for g in groups for e in g.event_ids]
    assert len(all_ids) == len(set(all_ids))
    assert len([g for g in groups if g.kind == "sequence"]) == 2     # separate days -> separate groups


def test_isolated_anomaly_distinguished(cfg):
    _, _, groups = _analyse([dict(timestamp="2026-03-23 12:00", event_type="bulk_download", volume_mb=900.0, device_id="D1", location="B1")], cfg)
    assert [g.kind for g in groups] == ["isolated"]
    assert "Isolated anomaly" in groups[0].explanation


def test_incomplete_sequence_with_missing_fields(cfg):
    rows = [dict(timestamp="2026-03-23 02:00", event_type="login_success"),            # no device/location
            dict(timestamp="2026-03-23 02:10", event_type="bulk_download", volume_mb=900.0)]
    _, _, groups = _analyse(rows, cfg)
    assert groups and groups[0].kind in ("partial", "isolated")


def test_legitimate_tagged_sequence_scores_lower_than_untagged(cfg):
    sig = dict(rule_sev={"R07": "high", "R10": "high"}, ml_norm=0.5, max_z=5, core_stages=2, ordered=True,
               event_types=["bulk_download", "data_transfer"], cfg=cfg)
    plain = score_signals(approved_coverage=0.0, **sig)["risk_score"]
    tagged = score_signals(approved_coverage=1.0, **sig)["risk_score"]
    assert tagged < plain and tagged > plain * (1 - cfg["risk"]["context_discount"]) - 1e-6


# ----------------------------------------------------------------- risk
def test_risk_score_bounds_and_priority(cfg):
    zero = score_signals({}, 0.0, 0.0, 0, True, [], 0.0, cfg)
    assert zero["risk_score"] == 0 and zero["priority"] == "Low"
    top = score_signals({r: "high" for r in "ABCDEFG"}, 1.0, 100, 5, True, ["data_transfer"], 0.0, cfg)
    assert top["risk_score"] == pytest.approx(100, abs=3) and top["risk_score"] <= 100 and top["priority"] == "Critical"
    t = cfg["risk"]["priority_thresholds"]
    assert priority_for(t["Medium"] - .1, cfg) == "Low" and priority_for(t["Medium"], cfg) == "Medium"
    assert priority_for(t["High"], cfg) == "High" and priority_for(t["Critical"], cfg) == "Critical"


def test_rule_signal_counts_distinct_rules_not_repeats(cfg):
    assert rule_signal({"R07": "high"}, cfg) == pytest.approx(0.75)
    assert rule_signal({"R07": "high", "R10": "high"}, cfg) == pytest.approx(1 - 0.25 * 0.25)


def test_contributions_sum_to_raw_and_weights_normalise_without_ml(cfg):
    s = score_signals({"R07": "high"}, None, 3, 2, True, ["bulk_download"], 0.0, cfg)
    assert sum(s["contributions"].values()) == pytest.approx(s["raw_score"])
    assert s["contributions"]["ml"] == 0 and sum(s["weights"].values()) == pytest.approx(1.0)
