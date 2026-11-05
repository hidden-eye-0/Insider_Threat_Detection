import pandas as pd

from insider.baseline import build_baselines, enrich_events
from insider.rules import available_rules, describe_rules, run_rules
from tests.conftest import history_rows, mk_events

END = pd.Timestamp("2026-03-21")
DEV = dict(device_id="D1", location="B1")


def run(extra, cfg, history=None):
    ev = mk_events((history if history is not None else history_rows()) + extra)
    bl = build_baselines(ev, END, cfg)
    hits, skipped = run_rules(enrich_events(ev, bl), bl, cfg, since=END)
    return hits, skipped, ev


def ids(hits):
    return {h.rule_id for h in hits}


def test_quiet_day_triggers_nothing(cfg):
    day = [dict(timestamp=f"2026-03-23 {9 + i // 2}:{(i % 2) * 30:02d}", event_type="account_access", customer_id=f"C{i % 10}",
                resource="core/accounts", **DEV) for i in range(8)]
    day.insert(0, dict(timestamp="2026-03-23 09:00", event_type="login_success", **DEV))
    hits, _, _ = run(day, cfg)
    assert hits == []


def test_r01_unusual_login_hour_and_weekday(cfg):
    assert "R01" in ids(run([dict(timestamp="2026-03-23 03:10", event_type="login_success", **DEV)], cfg)[0])
    assert "R01" in ids(run([dict(timestamp="2026-03-28 09:00", event_type="login_success", **DEV)], cfg)[0])  # Saturday


def test_r02_failed_logins_then_sensitive(cfg):
    base = [dict(timestamp=f"2026-03-23 10:0{i}", event_type="login_failed", outcome="failure") for i in range(5)]
    follow = [dict(timestamp="2026-03-23 10:10", event_type="login_success", **DEV),
              dict(timestamp="2026-03-23 10:15", event_type="sensitive_search", customer_id="C1")]
    assert "R02" in ids(run(base + follow, cfg)[0])
    assert "R02" not in ids(run(base, cfg)[0])                     # failures alone: no sensitive follow-up
    assert "R02" not in ids(run(base[:2] + follow, cfg)[0])        # below min_failed


def test_r03_r04_many_unfamiliar_accounts(cfg):
    burst = [dict(timestamp=f"2026-03-23 11:{i:02d}", event_type="account_access", customer_id=f"X{i}",
                  resource="core/accounts", **DEV) for i in range(40)]
    assert {"R03", "R04"} <= ids(run(burst, cfg)[0])
    assert not ({"R03", "R04"} & ids(run(burst[:5], cfg)[0]))


def test_r05_unfamiliar_resource(cfg):
    hits, _, _ = run([dict(timestamp="2026-03-23 11:00", event_type="resource_access", resource="treasury/wires", **DEV)], cfg)
    assert "R05" in ids(hits)


def test_r06_search_burst(cfg):
    burst = [dict(timestamp=f"2026-03-23 11:{i:02d}", event_type="sensitive_search", customer_id=f"C{i % 10}") for i in range(14)]
    assert "R06" in ids(run(burst, cfg)[0])
    assert "R06" not in ids(run(burst[:4], cfg)[0])


def test_r07_large_download(cfg):
    big = dict(timestamp="2026-03-23 12:00", event_type="bulk_download", volume_mb=900.0, **DEV)
    small = dict(timestamp="2026-03-23 12:00", event_type="bulk_download", volume_mb=5.0, **DEV)
    assert "R07" in ids(run([big], cfg)[0])
    assert "R07" not in ids(run([small], cfg)[0])


def test_r08_privileged_for_role_without_history(cfg):
    hits, _, _ = run([dict(timestamp="2026-03-23 12:00", event_type="privileged_op", resource="admin/console", **DEV)], cfg)
    assert "R08" in ids(hits)


def test_r09_new_device_only_for_established(cfg):
    new_dev = [dict(timestamp="2026-03-23 09:00", event_type="login_success", device_id="D77", location="B1")]
    assert "R09" in ids(run(new_dev, cfg)[0])
    # employee with insufficient history: the rule is skipped rather than flagging every device
    assert "R09" not in ids(run(new_dev, cfg, history=history_rows(days=3))[0])


def test_r10_external_transfer(cfg):
    ext = dict(timestamp="2026-03-23 13:00", event_type="data_transfer", resource="external:share-1", volume_mb=100.0)
    internal = dict(timestamp="2026-03-23 13:00", event_type="data_transfer", resource="internal:backup", volume_mb=100.0)
    assert "R10" in ids(run([ext], cfg)[0])
    assert "R10" not in ids(run([internal], cfg)[0])


def test_hits_have_required_fields(pipeline_env):
    for h in pipeline_env["res"]["hits"][:200]:
        assert h.rule_id and h.rule_name and h.severity in ("low", "medium", "high", "critical")
        assert h.event_ids and h.evidence and h.explanation.strip()


def test_missing_columns_skip_rules(cfg):
    ev = mk_events(history_rows())
    ev["volume_mb"] = None
    ev["customer_id"] = None
    ok, skipped = available_rules(ev, cfg)
    assert "R07" in skipped and "R03" in skipped and "R01" in ok


def test_rule_catalogue_documented(cfg):
    d = describe_rules(cfg)
    assert len(d) == 10 and d["rule_id"].is_unique and (d["condition"].str.len() > 10).all()
