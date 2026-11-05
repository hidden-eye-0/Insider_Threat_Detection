"""Shared fixtures: a full pipeline run over the seeded synthetic dataset in a temp workspace."""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from insider import db, ml  # noqa: E402
from insider.config import EVENT_COLUMNS, load_config  # noqa: E402
from insider.generator import generate  # noqa: E402
from insider.pipeline import ingest_events, process_workspace  # noqa: E402
from insider.preprocess import validate_and_clean  # noqa: E402


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def pipeline_env(tmp_path_factory):
    """Generate data, ingest and process in a temp DB (models written to a temp dir)."""
    tmp = tmp_path_factory.mktemp("env")
    ml.MODEL_DIR = tmp / "models"
    synth = tmp / "synth"
    meta = generate(synth)
    raw = pd.read_csv(synth / "bank_events.csv", dtype=str, keep_default_na=False, na_values=[""])
    events, report = validate_and_clean(raw)
    gt = pd.read_csv(synth / "ground_truth.csv")
    path = tmp / "t.db"
    con = db.connect(path)
    ingest_events(con, events, report, gt, meta)
    res = process_workspace(con, load_config(), model_name="pytest")
    con.commit()
    yield {"con": con, "res": res, "events": events, "gt": gt, "meta": meta, "path": path, "synth": synth, "report": report}
    con.close()


def mk_events(rows, emp="E1", role="teller"):
    """Build an event frame from dict rows; missing columns default to None."""
    df = pd.DataFrame(rows)
    for c in EVENT_COLUMNS:
        if c not in df:
            df[c] = None
    df["employee_id"] = df["employee_id"].fillna(emp)
    df["role"] = df["role"].fillna(role)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["event_id"] = [f"T{i:05d}" for i in range(len(df))]
    df["source_ref"] = df["event_id"]
    return df.sort_values("timestamp").reset_index(drop=True)


def history_rows(days=15, start="2026-03-02", n_acc=10):
    """Plain weekday history: 09:00 login + n_acc account accesses between 09:30-16:00."""
    rows, d = [], pd.Timestamp(start)
    for _ in range(days * 2):
        if d.weekday() < 5 and len([r for r in rows if r["event_type"] == "login_success"]) < days:
            rows.append(dict(timestamp=d + pd.Timedelta(hours=9), event_type="login_success", device_id="D1", location="B1"))
            for i in range(n_acc):
                rows.append(dict(timestamp=d + pd.Timedelta(hours=9.5 + 0.6 * i), event_type="account_access",
                                 resource="core/accounts", customer_id=f"C{i}", device_id="D1", location="B1", rec=1))
        d += pd.Timedelta(days=1)
    return rows
