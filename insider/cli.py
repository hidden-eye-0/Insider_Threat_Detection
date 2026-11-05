"""Command line helpers: ``python -m insider.cli init-demo | process | verify``."""
from __future__ import annotations

import argparse
import json

import pandas as pd

from . import db
from .config import DEFAULT_WORKSPACE, SYNTH_DIR, load_config
from .generator import generate
from .pipeline import ingest_events, process_workspace
from .preprocess import validate_and_clean


def init_demo(name: str = DEFAULT_WORKSPACE, regenerate: bool = True) -> dict:
    """(Re)create the demo workspace from the seeded synthetic dataset and run the full pipeline."""
    if regenerate or not (SYNTH_DIR / "bank_events.csv").exists():
        meta = generate()
    else:
        meta = json.loads((SYNTH_DIR / "dataset_meta.json").read_text(encoding="utf-8"))
    raw = pd.read_csv(SYNTH_DIR / "bank_events.csv", dtype=str, keep_default_na=False, na_values=[""])
    events, report = validate_and_clean(raw)
    gt = pd.read_csv(SYNTH_DIR / "ground_truth.csv")
    path = db.workspace_path(name)
    with db.session(path) as con:
        ingest_events(con, events, report, gt, meta)
        res = process_workspace(con, load_config(), model_name=name)
    db.set_active_workspace(name)
    return {"events": len(events), "alerts": len(res["alerts"]), "path": str(path)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Insider threat detection - helper commands")
    ap.add_argument("command", choices=["init-demo", "process", "verify"])
    ap.add_argument("--workspace", default=None)
    a = ap.parse_args()
    ws = a.workspace or db.get_active_workspace()
    if a.command == "init-demo":
        print(init_demo(a.workspace or DEFAULT_WORKSPACE))
    elif a.command == "process":
        with db.session(db.workspace_path(ws)) as con:
            res = process_workspace(con, load_config())
        print({"alerts": len(res["alerts"])})
    else:
        with db.session(db.workspace_path(ws)) as con:
            print("audit chain ok:", db.verify_audit_chain(con))


if __name__ == "__main__":
    main()
