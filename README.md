# Behavioral and Forensic Analytics-Based Insider Threat Detection System for Banking Environments

An end-to-end, local, **academic prototype** that analyses employee activity logs from a *simulated* bank and
helps a human analyst find, prioritise and investigate potentially suspicious insider activity.

> **All default data is synthetic.** No real bank, employee or customer data is used or required. Alerts are
> prioritisation aids that require human review; a high risk score never establishes that someone is malicious.

## What it does
`activity logs → validation → employee baselines → 10 rules + Isolation Forest → event correlation → risk score (0-100) → explainable alerts → forensic timeline → analyst notes/disposition (SQLite) → reports + evaluation`

| Capability | Where |
|---|---|
| Seeded synthetic bank dataset (≈21.9k events, 24 employees, 60 days, labelled simulated incidents + legitimate-unusual episodes) | `insider/generator.py`, `docs/DATASET.md` |
| CSV validation / normalisation / duplicate + malformed-row handling / quality report / SHA-256 record fingerprints | `insider/preprocess.py` |
| Per-employee robust baselines (+ role fallback for new employees, contamination control) | `insider/baseline.py` |
| 10 configurable rules (R01–R10) with evidence + explanations | `insider/rules.py`, `insider/config.py` |
| Isolation Forest (primary) + LOF (comparison), saved with joblib | `insider/ml.py`, `insider/features.py` |
| Correlation engine (employee/time-window sequences, every event in one group) | `insider/correlation.py` |
| Transparent weighted risk score + priority | `insider/risk.py` |
| SQLite persistence, investigations, notes, tamper-evident audit chain | `insider/db.py`, `insider/pipeline.py` |
| Timeline, five-part investigation summary, integrity check, HTML/CSV/JSON reports | `insider/forensics.py` |
| Rule-only vs ML-only vs combined evaluation | `insider/evaluation.py`, `docs/EVALUATION.md` |
| Streamlit dashboard (9 pages, light theme) | `dashboard/` |
| 69 automated tests | `tests/` |

## Quick start (Windows / macOS / Linux, Python 3.10+; developed on 3.13)
```bash
pip install -r requirements.txt
python run.py            # builds the demo workspace on first run, then opens http://127.0.0.1:8501
```
Other commands:
```bash
python run.py --rebuild        # regenerate data + re-run the whole pipeline
python run.py --no-ui          # prepare data only
python -m pytest tests -q      # run the test suite
python scripts/make_eval_doc.py  # regenerate docs/EVALUATION.md from the stored evaluation results
python -m insider.cli verify   # verify the audit-log hash chain of the active workspace
```
`start.bat` is a Windows shortcut for `python run.py`. The app binds to `127.0.0.1` only.

## Dashboard pages
**Sentinel Intelligence** light-theme UI: Overview · Security Events · Employee Risk · Behavioral Analytics · Threat Investigations · Forensic Timeline · Alerts & Cases · Reports (exports + evaluation) · System Settings (detection engine, data & workspaces, analyst profile). Top bar: global alert search, notifications (pending High/Critical alerts), profile menu. UI code: `dashboard/design.py` (design tokens, CSS, components), `dashboard/views.py` (pages), `dashboard/app.py` (shell/navigation); theme in `.streamlit/config.toml`.
Step-by-step walkthrough: `docs/DEMO_GUIDE.md`.

## Using your own CSV
*Data Explorer → Upload CSV.* Required columns: `event_id, timestamp, employee_id, event_type`. Optional: `role, resource, customer_id,
device_id, location, volume_mb, record_count, outcome, context_tag, source_ref`. The file is validated and previewed, then imported into a
**new workspace** (existing workspaces are never overwritten). Rules whose inputs are absent are skipped and the limitation is displayed.
A sample file is at `data/synthetic/sample_upload.csv` (this is a 200-row excerpt – too little history for meaningful baselines). Uploaded data has no ground truth, so the Evaluation page is only available for the demo workspace.

## Repository layout
```
insider/      core library (config, generator, preprocess, baseline, rules, features, ml, correlation, risk, db, pipeline, forensics, evaluation, cli)
dashboard/    Streamlit app (app.py, views.py, common.py)
tests/        pytest suite (units, pipeline, DB, dashboard rendering)
docs/         architecture, methodology, dataset, evaluation, demo guide, report, presentation outline
data/         synthetic CSVs (generated) and SQLite workspaces (data/workspaces/*.db)
models/       persisted Isolation Forest models (generated)
scripts/      make_eval_doc.py
```

## Configuration
All thresholds, weights and priorities are in `insider/config.py` (`DEFAULT_CONFIG`). You may override any value with
`config/detection_config.json` (deep-merged), then run `python run.py --rebuild` (or *Data Explorer → Demo dataset / reset*).
No secrets or environment variables are needed, so there is no `.env.example`.

## Troubleshooting
- **Port in use** – `python run.py --port 8600`.
- **Blank dashboard / "workspace has no data"** – `python run.py --rebuild`.
- **Import errors** – run commands from the project root and `pip install -r requirements.txt`.
- **Changed config has no effect** – alerts are computed at processing time; rebuild or re-process the workspace.
- **Starting over** – delete `data/workspaces/*.db` (local simulated data only) and run `python run.py`.

## Limitations (summary – details in docs)
Synthetic data only; small evaluation sample; the test split is not a clean hold-out (rules were tuned while inspecting it); context tags are
treated as claims, not verified approvals; PDF export and a FastAPI layer are not implemented; the audit log is tamper-*evident*, not tamper-proof;
no real-time ingestion; no authentication (local single-user prototype).
