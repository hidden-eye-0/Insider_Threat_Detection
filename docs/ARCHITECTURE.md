# Architecture and Data Flow

## Overview
A single Python application: a library (`insider/`) that does all processing, a SQLite file per *workspace* for persistence, and a Streamlit
dashboard (`dashboard/`) that only reads from SQLite (and writes analyst actions back to it). No external services, cloud calls or telemetry.
FastAPI was deliberately not added – it would not have improved the demonstration and would have added moving parts.

```
 CSV (synthetic generator or upload)
        │  preprocess.validate_and_clean  – schema check, timestamps, duplicates, aliases, hashes, quality report
        ▼
   events (SQLite)  ◄── ground_truth (separate table, evaluation only)
        │  baseline.build_baselines       – per-employee + role baselines from history BEFORE train_end
        │  baseline.enrich_events         – per-event flags (off-hours, unfamiliar account/resource, new device/location)
        ├──► rules.run_rules              – R01-R10 hits with evidence (monitoring period only)
        ├──► features.employee_day_features ──► ml.AnomalyModel (IsolationForest, LOF)  – anomaly score per employee-day
        ▼
   correlation.correlate                  – groups rule-evidence events into per-employee sequences
        ▼
   risk.score_signals                     – weighted 0-100 score, priority, contribution breakdown
        ▼
   alerts + alert_events + alert_rules + investigations (SQLite)
        ▼
   forensics (timeline, summary, integrity, reports)  ◄──►  dashboard (analyst notes, status, disposition → SQLite + audit log)
        ▼
   evaluation.compare_methods → json_store['evaluation']  → Evaluation page / docs/EVALUATION.md
```

## Modules
| Module | Responsibility |
|---|---|
| `config.py` | Paths, schema, event-type aliases, sensitivity weights, **all thresholds** (`DEFAULT_CONFIG`), JSON override |
| `generator.py` | Reproducible synthetic data (`numpy.random.default_rng(42)`), roles, normal behaviour, legitimate-unusual and malicious scenarios, split metadata |
| `preprocess.py` | Upload limits, validation, normalisation, de-duplication, `record_hash` |
| `baseline.py` | Robust statistics (median/MAD/p95), hour windows, familiar accounts/devices/locations, event enrichment |
| `rules.py` | Rule registry; each rule is a pure function returning `Hit` objects |
| `features.py` | 19 raw + 7 deviation + 5 role features per employee-day |
| `ml.py` | `AnomalyModel`: Isolation Forest + LOF, quantile thresholds, persistence |
| `correlation.py` | Gap/span-based grouping, stage mapping, ordering check |
| `risk.py` | Signal normalisation and weighted score |
| `pipeline.py` | `analyze` (pure) → alerts; `evaluate`; `ingest_events`; `process_workspace` (idempotent persistence) |
| `db.py` | Schema, workspaces, investigations, notes, audit hash chain |
| `forensics.py` | Alert detail, timeline, integrity verification, summary, HTML/CSV/JSON reports |
| `evaluation.py` | Confusion-matrix metrics and comparison tables |

## Persistence (SQLite, one file per workspace in `data/workspaces/`)
Tables: `events`, `ground_truth`, `baselines`, `alerts`, `alert_events`, `alert_rules`, `investigations`, `notes`, `audit_log`, `json_store`
(quality report, dataset metadata, model info, evaluation) and `employee_days` (feature + score table written by pandas).
Foreign keys are enforced; `alerts.risk_score` has a 0–100 CHECK; indexes exist on `(employee_id, timestamp)`, `event_type`, alert employee/priority and note alert.
All SQL uses bound parameters; table names are never user-controlled; workspace names are validated against `^[A-Za-z0-9_-]{1,40}$`
so no path can be injected.

**Idempotent processing.** Alert IDs are `ALR-` + SHA-1(employee | type | first-event-id)[:8], so re-processing yields the same IDs and upserts rows.
Investigation status/notes are keyed by alert ID and survive re-processing. Alerts that disappear but carry analyst work are kept and flagged `stale`.

## Workspaces and uploads
Uploads never replace data: *validate → preview → confirm → import into a new workspace*; an existing name is rejected. The only destructive
action (regenerating `demo`) needs the typed word RESET and affects only local simulated data.

## Dashboard
`dashboard/app.py` routes to functions in `views.py`. Reads go through `common.query` (cached on file mtime so analyst edits show immediately).
Every metric/chart is a SQL query or a stored result; there are no static mock values.
