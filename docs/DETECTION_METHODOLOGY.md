# Detection Methodology

## 1. Time partitions
`train_end` (baseline/training history) and `val_end` come from dataset metadata (synthetic: day 35 and day 45 of 60) or, for uploads, from time
fractions (58 % / 17 %). Only events **before `train_end`** are used for baselines and model training. Rules, ML scoring, correlation and alerts operate on
the monitoring period (`>= train_end`).

## 2. Employee baselines (`baseline.py`)
For each employee, from history before `train_end`:
- login-hour window = [p1 − margin, p99 + margin] of own `login_success` hour-of-day (margin 1 h); active-hour window from all events (p0.5/p99.5); usual weekdays;
- daily robust statistics (median, MAD, p95, max) for: events, failed logins, distinct accounts, distinct resources, download MB, privileged ops, max sensitive searches in 30 min;
- familiar customer accounts, known devices, known locations, known resources.

**Contamination control.** Days on which the employee has *any* event carrying an exception `context_tag` (approved overtime, ticket, change window) are excluded,
and only medians/MAD/percentiles are used. (In the synthetic data the training period contains no malicious incidents by construction; in real data this
guard would matter more and should be supplemented with iterative cleaning.)

**Insufficient history.** With fewer than `min_history_days` (7) active days an employee is `insufficient`: the pooled role baseline is used for hours and
volumes; account-familiarity (R04), device/location novelty (R09) are **skipped** (not guessed), and any rule that does fire is marked *low confidence*.
The dashboard shows this state; the synthetic new hire `EMP-1099` demonstrates it.

**Update policy.** Baselines are rebuilt from scratch whenever the workspace is (re)processed; there is no online updating (future work).

## 3. Rules (`rules.py`, thresholds in `config.py`)
| ID | Name | Condition (summary) | Severity |
|---|---|---|---|
| R01 | Login outside usual working pattern | `login_success` outside own login-hour window or on an unused weekday; evidence includes off-hours session events in the next 2 h | medium |
| R02 | Failed logins → sensitive activity | ≥4 `login_failed` in 15 min, then `login_success` and a sensitive event within 60 min | high |
| R03 | Many distinct accounts in a day | distinct customers/day > max(35, own robust fence = max(p95, median+3·1.4826·MAD)); evidence = densest 2-hour burst | medium |
| R04 | Unfamiliar accounts | ≥8 accounts never seen in history and ≥50 % of the day's accounts (established baselines only) | medium |
| R05 | Unfamiliar resources | resource absent from own baseline | high |
| R06 | Sensitive-search burst | ≥ max(10, 1.5 × personal historic max) searches in 30 min | medium |
| R07 | Large download | `bulk_download` ≥ max(200 MB, 3 × personal p95 daily volume) | high |
| R08 | Unusual privileged operation | role/employee has no privileged history, or count above fence, or outside usual hours | high |
| R09 | New device or location | `login_success` from unseen device/location (established baselines only) | medium |
| R10 | External data transfer | `data_transfer` whose destination starts with `external:` | high |

Each hit carries rule ID/name, severity, event IDs, evidence dict, a plain-language explanation and a `low_confidence` flag. Rules are skipped, with a visible reason, when their input
columns are empty (e.g. no `volume_mb` → R07 skipped). Thresholds are chosen as readable defaults, not optimised; they are all in `DEFAULT_CONFIG`.

## 4. ML anomaly detection (`features.py`, `ml.py`)
- **Unit:** employee-day. **Features (31):** 19 raw behavioural counts/volumes (events, logins, failed logins, distinct/unfamiliar accounts and resources, download totals, privileged ops,
  sensitive searches and burst size, transfers, off-hours events, new device/location events), 7 robust z-scores against the employee's own baseline (clipped), 5 role indicators.
- **Primary model:** `IsolationForest(n_estimators=300, random_state=42)` trained on baseline-period employee-days only. **Second detector:** `LocalOutlierFactor(novelty=True)` on log-scaled, standardised features.
- **Score convention:** `anomaly_score = −score_samples` (higher = more anomalous). It is an unsupervised anomaly index, **not** a probability.
  `ml_norm = clip((score − median_train) / (p99.9_train − median_train), 0, 1)` feeds the risk score.
- **Flag threshold:** a quantile of the training scores; the quantile (0.95/0.97/0.98/0.99) is picked by F1 on the validation partition.
- Insufficient training rows (<100) raises `InsufficientDataError`; the pipeline then disables ML and renormalises risk weights, with a visible warning.
- No supervised classifier is trained. Labels are used only (a) to choose the ML threshold on validation and (b) for evaluation.

## 5. Correlation (`correlation.py`)
Signal events = events cited as evidence by any rule hit. Per employee they are sorted by time and split where the gap exceeds `max_gap_min` (90) or the span would exceed `max_span_hours` (12).
Because grouping is a partition, **every event belongs to exactly one group** and is never counted twice. Event types map to stages
`login_anomaly → account_access → sensitive_search → bulk_download → data_transfer` (+ `privileged_op`). Group kinds: **sequence** (≥4 core stages), **partial** (2–3), **isolated** (1).
Ordering is checked on the first occurrence of each stage. Missing fields never raise: events simply lack stage evidence.

## 6. Risk score (`risk.py`)
`score = 100 · (0.30·S_rules + 0.20·S_ml + 0.15·S_dev + 0.20·S_corr + 0.15·S_sens) · (1 − 0.40 · approved_coverage)`
- `S_rules = 1 − Π(1 − w_sev)` over **distinct** rule IDs (low .25, medium .5, high .75, critical 1.0) – repeats of the same rule do not stack.
- `S_ml = ml_norm`; `S_dev = min(1, max positive robust z / 8)`; `S_corr = (core_stages − 1)/4` (×0.8 if out of order, 0 if isolated); `S_sens = max sensitivity weight` of the group's event types
  (login .1, account .3, resource .4, search .5, privileged .7, download .8, transfer 1.0).
- `approved_coverage` = share of the group's events carrying a `context_tag`. The discount lowers priority but never hides the alert; the explanation states that **tags are unverified claims**.
- If ML is unavailable, the ML weight is removed and the others renormalised.
- Priority: Low < 30 ≤ Medium < 50 ≤ High < 75 ≤ Critical. Groups scoring below 30 are not raised. ML-only alerts (flagged employee-day, no rule hit) are scored the same way.

**Limitations:** weights/thresholds are expert-set, not learned; signals are correlated (rules and ML see the same behaviour) so the score is an index, not a probability;
the correlation window is heuristic; legitimate rare behaviours without tags will alert (and that is by design – the analyst decides).

## 7. Explainability
Every alert stores: the textual explanation, each rule's evidence, the per-signal contributions that add up to the score, correlated stages (and stages *not* observed),
ML score and severity index, baseline status and context coverage. The investigation summary separates observed facts, detection signals, inferred relationships,
missing/uncertain evidence and analyst conclusions.
