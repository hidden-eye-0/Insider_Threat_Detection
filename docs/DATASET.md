# Dataset documentation

**SYNTHETIC DATA.** Produced by `insider/generator.py` (`numpy.random.default_rng(seed=42)`); it contains no real bank, employee or customer information. Pseudonymous IDs only
(`EMP-1001…`, `CUST-00001…`, `DEV-####`). Regenerate with `python -m insider.generator` (writes to `data/synthetic/`).

## Files
| File | Content |
|---|---|
| `data/synthetic/bank_events.csv` | 21,863 events – the only file the detection pipeline reads |
| `data/synthetic/ground_truth.csv` | per-event `is_malicious`, `scenario_type`, `scenario_id` – **used only for evaluation and ML-threshold selection on the validation split** |
| `data/synthetic/dataset_meta.json` | seed, partition dates, list of every simulated scenario (employee, date, type) |
| `data/synthetic/sample_upload.csv` | first 200 events, to demonstrate the upload format |

## Event schema
| Column | Required | Description |
|---|---|---|
| `event_id` | yes | unique event identifier (`EVT-000001`) |
| `timestamp` | yes | local naive time; uploads with offsets are converted to UTC |
| `employee_id` | yes | pseudonymous employee |
| `event_type` | yes | `login_success, login_failed, account_access, sensitive_search, transaction_view, bulk_download, data_transfer, privileged_op, resource_access` (aliases such as `login`, `download`, `search` are normalised) |
| `role` | no | `teller, loan_officer, support, auditor, admin` (`unknown` if absent) |
| `resource` | no | system/module touched; `external:*` = external destination, `internal:*` = internal |
| `customer_id` | no | customer account referenced |
| `device_id`, `location` | no | workstation and branch/network context (`EXT-nn` = external network) |
| `volume_mb`, `record_count` | no | data volume / records |
| `outcome` | no | `success` / `failure` |
| `context_tag` | no | approval/ticket reference (e.g. `OT-APPROVED-1234`); treated as an *unverified claim* |
| `source_ref` | no | pointer to the original log line (`core-log-20260302.log#L17`); generated as `upload:rowN` if absent |

At ingest each record also gets `record_hash` (SHA-256 of its canonical fields) for integrity checks.

## Population
24 employees: {'teller': 8, 'support': 5, 'loan_officer': 4, 'admin': 4, 'auditor': 3}; one teller (`EMP-1099`) starts on day 52, so has insufficient history. 60 calendar days from 2026-03-02 (weekdays only).
Partitions: train/baseline `2026-03-02` → `2026-04-06`, validation → `2026-04-16`, test → end. **No malicious incident is in the training partition and every incident lies completely in one partition.**

## Scenarios (event counts from the generated file)
| scenario_type         |   events | description                                                                                                                                     |   incidents/episodes |
|:----------------------|---------:|:------------------------------------------------------------------------------------------------------------------------------------------------|---------------------:|
| normal                |    20794 | Routine role-typical activity                                                                                                                   |                  nan |
| legit_support         |      436 | Legitimate: support staff handle 30-45 customers under a ticket (SUPPORT-TKT-*)                                                                 |                    9 |
| full_chain            |      237 | Malicious: failed logins → off-hours login (new device/location) → ~28 unrelated accounts → ~13 searches → ~900 MB download → external transfer |                    5 |
| legit_overtime        |      134 | Legitimate: approved overtime evening session (tag OT-APPROVED-*)                                                                               |                   11 |
| unrelated_access      |      108 | Malicious: 28-42 accounts outside own portfolio within ~1.5 h                                                                                   |                    3 |
| search_burst          |       40 | Malicious: 15-25 sensitive searches in ~20 min                                                                                                  |                    2 |
| failed_then_sensitive |       27 | Malicious: 6-10 failed logins, success from external location, sensitive searches                                                               |                    2 |
| legit_untagged_late   |       22 | Legitimate but UNTAGGED: evening session at 19:00 (will alert; analyst must judge)                                                              |                    4 |
| off_hours_login       |       20 | Malicious: login ~01:30-04:00, a few account accesses                                                                                           |                    3 |
| legit_bulk            |       14 | Legitimate: admin/auditor 400-800 MB export + internal transfer under change approval (CHG-APPROVED-*)                                          |                    7 |
| legit_new_device      |       14 | Legitimate: replacement laptop (tag DEV-REPLACE-APPROVED)                                                                                       |                    4 |
| unusual_privileged    |        8 | Malicious: privileged ops by non-admin (or admin at night)                                                                                      |                    2 |
| unusual_resource      |        6 | Malicious: 2-4 accesses to treasury/HR/board/customer-export resources                                                                          |                    2 |
| large_download        |        3 | Malicious: single 600-1500 MB download                                                                                                          |                    3 |

Total malicious events: 449. The showcase incident is a `full_chain` for `EMP-1003` on 2026-04-22.

## Preview (first 8 records)
| event_id   | timestamp           | employee_id   | role         | event_type       | resource                  | customer_id   | device_id   | location   | volume_mb   |   record_count | outcome   | context_tag   | source_ref               |
|:-----------|:--------------------|:--------------|:-------------|:-----------------|:--------------------------|:--------------|:------------|:-----------|:------------|---------------:|:----------|:--------------|:-------------------------|
| EVT-000001 | 2026-03-02 07:37:43 | EMP-1009      | loan_officer | login_success    |                           |               | DEV-2335    | BR-02      |             |                | success   |               | core-log-20260302.log#L1 |
| EVT-000002 | 2026-03-02 07:55:12 | EMP-1016      | support      | login_success    |                           |               | DEV-9422    | HQ         |             |                | success   |               | core-log-20260302.log#L2 |
| EVT-000003 | 2026-03-02 07:58:08 | EMP-1015      | support      | login_success    |                           |               | DEV-3664    | HQ         |             |                | success   |               | core-log-20260302.log#L3 |
| EVT-000004 | 2026-03-02 08:00:59 | EMP-1009      | loan_officer | account_access   | loans/applications        | CUST-00450    | DEV-2335    | BR-02      |             |              1 | success   |               | core-log-20260302.log#L4 |
| EVT-000005 | 2026-03-02 08:02:51 | EMP-1001      | teller       | login_success    |                           |               | DEV-7964    | BR-03      |             |                | success   |               | core-log-20260302.log#L5 |
| EVT-000006 | 2026-03-02 08:04:11 | EMP-1009      | loan_officer | transaction_view | core-banking/transactions | CUST-00295    | DEV-2335    | BR-02      |             |              1 | success   |               | core-log-20260302.log#L6 |
| EVT-000007 | 2026-03-02 08:04:27 | EMP-1020      | admin        | login_success    |                           |               | DEV-6740    | HQ         |             |                | success   |               | core-log-20260302.log#L7 |
| EVT-000008 | 2026-03-02 08:04:44 | EMP-1011      | loan_officer | login_failed     |                           |               | DEV-5223    | BR-04      |             |                | failure   |               | core-log-20260302.log#L8 |

## Known artefacts of the synthetic design
- Behaviour is drawn from simple Poisson/uniform models, so it is more regular than real logs; real data would be noisier.
- Incidents were designed together with the detectors (same author), so recall figures are optimistic.
- Legitimate-unusual episodes carry approval tags (except `legit_untagged_late`), which is how contextual false-positive handling is demonstrated.
