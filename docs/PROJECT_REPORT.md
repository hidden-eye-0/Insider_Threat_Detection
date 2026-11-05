# Behavioral and Forensic Analytics-Based Insider Threat Detection System for Banking Environments

*Project report.* No separate academic specification document was supplied with the repository, so the structure follows the project title and the stated
objectives (behavioral baselines, rule-based detection, ML anomaly detection, correlation, risk scoring, forensic timeline reconstruction, analyst dashboard). Everything described under
"Implementation" exists in the repository and was executed; items under "Future work" do not exist.

## 1. Introduction
Insiders – employees and contractors with legitimate access – can misuse customer data in ways that perimeter security does not see. In banking, the data are regulated and
high-value, so detecting unusual access early and being able to reconstruct and justify what happened are both essential. This project builds a local prototype that combines
*behavioral analytics* (what is unusual for this employee) with *digital-forensic practice* (traceable evidence, timelines, integrity checks, analyst records).

## 2. Problem statement
Activity logs from core-banking, CRM and identity systems are voluminous and mostly benign. Pure threshold rules produce many false alarms on legitimate-but-unusual work (overtime, support surges,
approved exports); pure anomaly detection gives scores that analysts cannot explain or trace to evidence. Analysts need prioritised, explained, evidence-linked alerts and a way to document their decision.

## 3. Aim and objectives
**Aim:** a working end-to-end system that helps analysts identify and investigate potentially suspicious insider activity in a simulated bank.
Objectives: (1) generate a reproducible labelled synthetic environment; (2) validate and normalise logs; (3) learn per-employee baselines; (4) implement configurable rules; (5) add unsupervised ML anomaly detection;
(6) correlate multi-event sequences; (7) produce a transparent risk score; (8) reconstruct forensic timelines with traceability; (9) provide an analyst dashboard with persistent investigations; (10) evaluate honestly against baselines.

## 4. Scope
In scope: a local single-user prototype on synthetic (or explicitly authorised) CSV logs, batch processing, SQLite storage, Streamlit UI.
Out of scope: connection to real systems, real-time streaming, authentication/multi-user workflows, automated response or sanction, legal-grade evidence handling, PDF export.

## 5. Existing approaches
Rule/threshold systems (SIEM correlation rules, DLP policies) are transparent but brittle. User-and-entity behaviour analytics (UEBA) profile users statistically.
Machine-learning studies use the CERT insider-threat datasets (Glasser & Lindauer, 2013), unsupervised methods such as Isolation Forest (Liu et al., 2008) and LOF (Breunig et al., 2000),
and deep sequence models (e.g. Tuor et al., 2017). The CERT guide (Cappelli et al., 2012) catalogues insider-incident patterns (data exfiltration, sabotage, fraud). Forensic guidance (Kent et al., 2006) stresses preserving and documenting evidence.

## 6. Research gap
Many prototypes report a model score but not (a) employee-specific baselines with explicit handling of new employees, (b) handling of legitimate-unusual behaviour, (c) multi-event correlation that avoids double counting,
(d) an explainable score decomposition, and (e) an investigation workflow with traceable evidence and persisted analyst conclusions. This project integrates these in one reproducible application and compares rule-only, ML-only and combined detection.

## 7. Proposed system
Pipeline: *ingest → baseline → rules + ML → correlation → risk scoring → alert → timeline/investigation → report/evaluation* (see `ARCHITECTURE.md`). Output is always an alert for human review.

## 8. Architecture
Python library `insider/` (generator, preprocessing, baseline, rules, features, ML, correlation, risk, pipeline, forensics, evaluation, SQLite layer), Streamlit dashboard `dashboard/`,
one SQLite file per workspace. Details in `ARCHITECTURE.md`.

## 9. Methodology
Time-based partitions (train/baseline 35 days, validation 10, test 15). Baselines and the model use only the training window. Rules and ML run on the monitoring period. Alerts are correlated groups (or ML-only employee-days).
Evaluation is at employee-day level against documented simulated incidents. Full description: `DETECTION_METHODOLOGY.md`, `EVALUATION.md`.

## 10. Feature engineering
Per employee-day: 19 behavioural counts/volumes (events, logins, failed logins, distinct and unfamiliar accounts/resources, download totals, privileged ops, sensitive-search burst size, external transfers,
off-hours events, new device/location events), 7 robust z-scores against the employee's own baseline (median/MAD), and role indicators – 31 features. Baseline construction excludes exception-tagged days and uses robust statistics.

## 11. Detection and risk scoring
Ten rules (R01–R10) with centralised thresholds; Isolation Forest (primary) and LOF (comparison); a correlation engine that groups rule-evidence events per employee with gap/span windows and maps them to
the stages login anomaly → account access → sensitive search → bulk download → data transfer. The 0–100 risk score is a weighted sum of five normalised signals (rules 0.30, ML 0.20, deviation 0.15, correlation 0.20, sensitivity 0.15)
reduced by up to 40 % for activity carrying approval tags. Priorities: Low <30, Medium 30–50, High 50–75, Critical ≥75. The score is a prioritisation index, not a probability.

## 12. Forensic investigation and explainability
Each alert stores its source event IDs and original log references, the rules that fired with evidence, the ML score, correlated stages (and stages not observed), a score decomposition and a natural-language explanation.
The Investigation page shows an interactive timeline of alert and context events, an event-detail panel, and a five-part summary (observed facts / detection signals / inferred relationships / missing or uncertain evidence / analyst conclusions).
Analyst status, disposition, conclusion and notes are saved in SQLite and recorded in a SHA-256 hash-chained audit log (tamper-*evident*). Source records carry ingest-time hashes that can be re-verified.
Reports are exported as HTML, CSV and JSON.

## 13. Dashboard
Eight pages: Overview, Employee Behavior, Alert Center (filters/search/drill-down), Forensic Investigation, Detection Engine, Data Explorer (browse, quality, upload, reset), Evaluation, Reports. All content is queried from the workspace database.

## 14. Implementation
Python 3.13, pandas/NumPy, scikit-learn 1.7, Streamlit 1.57, Plotly, SQLite, pytest. ≈3,100 lines of application code. 66 automated tests cover generation (reproducibility, no incident leakage), validation, baselines,
every rule (triggering and non-triggering cases), model training/prediction/persistence, correlation (suspicious vs. isolated vs. tagged sequences), risk bounds, DB persistence, audit-chain tamper detection, reprocessing idempotency, timeline ordering,
integrity checks, report content, metric calculations and dashboard rendering/interaction.

## 15. Evaluation (actual results)
Synthetic dataset: 21,863 events, 24 employees, 22 simulated malicious incidents (4 in validation, 18 in test) plus legitimate-unusual episodes. Test partition: 259 employee-days, 18 positive.

| Method (test) | TP | FP | TN | FN | Precision | Recall | F1 | Balanced acc. |
|---|---|---|---|---|---|---|---|---|
| Rule-only (any rule hit) | 18 | 16 | 225 | 0 | 0.529 | 1.000 | 0.692 | 0.967 |
| ML-only (Isolation Forest) | 6 | 7 | 234 | 12 | 0.462 | 0.333 | 0.387 | 0.652 |
| ML-only (LOF) | 13 | 19 | 222 | 5 | 0.406 | 0.722 | 0.520 | 0.822 |
| Combined (any alert) | 18 | 8 | 233 | 0 | 0.692 | 1.000 | 0.818 | 0.983 |
| Combined (High/Critical only) | 14 | 0 | 241 | 4 | 1.000 | 0.778 | 0.875 | 0.889 |

All 22 incidents were covered by at least one combined alert; all 5 full multi-event chains were detected as a single correlated *sequence* alert (Critical, mean 94 % of the incident's events inside the alert).
All 26 test-period alerts had explanations, timelines and complete source references; 8 were false alerts (0.16 per employee-week) – legitimate-unusual episodes surfacing at Medium/High priority.
**Caveats:** synthetic data authored together with the detectors; few positives; rule logic and thresholds were adjusted while inspecting validation *and test* alerts, so the test partition is not a clean hold-out and
the combined figures are optimistic development-time numbers. See `EVALUATION.md` (auto-generated from the stored results).

## 16. Security, privacy and ethics
Synthetic data by default; no external connections or telemetry; the app binds to 127.0.0.1; uploads are size/row-limited, parsed as text, never executed, and imported only into validated workspace names;
SQL is parameterised; secrets are never required. Alerts and scores are explicitly labelled as requiring human review; the system takes no automated action against any employee. Behavioural monitoring raises fairness and proportionality
concerns (false accusations, chilling effects, bias toward roles with unusual duties); deployments would need legal basis, transparency to staff, access controls and appeal processes.

## 17. Limitations and future enhancements
Limitations: synthetic regular data; small evaluation; unverified context tags (an insider could forge an approval tag); no authentication; batch only; baselines rebuilt not updated online; weights are expert-set;
audit log is tamper-evident not tamper-proof; no PDF export; no supervised model; the simple correlation heuristic could split a slow attack into separate groups.
Future: real-time ingestion, tag verification against ticketing systems, learned/calibrated scoring, sequence models, peer-group baselines, role-based access, signed audit logs, PDF/STIX export, evaluation on public insider datasets.

## 18. Conclusion
The prototype demonstrates a complete, reproducible workflow from logs to documented analyst decisions. On synthetic data, combining employee baselines, rules, ML and correlation gave better precision than rule-only detection at equal recall and far better recall than ML alone,
while keeping every alert explainable and traceable. These results illustrate the design, not real-world performance.

## 19. References
1. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *Proc. IEEE ICDM*, 413–422.
2. Breunig, M. M., Kriegel, H.-P., Ng, R. T., & Sander, J. (2000). LOF: Identifying density-based local outliers. *Proc. ACM SIGMOD*, 93–104.
3. Cappelli, D., Moore, A., & Trzeciak, R. (2012). *The CERT Guide to Insider Threats*. Addison-Wesley.
4. Glasser, J., & Lindauer, B. (2013). Bridging the gap: A pragmatic approach to generating insider threat data. *IEEE Security and Privacy Workshops*.
5. Tuor, A., Kaplan, S., Hutchinson, B., Nichols, N., & Robinson, S. (2017). Deep learning for unsupervised insider threat detection in structured cybersecurity data streams. *AAAI-17 AICS Workshop*.
6. Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to Integrating Forensic Techniques into Incident Response* (NIST SP 800-86).
7. Pedregosa, F., et al. (2011). Scikit-learn: Machine learning in Python. *JMLR* 12, 2825–2830.

*(Citations were written from memory; please verify details before submission.)*
