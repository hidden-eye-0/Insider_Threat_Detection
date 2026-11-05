# Presentation Outline (≈12 slides, 10–12 min + live demo)

1. **Title** – Behavioral and Forensic Analytics-Based Insider Threat Detection for Banking Environments; team, guide, date. Footer: "synthetic data; human review required".
2. **Problem** – Insiders have legitimate access; logs are huge and mostly benign; rules alone → false alarms, ML alone → unexplainable scores.
3. **Aim & objectives** – prioritised, explained, evidence-linked alerts + analyst workflow; list the 10 objectives in 3 groups (detect / explain / investigate).
4. **Approach at a glance** – pipeline diagram: logs → validation → baselines → rules + Isolation Forest → correlation → risk score → alert → timeline → report.
5. **Data** – synthetic bank: 21.9k events, 24 employees, 5 roles, 60 days; normal + legitimate-unusual (overtime, support surge, approved bulk) + 8 incident types; time-based split, no incident leakage; ground truth kept separate.
6. **Employee baselines** – per-employee robust stats, hour windows, familiar accounts/devices; new employee → role fallback (EMP-1099); tagged days excluded.
7. **Detection** – 10 configurable rules; Isolation Forest (+LOF) anomaly score ≠ probability; correlation stages (login → accounts → searches → download → transfer); each event counted once.
8. **Risk score** – formula, 5 signals and weights, context discount, priorities; screenshot of score-composition chart.
9. **Forensic investigation** – timeline, five-part summary, source refs, SHA-256 integrity check, hash-chained audit log; statuses and dispositions in SQLite.
10. **Live demo** – follow `DEMO_GUIDE.md` (Critical alert ALR-44ED9840 → timeline → disposition → report; then a legitimate false positive).
11. **Results** – table: rule-only / ML-only / LOF / combined (test: F1 0.692 / 0.387 / 0.520 / 0.818; High+Critical precision 1.000, recall 0.778); 5/5 chains detected as sequences; 0.16 false alerts per employee-week. Caveats: synthetic, 18 positives, not a clean hold-out.
12. **Security, ethics, limitations** – local only, no automated action, unverified tags, no auth, batch only; future work (real-time, ticket verification, calibrated scoring, public datasets).
13. **Conclusion & Q&A** – what was built (8-page dashboard, 66 tests), what the numbers do and do not show.

**Likely questions:** Why not supervised learning? (few labelled insiders in practice; kept as future work.) Why is Isolation Forest recall low? (single-signal incidents; value is as corroborating signal.)
Can an insider forge a context tag? (yes – listed limitation; tags only lower priority and are flagged for verification.) Is the audit log tamper-proof? (no – tamper-evident hash chain.)
