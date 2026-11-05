# Demonstration Guide (≈10 minutes)

**Start:** `pip install -r requirements.txt` (once) → `python run.py` → open <http://127.0.0.1:8501>.
First run builds the demo workspace in about 10–20 s (data → baselines → rules → ML → correlation → risk → evaluation). Reset any time: `python run.py --rebuild`.

Key numbers you will see (seed 42; from the stored results): 21,863 events · 24 employees · 34 alerts (5 Critical, 12 High, 17 Medium).

## Flow
1. **Overview** – KPIs, activity-vs-alert trend, risk histogram, status distribution. Point out the "synthetic / human review" banner.
2. **Security Events** (explorer + Data quality tab) – show raw events (filter employee `EMP-1003`), quality report, documented scenario ground truth.
   *(Optional)* Upload tab: download the sample CSV, upload it, show validation/limitations messages (do not confirm import unless you want a new workspace).
3. **Employee Risk** (ranked table, risk factors) then **Behavioral Analytics** – select `EMP-1003` (teller): baseline status *established*, usual login window ≈ 7.7h–14.4h, daily robust stats, 83 familiar accounts, one device/location.
   Daily anomaly-score chart shows spikes on 2026-04-07 and 2026-04-22. Select `EMP-1099`: *insufficient history* warning and role-baseline fallback.
4. **Alerts & Cases** – sort by risk; filter Priority = Critical. Click the row for **ALR-44ED9840** (EMP-1003, 2026-04-22 ≈02:52, risk 100 / Critical).
   Read the *Why this alert?* text; show score-composition bar chart, the triggered rules R01, R09, R03, R04, R06, R05, R07, R10 with evidence, and the correlated sequence
   `login_anomaly → account_access → sensitive_search → bulk_download → data_transfer`.
5. **Forensic Timeline**, then **Threat Investigations** – chronological timeline (large markers = alert events, grey = surrounding context); open an event in the detail panel;
   expand the five-part investigation summary; show the integrity check ("41+ source records re-hashed").
6. **Analyst review** – set Status = *Under investigation*, add a note, then Status = *Escalated*, Disposition = *Confirmed policy violation (needs HR/compliance action)*, add a conclusion → Save.
   Refresh the browser or open Overview: the status distribution changed (persisted in SQLite). System Settings → Data & workspaces → audit log shows the actions and "Chain verification: OK".
7. **False-positive handling** – Alert Center, Priority = Medium: e.g. a `legit_support` alert (R03/R04, context coverage ≈ 0.8, score reduced by the context discount) or `legit_bulk` (R07 + R05, 100 % tagged).
   Open one → Investigation → mark *Explained / legitimate* with disposition *False positive - legitimate activity*. Mention `legit_untagged_late` (no tag) still alerts – the analyst decides.
8. **System Settings → Detection engine** – rules table with parameters; ML model status (training rows, threshold, score convention); risk formula & weights; method comparison chart.
9. **Reports → Evaluation** – test partition: rule-only vs ML-only vs LOF vs combined; confusion matrices; alert quality (explanations/timelines/source refs 100 %); full-chain detection 5/5 as correlated sequences.
   State the caveats on the page (synthetic, small sample, not a clean hold-out).
10. **Reports** – export filtered alerts CSV, evidence JSON, and **download the HTML investigation report** for ALR-44ED9840; open it in a browser (facts / signals / inference / missing evidence / analyst conclusions / timeline / integrity).

## Talking points
- Scores are prioritisation indices, never probabilities of intent; every alert needs a human decision.
- The ML model alone misses most single-signal incidents; the value is in combining baselines, rules, ML and correlation.
- Context tags reduce priority but never suppress alerts, and are treated as claims to verify.
- What is *not* done: real data, real-time ingestion, authentication, PDF export, supervised learning, online baseline updates.

## If something goes wrong
`python run.py --rebuild` restores a clean demo; `python -m pytest tests -q` confirms the installation (≈20–40 s).
