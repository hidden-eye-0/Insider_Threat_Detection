"""Reproducible synthetic banking activity generator (fixed seed).

ALL data produced here is synthetic. Ground truth (which events belong to simulated
incidents / legitimate-unusual episodes) is written to a separate file and is used only
for evaluation, never as a detection feature.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from .config import SEED, SYNTH_DIR

START = datetime(2026, 3, 2)           # Monday
N_DAYS = 60
TRAIN_END = START + timedelta(days=35)  # baseline / training history: days 0-34
VAL_END = START + timedelta(days=45)    # validation: days 35-44; test: days 45-59

ROLE_SPEC = {
    # n employees, daily Poisson rates, pool size, resources, location kind
    "teller": dict(n=7, acc=14, txn=5, sens=2, bulk=.05, bulk_mb=2, priv=0, pool=60,
                   res=["core-banking/accounts", "core-banking/transactions", "kyc/viewer"]),
    "loan_officer": dict(n=4, acc=9, txn=4, sens=2, bulk=.10, bulk_mb=5, priv=0, pool=40,
                         res=["loans/applications", "core-banking/accounts", "credit/bureau-view"]),
    "support": dict(n=5, acc=12, txn=3, sens=3, bulk=.05, bulk_mb=3, priv=0, pool=120,
                    res=["crm/tickets", "core-banking/accounts", "kyc/viewer"]),
    "auditor": dict(n=3, acc=8, txn=8, sens=4, bulk=.15, bulk_mb=20, priv=0, pool=100,
                    res=["audit/reports", "core-banking/transactions", "core-banking/accounts", "compliance/archive"]),
    "admin": dict(n=4, acc=4, txn=1, sens=.5, bulk=.20, bulk_mb=50, priv=3, pool=20,
                  res=["admin/console", "iam/directory", "db/backup", "core-banking/accounts"]),
}
UNUSUAL_RESOURCES = ["hr/payroll", "treasury/wires", "exec/board-docs", "db/customer-master-export"]
N_CUSTOMERS = 2000
NEW_HIRE_START_DAY = 52

MALICIOUS_TYPES = ["off_hours_login", "unrelated_access", "search_burst", "large_download",
                   "unusual_privileged", "failed_then_sensitive", "unusual_resource", "full_chain"]
LEGIT_TYPES = ["legit_overtime", "legit_support", "legit_bulk", "legit_untagged_late", "legit_new_device"]


def _cust(i: int) -> str:
    return f"CUST-{i:05d}"


def build_employees(rng: np.random.Generator) -> list[dict]:
    emps, n = [], 0
    for role, spec in ROLE_SPEC.items():
        for _ in range(spec["n"]):
            n += 1
            hq = role in ("admin", "auditor", "support")
            emps.append({
                "employee_id": f"EMP-{1000 + n}", "role": role,
                "shift_start": float(rng.choice([8, 8.5, 9, 9.5])),
                "device": f"DEV-{rng.integers(1000, 9999)}",
                "location": "HQ" if hq else f"BR-0{rng.integers(1, 5)}",
                "pool": [_cust(int(c)) for c in rng.choice(N_CUSTOMERS, spec["pool"], replace=False)],
                "start_day": 0,
            })
    # new hire (insufficient history by design)
    emps.append({"employee_id": "EMP-1099", "role": "teller", "shift_start": 9.0,
                 "device": f"DEV-{rng.integers(1000, 9999)}", "location": "BR-02",
                 "pool": [_cust(int(c)) for c in rng.choice(N_CUSTOMERS, 60, replace=False)],
                 "start_day": NEW_HIRE_START_DAY})
    return emps


class _Gen:
    def __init__(self, seed: int = SEED):
        self.rng = np.random.default_rng(seed)
        self.rows: list[dict] = []
        self.emps = build_employees(self.rng)
        self.by_id = {e["employee_id"]: e for e in self.emps}
        self.scenarios: list[dict] = []
        self._sid = 0

    # -- low-level helpers -------------------------------------------------
    def add(self, emp, ts, etype, *, resource=None, customer=None, device=None, location=None,
            vol=None, rec=None, outcome="success", tag=None, gt=("normal", 0, None)):
        self.rows.append(dict(
            timestamp=ts, employee_id=emp["employee_id"], role=emp["role"], event_type=etype,
            resource=resource, customer_id=customer, device_id=device or emp["device"],
            location=location or emp["location"], volume_mb=vol, record_count=rec,
            outcome=outcome, context_tag=tag, scenario_type=gt[0], is_malicious=gt[1], scenario_id=gt[2]))

    def day_ts(self, day: int, hour: float) -> datetime:
        return START + timedelta(days=day, seconds=float(hour) * 3600)

    def new_sid(self, kind: str) -> str:
        self._sid += 1
        return f"SIM-{self._sid:03d}-{kind}"

    # -- normal behaviour ----------------------------------------------------
    def normal_day(self, emp, day):
        r, spec = self.rng, ROLE_SPEC[emp["role"]]
        s = emp["shift_start"] + r.normal(0, 0.2)
        if r.random() < 0.04:  # a failed login before success
            self.add(emp, self.day_ts(day, s - 0.01), "login_failed", outcome="failure")
        self.add(emp, self.day_ts(day, s), "login_success")
        if r.random() < 0.3:
            self.add(emp, self.day_ts(day, s + 4 + r.normal(0, .2)), "login_success")
        pool = emp["pool"]

        def pick():
            return pool[r.integers(len(pool))] if r.random() < 0.95 else _cust(int(r.integers(N_CUSTOMERS)))

        def when():
            return self.day_ts(day, s + r.uniform(0.1, 8.0))
        for _ in range(r.poisson(spec["acc"])):
            self.add(emp, when(), "account_access", resource=spec["res"][0], customer=pick(), rec=1)
        for _ in range(r.poisson(spec["txn"])):
            self.add(emp, when(), "transaction_view", resource="core-banking/transactions", customer=pick(), rec=1)
        for _ in range(r.poisson(spec["sens"])):
            self.add(emp, when(), "sensitive_search", resource="kyc/viewer", customer=pick(), rec=1)
        for _ in range(r.poisson(2)):
            self.add(emp, when(), "resource_access", resource=spec["res"][r.integers(len(spec["res"]))])
        if r.random() < spec["bulk"]:
            mb = float(min(r.lognormal(np.log(spec["bulk_mb"]), 0.4), 120))
            self.add(emp, when(), "bulk_download", resource=spec["res"][-1], vol=round(mb, 1), rec=int(mb * 20))
        for _ in range(r.poisson(spec["priv"])):
            self.add(emp, when(), "privileged_op", resource="admin/console")
        if emp["role"] == "admin" and r.random() < 0.1:
            self.add(emp, when(), "data_transfer", resource="internal:backup-server",
                     vol=round(float(r.uniform(20, 90)), 1))

    # -- legitimate unusual -----------------------------------------------
    def legit(self, kind, emp, day):
        r, sid = self.rng, self.new_sid(kind)
        gt = (kind, 0, sid)
        spec = ROLE_SPEC[emp["role"]]
        self.scenarios.append(dict(scenario_id=sid, type=kind, malicious=False, employee_id=emp["employee_id"],
                                   day=day, date=str((START + timedelta(days=day)).date())))
        if kind == "legit_overtime":
            tag, h = f"OT-APPROVED-{r.integers(1000, 9999)}", 20.5
            self.add(emp, self.day_ts(day, h), "login_success", tag=tag, gt=gt)
            for i in range(r.integers(8, 14)):
                self.add(emp, self.day_ts(day, h + r.uniform(.1, 2)), "account_access", resource=spec["res"][0],
                         customer=emp["pool"][r.integers(len(emp["pool"]))], rec=1, tag=tag, gt=gt)
        elif kind == "legit_support":
            tag, h = f"SUPPORT-TKT-{r.integers(1000, 9999)}", emp["shift_start"] + 1
            for i in range(r.integers(30, 46)):
                self.add(emp, self.day_ts(day, h + r.uniform(0, 5)), "account_access", resource="crm/tickets",
                         customer=_cust(int(r.integers(N_CUSTOMERS))), rec=1, tag=tag, gt=gt)
            for i in range(r.integers(8, 13)):
                self.add(emp, self.day_ts(day, h + r.uniform(0, 1)), "sensitive_search", resource="kyc/viewer",
                         customer=_cust(int(r.integers(N_CUSTOMERS))), rec=1, tag=tag, gt=gt)
        elif kind == "legit_bulk":
            tag, h = f"CHG-APPROVED-{r.integers(1000, 9999)}", emp["shift_start"] + 3
            mb = float(r.uniform(400, 800))
            self.add(emp, self.day_ts(day, h), "bulk_download", resource=spec["res"][-1], vol=round(mb, 1),
                     rec=int(mb * 20), tag=tag, gt=gt)
            self.add(emp, self.day_ts(day, h + .3), "data_transfer", resource="internal:archive-server",
                     vol=round(mb, 1), tag=tag, gt=gt)
        elif kind == "legit_untagged_late":   # mild, unexplained-in-data but benign
            self.add(emp, self.day_ts(day, 19.0), "login_success", gt=gt)
            for i in range(r.integers(3, 7)):
                self.add(emp, self.day_ts(day, 19.1 + r.uniform(0, .8)), "account_access", resource=spec["res"][0],
                         customer=emp["pool"][r.integers(len(emp["pool"]))], rec=1, gt=gt)
        elif kind == "legit_new_device":      # replacement laptop
            dev = f"DEV-{r.integers(1000, 9999)}"
            tag = "DEV-REPLACE-APPROVED"
            self.add(emp, self.day_ts(day, emp["shift_start"] + 7.5), "login_success", device=dev, tag=tag, gt=gt)
            for i in range(r.integers(2, 5)):
                self.add(emp, self.day_ts(day, emp["shift_start"] + 7.6 + r.uniform(0, .3)), "account_access",
                         resource=spec["res"][0], device=dev, customer=emp["pool"][r.integers(len(emp["pool"]))],
                         rec=1, tag=tag, gt=gt)

    # -- simulated malicious incidents ---------------------------------------
    def malicious(self, kind, emp, day):
        r, sid = self.rng, self.new_sid(kind)
        gt = (kind, 1, sid)
        spec = ROLE_SPEC[emp["role"]]
        day_date = str((START + timedelta(days=day)).date())
        self.scenarios.append(dict(scenario_id=sid, type=kind, malicious=True, employee_id=emp["employee_id"],
                                   day=day, date=day_date))
        others = lambda: _cust(int(r.integers(N_CUSTOMERS)))  # noqa: E731
        if kind == "off_hours_login":
            h = float(r.uniform(1.5, 4))
            self.add(emp, self.day_ts(day, h), "login_success", gt=gt)
            for i in range(r.integers(3, 7)):
                self.add(emp, self.day_ts(day, h + r.uniform(.05, .5)), "account_access", resource=spec["res"][0],
                         customer=emp["pool"][r.integers(len(emp["pool"]))], rec=1, gt=gt)
        elif kind == "unrelated_access":
            h = emp["shift_start"] + 2
            for i in range(r.integers(28, 42)):
                self.add(emp, self.day_ts(day, h + r.uniform(0, 1.5)), "account_access", resource=spec["res"][0],
                         customer=others(), rec=1, gt=gt)
        elif kind == "search_burst":
            h = emp["shift_start"] + 3
            for i in range(r.integers(15, 26)):
                self.add(emp, self.day_ts(day, h + r.uniform(0, .33)), "sensitive_search", resource="kyc/viewer",
                         customer=others(), rec=1, gt=gt)
        elif kind == "large_download":
            h, mb = emp["shift_start"] + 4, float(r.uniform(600, 1500))
            self.add(emp, self.day_ts(day, h), "bulk_download", resource=spec["res"][-1], vol=round(mb, 1),
                     rec=int(mb * 20), gt=gt)
        elif kind == "unusual_privileged":
            if emp["role"] == "admin":
                h = float(r.uniform(2, 4))
                for i in range(r.integers(6, 10)):
                    self.add(emp, self.day_ts(day, h + i * .05), "privileged_op", resource="iam/directory", gt=gt)
            else:
                h = emp["shift_start"] + 5
                for i in range(r.integers(3, 6)):
                    self.add(emp, self.day_ts(day, h + i * .05), "privileged_op", resource="admin/console", gt=gt)
        elif kind == "failed_then_sensitive":
            h = emp["shift_start"] + 1
            nf = int(r.integers(6, 11))
            for i in range(nf):
                self.add(emp, self.day_ts(day, h + i * .02), "login_failed", outcome="failure", gt=gt)
            loc = f"EXT-{r.integers(10, 99)}"
            self.add(emp, self.day_ts(day, h + nf * .02 + .02), "login_success", location=loc, gt=gt)
            for i in range(r.integers(4, 9)):
                self.add(emp, self.day_ts(day, h + .3 + i * .03), "sensitive_search", resource="kyc/viewer",
                         customer=others(), rec=1, location=loc, gt=gt)
        elif kind == "unusual_resource":
            h = emp["shift_start"] + 3
            for i in range(r.integers(2, 5)):
                self.add(emp, self.day_ts(day, h + i * .1), "resource_access",
                         resource=UNUSUAL_RESOURCES[r.integers(len(UNUSUAL_RESOURCES))], gt=gt)
        elif kind == "full_chain":
            h = float(r.uniform(1.0, 2.5))
            dev, loc = f"DEV-{r.integers(1000, 9999)}", f"EXT-{r.integers(10, 99)}"
            kw = dict(device=dev, location=loc)
            for i in range(3):
                self.add(emp, self.day_ts(day, h - .1 + i * .02), "login_failed", outcome="failure", gt=gt, **kw)
            self.add(emp, self.day_ts(day, h), "login_success", gt=gt, **kw)
            for i in range(r.integers(24, 32)):
                self.add(emp, self.day_ts(day, h + .05 + i * .01), "account_access", resource=spec["res"][0],
                         customer=others(), rec=1, gt=gt, **kw)
            for i in range(r.integers(11, 16)):
                self.add(emp, self.day_ts(day, h + .5 + i * .01), "sensitive_search", resource="kyc/viewer",
                         customer=others(), rec=1, gt=gt, **kw)
            mb = float(r.uniform(800, 1100))
            self.add(emp, self.day_ts(day, h + .8), "bulk_download", resource="db/customer-master-export",
                     vol=round(mb, 1), rec=int(mb * 20), gt=gt, **kw)
            self.add(emp, self.day_ts(day, h + 1.0), "data_transfer", resource="external:file-share-77",
                     vol=round(mb * .95, 1), gt=gt, **kw)

    # -- orchestration --------------------------------------------------------
    def pick(self, day_lo, day_hi, role_filter=None, used=None):
        used = used if used is not None else set()
        for _ in range(500):
            e = self.emps[self.rng.integers(len(self.emps))]
            d = int(self.rng.integers(day_lo, day_hi))
            if (START + timedelta(days=d)).weekday() >= 5 and self.rng.random() < .9:
                continue
            if e["start_day"] > d or (role_filter and e["role"] not in role_filter):
                continue
            if e["employee_id"] == "EMP-1099" and d < e["start_day"] + 3 and False:
                continue
            if (e["employee_id"], d) in used:
                continue
            used.add((e["employee_id"], d))
            return e, d
        raise RuntimeError("could not place scenario")

    def build(self) -> pd.DataFrame:
        for day in range(N_DAYS):
            if (START + timedelta(days=day)).weekday() >= 5:
                continue
            for e in self.emps:
                if day >= e["start_day"]:
                    self.normal_day(e, day)
        used: set = set()
        # legitimate-unusual episodes in all partitions
        legit_plan = [("legit_overtime", 4, 2, 5), ("legit_support", 3, 2, 4), ("legit_bulk", 3, 1, 3),
                      ("legit_untagged_late", 1, 1, 2), ("legit_new_device", 1, 1, 2)]
        roles = {"legit_overtime": None, "legit_support": ["support"], "legit_bulk": ["admin", "auditor"],
                 "legit_untagged_late": None, "legit_new_device": ["teller", "loan_officer"]}
        for kind, n_tr, n_va, n_te in legit_plan:
            for (lo, hi, n) in ((0, 35, n_tr), (35, 45, n_va), (45, N_DAYS, n_te)):
                for _ in range(n):
                    e, d = self.pick(max(lo, 7) if lo == 0 else lo, hi, roles[kind], used)
                    self.legit(kind, e, d)
        # malicious incidents only in validation / test (incident-level separation)
        val_plan = ["off_hours_login", "unrelated_access", "large_download", "full_chain"]
        test_plan = (["full_chain"] * 3 + ["off_hours_login"] * 2 + ["unrelated_access"] * 2 +
                     ["search_burst"] * 2 + ["large_download"] * 2 + ["unusual_privileged"] * 2 +
                     ["failed_then_sensitive"] * 2 + ["unusual_resource"] * 2)
        for kind in val_plan:
            e, d = self.pick(35, 45, None, used)
            self.malicious(kind, e, d)
        for kind in test_plan:
            e, d = self.pick(45, N_DAYS, ["teller", "loan_officer", "support", "auditor", "admin"], used)
            self.malicious(kind, e, d)
        # deterministic showcase: the flagship chain on a known employee/date
        hero = self.by_id["EMP-1003"]
        self.malicious("full_chain", hero, 51)
        self.scenarios[-1]["showcase"] = True

        df = pd.DataFrame(self.rows).sort_values("timestamp", kind="stable").reset_index(drop=True)
        df["event_id"] = [f"EVT-{i + 1:06d}" for i in range(len(df))]
        df["source_ref"] = [f"core-log-{t:%Y%m%d}.log#L{i + 1}" for i, t in enumerate(df["timestamp"])]
        df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
        return df


def generate(out_dir=SYNTH_DIR, seed: int = SEED) -> dict:
    """Generate the synthetic dataset and write CSV/JSON files. Returns metadata."""
    out_dir.mkdir(parents=True, exist_ok=True)
    g = _Gen(seed)
    df = g.build()
    event_cols = ["event_id", "timestamp", "employee_id", "role", "event_type", "resource", "customer_id",
                  "device_id", "location", "volume_mb", "record_count", "outcome", "context_tag", "source_ref"]
    df[event_cols].to_csv(out_dir / "bank_events.csv", index=False)
    df[["event_id", "is_malicious", "scenario_type", "scenario_id"]].to_csv(out_dir / "ground_truth.csv", index=False)
    meta = {
        "synthetic": True, "seed": seed, "n_events": len(df), "n_employees": len(g.emps),
        "start": str(START.date()), "train_end": str(TRAIN_END.date()), "val_end": str(VAL_END.date()),
        "n_malicious_events": int(df["is_malicious"].sum()),
        "scenarios": g.scenarios,
        "notice": "SYNTHETIC DATA - not real bank, employee or customer data.",
    }
    (out_dir / "dataset_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    df[event_cols].head(200).drop(columns=[]).to_csv(out_dir / "sample_upload.csv", index=False)
    return meta


if __name__ == "__main__":
    m = generate()
    print(f"Generated {m['n_events']} events, {m['n_employees']} employees, {len(m['scenarios'])} scenarios")
