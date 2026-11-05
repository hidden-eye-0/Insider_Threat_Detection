"""Multi-event correlation: group rule-triggering events per employee into attack-style sequences.

Algorithm
---------
1. "Signal events" = events referenced by at least one rule hit (hits provide the evidence).
2. Per employee, signal events are sorted chronologically and split into groups whenever the
   gap between consecutive signal events exceeds ``max_gap_min`` or the group would span more
   than ``max_span_hours``. Each event therefore belongs to exactly ONE group (no double counting).
3. Each group is mapped to kill-chain-like stages by event type:
   login_anomaly -> account_access -> sensitive_search -> bulk_download -> data_transfer
   (privileged_op is tracked as an additional stage).
4. The group is ``sequence`` (>=4 core stages), ``partial`` (2-3 core stages) or ``isolated``
   (1 stage). Order consistency is checked on the first occurrence of each stage.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .rules import Hit

CORE_STAGES = ["login_anomaly", "account_access", "sensitive_search", "bulk_download", "data_transfer"]
STAGE_OF = {"login_success": "login_anomaly", "login_failed": "login_anomaly",
            "account_access": "account_access", "transaction_view": "account_access",
            "resource_access": "account_access", "sensitive_search": "sensitive_search",
            "bulk_download": "bulk_download", "data_transfer": "data_transfer",
            "privileged_op": "privileged_op"}


@dataclass
class Group:
    employee_id: str
    ts_start: pd.Timestamp
    ts_end: pd.Timestamp
    event_ids: list[str]
    hits: list[Hit] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)     # in order of first occurrence
    core_stages: int = 0
    ordered: bool = True
    kind: str = "isolated"                              # isolated | partial | sequence
    explanation: str = ""


def correlate(enriched: pd.DataFrame, hits: list[Hit], cfg: dict) -> list[Group]:
    """Build correlated groups from rule hits. Returns groups sorted by start time."""
    cc = cfg["correlation"]
    gap, span = pd.Timedelta(minutes=cc["max_gap_min"]), pd.Timedelta(hours=cc["max_span_hours"])
    by_id = enriched.set_index("event_id")
    groups: list[Group] = []
    per_emp: dict[str, list[Hit]] = {}
    for h in hits:
        per_emp.setdefault(h.employee_id, []).append(h)
    for emp, emp_hits in per_emp.items():
        ev_hits: dict[str, list[Hit]] = {}
        for h in emp_hits:
            for eid in h.event_ids:
                if eid in by_id.index:
                    ev_hits.setdefault(eid, []).append(h)
        sig = by_id.loc[list(ev_hits)].sort_values(["timestamp"])
        cur: list[str] = []
        t_first = t_prev = None
        batches: list[list[str]] = []
        for eid, ts in zip(sig.index, sig["timestamp"]):
            if cur and (ts - t_prev > gap or ts - t_first > span):
                batches.append(cur); cur = []
            if not cur:
                t_first = ts
            cur.append(eid); t_prev = ts
        if cur:
            batches.append(cur)
        for b in batches:
            ghits, seen = [], set()
            for eid in b:
                for h in ev_hits[eid]:
                    if id(h) not in seen:
                        seen.add(id(h)); ghits.append(h)
            sub = sig.loc[b]
            stages: list[str] = []
            for et in sub["event_type"]:
                st = STAGE_OF.get(et)
                if st and st not in stages:
                    stages.append(st)
            core = [s for s in stages if s in CORE_STAGES]
            order = [CORE_STAGES.index(s) for s in core]
            g = Group(emp, sub["timestamp"].min(), sub["timestamp"].max(), b, ghits, stages, len(core),
                      order == sorted(order))
            g.kind = "sequence" if len(core) >= 4 else "partial" if len(core) >= 2 else "isolated"
            g.explanation = _explain(g)
            groups.append(g)
    return sorted(groups, key=lambda g: (g.ts_start, g.employee_id))


def _explain(g: Group) -> str:
    dur = (g.ts_end - g.ts_start).total_seconds() / 60
    chain = " -> ".join(g.stages)
    if g.kind == "isolated":
        return (f"Isolated anomaly: {len(g.event_ids)} event(s) of a single stage ({chain}) with no "
                f"corroborating activity in the correlation window; given lower correlation weight.")
    order = "in the expected order" if g.ordered else "(not in the typical order)"
    label = "Complete multi-stage sequence" if g.kind == "sequence" else "Partial multi-stage sequence"
    return (f"{label}: {g.core_stages} of {len(CORE_STAGES)} core stages observed within {dur:.0f} min {order}: "
            f"{chain}. {len(g.event_ids)} contributing events, each counted once.")


def find_missing_stages(g: Group) -> list[str]:
    return [s for s in CORE_STAGES if s not in g.stages]
