"""Dashboard pages (Sentinel Intelligence). Every number and chart is read from the active SQLite workspace."""
from __future__ import annotations

import html
import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from insider import db, forensics
from insider.baseline import METRICS
from insider.cli import init_demo
from insider.config import (DEFAULT_WORKSPACE, MAX_UPLOAD_MB, OPTIONAL_COLUMNS, REQUIRED_COLUMNS, SYNTH_DIR,
                             load_config, priority_for)
from insider.pipeline import ingest_events, process_workspace
from insider.preprocess import IngestError, read_csv_safely, validate_and_clean
from insider.rules import describe_rules

from . import design as ds
from .common import alerts, connect, db_path, flash, has_data, json_store, query

ACTOR = "analyst"
HUMAN_REVIEW = ("Simulated banking environment with synthetic data. Alerts are prioritisation aids for human review; "
                "a high score does not establish that anyone acted maliciously.")
SIGNAL_LABELS = {"rules": "Rule matches", "ml": "ML anomaly", "deviation": "Baseline deviation",
                 "correlation": "Event correlation", "sensitivity": "Sensitive operations"}
KIND_LABELS = {"sequence": "Multi-stage sequence", "partial": "Partial sequence", "isolated": "Isolated anomaly", "ml_only": "ML anomaly only"}
ALERT_COLS = {
    "alert_id": st.column_config.TextColumn("Alert ID", width="small"),
    "ts_detect": st.column_config.DatetimeColumn("Detected", format="YYYY-MM-DD HH:mm"),
    "employee_id": st.column_config.TextColumn("Employee"),
    "role": st.column_config.TextColumn("Role"),
    "pattern": st.column_config.TextColumn("Pattern"),
    "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%.0f"),
    "priority": st.column_config.TextColumn("Severity", width="small"),
    "status": st.column_config.TextColumn("Status"),
    "rules": st.column_config.TextColumn("Rules"),
    "n_events": st.column_config.NumberColumn("Events", width="small"),
}


# ================================================================= shared helpers
def _need_data() -> bool:
    if not has_data():
        ds.empty_state("This workspace has no data yet", "Open System Settings → Data & workspaces to load the demo dataset or upload a CSV.", "database")
        return False
    return True


def _pct(x):
    return "n/a" if x is None else f"{x:.1%}"


def go_to(page_key: str) -> None:
    st.switch_page(st.session_state["_pages"][page_key])


def _alerts_view(df: pd.DataFrame) -> pd.DataFrame:
    v = df.copy()
    v["pattern"] = v["kind"].map(KIND_LABELS).fillna(v["kind"])
    v["ts_detect"] = pd.to_datetime(v["ts_detect"])
    return v


def alert_table(df: pd.DataFrame, key: str, cols=("alert_id", "ts_detect", "employee_id", "role", "pattern", "risk_score", "priority", "status")):
    """Paginated, sortable, selectable alert table. Returns the selected alert_id (or None)."""
    if df.empty:
        ds.empty_state("No alerts match", "Adjust or clear the filters above.", "search_off")
        return None
    v = _alerts_view(df)[list(cols)]
    page = ds.paginate(v, key)
    ev = st.dataframe(ds.severity_styler(page, "priority"), column_config=ALERT_COLS, hide_index=True, width="stretch",
                      on_select="rerun", selection_mode="single-row", key=f"{key}_tbl")
    rows = ev.selection.rows if ev and ev.selection else []
    return page.iloc[rows[0]]["alert_id"] if rows else None


@st.dialog("Alert details", width="large")
def alert_dialog(alert_id: str):
    con = connect()
    try:
        d = forensics.get_alert(con, alert_id)
    finally:
        con.close()
    render_alert_detail(d, compact=True)
    c1, c2, c3 = st.columns(3)
    if c1.button("Open case", type="primary", key=f"dlg_case_{alert_id}", icon=":material/policy:"):
        st.session_state["sel_alert"] = alert_id
        go_to("investigations")
    if c2.button("Forensic timeline", key=f"dlg_tl_{alert_id}", icon=":material/timeline:"):
        st.session_state["sel_alert"] = alert_id
        go_to("timeline")
    if c3.button("Close", key=f"dlg_close_{alert_id}"):
        st.rerun()


def view_details_button(selected: str | None, key: str):
    if selected is None:
        st.caption("Select a row in the table to view its details.")
        return
    if st.button(f"View details for {selected}", key=f"{key}_view", type="primary", icon=":material/open_in_new:"):
        alert_dialog(selected)


def render_alert_detail(d: dict, compact: bool = False):
    al = d["alert"]
    c = st.columns(4)
    c[0].markdown(ds.kpi("Risk score", f"{al['risk_score']:.0f}/100", "speed", "rose" if al["priority"] in ("Critical", "High") else "amber",
                         help_text="Prioritisation index (0-100), not a probability of malicious intent."), unsafe_allow_html=True)
    c[1].markdown(ds.kpi("Severity", al["priority"], "flag", "rose" if al["priority"] == "Critical" else "amber" if al["priority"] in ("High", "Medium") else "mint",
                         sub=KIND_LABELS.get(al["kind"], al["kind"])), unsafe_allow_html=True)
    c[2].markdown(ds.kpi("Employee", al["employee_id"], "badge", "indigo", sub=al["role"].replace("_", " ")), unsafe_allow_html=True)
    c[3].markdown(ds.kpi("ML anomaly score", f"{al['ml_anomaly_score']:.3f}", "psychology", "lavender",
                         sub="not a probability", help_text="-IsolationForest.score_samples; higher = more unusual."), unsafe_allow_html=True)
    st.markdown("")
    ds.callout(f"<b>Why this alert?</b> {html.escape(al['explanation'])}")
    st.markdown("")
    left, right = st.columns(2)
    with left, st.container(border=True):
        sg = al.get("signals", {})
        ds.card_title("Score composition", "Points contributed by each signal (they sum to the raw score)")
        if sg:
            contrib = pd.DataFrame({"signal": [SIGNAL_LABELS[k] for k in sg["contributions"]], "points": list(sg["contributions"].values()),
                                    "value": [sg["signals"][k] for k in sg["contributions"]], "weight": [sg["weights"][k] for k in sg["contributions"]]})
            fig = px.bar(contrib.iloc[::-1], x="points", y="signal", orientation="h", hover_data={"value": ":.2f", "weight": ":.2f", "points": ":.1f"},
                         color_discrete_sequence=[ds.PRIMARY])
            fig.update_layout(xaxis_title="points", yaxis_title=None)
            ds.plot(fig, key=f"comp_{al['alert_id']}_{compact}", height=240)
            st.caption(f"Raw {sg['raw_score']:.1f} · context discount {sg['context_discount']:.0%} · final {al['risk_score']:.1f}")
    with right, st.container(border=True):
        ds.card_title("Triggered rules and evidence")
        if d["rules"]:
            for r in d["rules"]:
                with st.expander(f"{r['rule_id']} · {r['rule_name']}" + (" · low confidence" if r["low_confidence"] else "")):
                    st.markdown(ds.badge(r["severity"].capitalize(), "amber"), unsafe_allow_html=True)
                    st.write(r["explanation"])
                    st.json(r["evidence"], expanded=False)
        else:
            st.write("No rule fired; this is a machine-learning anomaly alert.")
        if al["stages"]:
            st.markdown("**Correlated sequence**<br>" + " → ".join(f"<code>{s}</code>" for s in al["stages"]), unsafe_allow_html=True)
            if al["missing_stages"]:
                st.caption("Not observed: " + ", ".join(al["missing_stages"]))


def pick_alert(label="Case", key="pick") -> str | None:
    """Selector of an alert shared across pages through session_state['sel_alert']."""
    a = alerts()
    if a.empty:
        ds.empty_state("No alerts to work on", "Process a dataset that produces alerts first.", "notifications_off")
        return None
    ids = a["alert_id"].tolist()
    cur = st.session_state.get("sel_alert", ids[0])
    labels = {r.alert_id: f"{r.alert_id} · {r.employee_id} · {r.priority} {r.risk_score:.0f} · {r.status}" for r in a.itertuples()}
    sel = st.selectbox(label, ids, index=ids.index(cur) if cur in ids else 0, format_func=lambda x: labels[x], key=key)
    st.session_state["sel_alert"] = sel
    return sel


def _load_detail(alert_id: str):
    con = connect()
    try:
        d = forensics.get_alert(con, alert_id)
        integrity = forensics.verify_event_integrity(con, d["timeline"]["event_id"].tolist())
    finally:
        con.close()
    return d, integrity


# ================================================================= Overview
def overview():
    ds.page_header("Overview", "Security posture of the monitored banking environment at a glance.", "Dashboard")
    ds.callout(HUMAN_REVIEW)
    st.markdown("")
    if not _need_data():
        return
    a = alerts()
    n_events = int(query("SELECT COUNT(*) n FROM events")["n"][0])
    n_emp = int(query("SELECT COUNT(DISTINCT employee_id) n FROM events")["n"][0])
    daily = query("SELECT substr(timestamp,1,10) d, COUNT(*) events FROM events GROUP BY d ORDER BY d")
    ed = query("SELECT employee_id, date, anomaly_score, ml_flag, partition FROM employee_days")
    mon = ed[ed["partition"] != "train"]
    # trend: last 7 vs previous 7 days of data (only when 14 days of history exist)
    trend = None
    if len(daily) >= 14:
        last7, prev7 = daily["events"].iloc[-7:].sum(), daily["events"].iloc[-14:-7].sum()
        if prev7:
            trend = ((last7 - prev7) / prev7 * 100, "vs previous 7 days")
    hc_emp = a.loc[a["priority"].isin(["High", "Critical"]), "employee_id"].nunique() if len(a) else 0
    active = int(a["status"].isin(["Under investigation", "Escalated"]).sum()) if len(a) else 0
    unresolved = int(a["status"].isin(["Pending review", "Under investigation", "Escalated"]).sum()) if len(a) else 0
    rate = (mon["ml_flag"].sum() / len(mon)) if len(mon) else None
    cols = st.columns(6)
    cards = [
        ds.kpi("Security events", f"{n_events:,}", "shield", "indigo", f"{n_emp} employees monitored", trend),
        ds.kpi("High / Critical employees", str(hc_emp), "person_alert", "rose", "with a High or Critical alert"),
        ds.kpi("Active investigations", str(active), "manage_search", "sky", "under investigation or escalated"),
        ds.kpi("Unresolved alerts", str(unresolved), "notifications_active", "amber", f"of {len(a)} total alerts"),
        ds.kpi("Anomaly detection rate", _pct(rate), "query_stats", "lavender", f"{int(mon['ml_flag'].sum())} of {len(mon)} employee-days flagged by ML",
               help_text="Share of monitored employee-days whose ML anomaly score exceeds the threshold."),
        ds.kpi("Average risk score", f"{a['risk_score'].mean():.0f}" if len(a) else "n/a", "speed", "mint", "mean across alerts (0-100)",
               help_text="Mean alert risk score; a prioritisation index, not a probability."),
    ]
    for c, html_ in zip(cols, cards):
        c.markdown(html_, unsafe_allow_html=True)
    st.markdown("")
    l, r = st.columns([2, 1])
    with l, st.container(border=True):
        ds.card_title("Security events over time", "Daily event volume with alerts raised")
        ad = (a.assign(d=a["ts_detect"].dt.strftime("%Y-%m-%d")).groupby("d").size().rename("alerts").reset_index() if len(a)
              else pd.DataFrame(columns=["d", "alerts"]))
        dd = daily.merge(ad, on="d", how="left").fillna({"alerts": 0})
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=dd["d"], y=dd["events"], name="Events", mode="lines", line=dict(color=ds.PRIMARY, width=2.2),
                                 fill="tozeroy", fillcolor="rgba(79,70,229,.08)", hovertemplate="%{x}<br>%{y:,} events<extra></extra>"))
        fig.add_trace(go.Bar(x=dd["d"], y=dd["alerts"], name="Alerts", yaxis="y2", marker_color="#F43F5E", opacity=.85,
                             hovertemplate="%{x}<br>%{y} alerts<extra></extra>"))
        fig.update_layout(yaxis=dict(title="Events"), yaxis2=dict(overlaying="y", side="right", showgrid=False, title="Alerts", rangemode="tozero"), bargap=.5)
        ds.plot(fig, "ov_time", 300)
    with r, st.container(border=True):
        ds.card_title("Alerts by severity", "Count of alerts per review priority")
        if len(a):
            s = a["priority"].value_counts().reindex(ds.SEVERITY_ORDER).fillna(0).reset_index()
            s.columns = ["priority", "alerts"]
            fig = px.bar(s, x="alerts", y="priority", orientation="h", color="priority", color_discrete_map=ds.SEVERITY, text="alerts",
                         category_orders={"priority": ds.SEVERITY_ORDER})
            fig.update_layout(showlegend=False, yaxis_title=None, xaxis_title="alerts")
            fig.update_traces(textposition="outside", cliponaxis=False)
            ds.plot(fig, "ov_sev", 300)
        else:
            ds.empty_state("No alerts", "Nothing to prioritise yet.", "verified")
    l2, r2 = st.columns(2)
    with l2, st.container(border=True):
        ds.card_title("Employee risk-score distribution", "Highest alert score per employee (0 = no alerts)")
        mx = a.groupby("employee_id")["risk_score"].max() if len(a) else pd.Series(dtype=float)
        emp_scores = pd.DataFrame({"employee_id": query("SELECT DISTINCT employee_id FROM events")["employee_id"]})
        emp_scores["risk"] = emp_scores["employee_id"].map(mx).fillna(0)
        fig = px.histogram(emp_scores, x="risk", nbins=10, range_x=[0, 100], color_discrete_sequence=[ds.SECONDARY])
        fig.update_layout(xaxis_title="max risk score", yaxis_title="employees", bargap=.08)
        ds.plot(fig, "ov_dist", 280)
    with r2, st.container(border=True):
        ds.card_title("Behavioral anomaly trend", "Daily mean / max ML anomaly score (monitoring period) and flagged employee-days")
        if len(mon):
            t = mon.groupby("date").agg(mean=("anomaly_score", "mean"), max=("anomaly_score", "max"), flagged=("ml_flag", "sum")).reset_index()
            fig = go.Figure()
            fig.add_trace(go.Bar(x=t["date"], y=t["flagged"], name="Flagged days", yaxis="y2", marker_color="rgba(244,63,94,.35)"))
            fig.add_trace(go.Scatter(x=t["date"], y=t["max"], name="Max score", line=dict(color="#F59E0B", width=2)))
            fig.add_trace(go.Scatter(x=t["date"], y=t["mean"], name="Mean score", line=dict(color=ds.PRIMARY, width=2.2)))
            fig.update_layout(yaxis_title="anomaly score", yaxis2=dict(overlaying="y", side="right", showgrid=False, title="flagged", rangemode="tozero"))
            ds.plot(fig, "ov_anom", 280)
        else:
            ds.empty_state("No ML scores", "The anomaly model is not available for this workspace.", "psychology")
    c1, c2, c3 = st.columns(3)
    with c1, st.container(border=True):
        ds.card_title("Event categories", "Activity by event type")
        cat = query("SELECT event_type, COUNT(*) n FROM events GROUP BY event_type ORDER BY n DESC")
        fig = px.bar(cat.iloc[::-1], x="n", y="event_type", orientation="h", color_discrete_sequence=[ds.PRIMARY])
        fig.update_layout(yaxis_title=None, xaxis_title="events")
        ds.plot(fig, "ov_cat", 280)
    with c2, st.container(border=True):
        ds.card_title("Departments (roles)", "Alerts per 1,000 events by role")
        rr = query("SELECT role, COUNT(*) events FROM events GROUP BY role")
        ra = a.groupby("role").size().rename("alerts").reset_index() if len(a) else pd.DataFrame(columns=["role", "alerts"])
        rr = rr.merge(ra, on="role", how="left").fillna({"alerts": 0})
        rr["alerts per 1k events"] = (rr["alerts"] / rr["events"] * 1000).round(2)
        fig = px.bar(rr.sort_values("alerts per 1k events"), x="alerts per 1k events", y="role", orientation="h", hover_data=["events", "alerts"],
                     color_discrete_sequence=["#0EA5E9"])
        fig.update_layout(yaxis_title=None)
        ds.plot(fig, "ov_role", 280)
    with c3, st.container(border=True):
        ds.card_title("Investigation status", "Where alerts are in the review workflow")
        if len(a):
            s = a["status"].value_counts().reset_index()
            s.columns = ["status", "alerts"]
            fig = px.pie(s, names="status", values="alerts", hole=.62, color="status",
                         color_discrete_map={k: ds.TONES[v][1] for k, v in ds.STATUS_TONE.items()})
            fig.update_traces(textinfo="value", sort=False)
            fig.update_layout(legend=dict(orientation="h", y=-.1))
            ds.plot(fig, "ov_status", 280)
        else:
            ds.empty_state("No cases", "No alerts have been raised.", "folder_open")
    with st.container(border=True):
        ds.card_title("Recent security activity", "Latest alerts first. Click a column header to sort; select a row for details.")
        f1, f2 = st.columns([3, 2])
        q = f1.text_input("Search alerts", placeholder="Alert ID, employee, rule…", key="ov_q", label_visibility="collapsed")
        sev = f2.multiselect("Severity", ds.SEVERITY_ORDER, key="ov_sev_f", placeholder="All severities", label_visibility="collapsed")
        df = a.sort_values("ts_detect", ascending=False)
        if q:
            ql = q.lower()
            df = df[df["alert_id"].str.lower().str.contains(ql) | df["employee_id"].str.lower().str.contains(ql) | df["rules"].str.lower().str.contains(ql)]
        if sev:
            df = df[df["priority"].isin(sev)]
        sel = alert_table(df, "ov_tbl")
        view_details_button(sel, "ov")


# ================================================================= Security events
def _events_filtered(f: dict) -> pd.DataFrame:
    sql = """SELECT e.event_id, e.timestamp, e.employee_id, e.role, e.event_type, e.resource, e.customer_id, e.device_id, e.location,
                    e.volume_mb, e.outcome, e.context_tag, e.source_ref, x.alert_id, x.risk_score, x.priority, x.status
             FROM events e LEFT JOIN (
               SELECT event_id, alert_id, risk_score, priority, status FROM (
                 SELECT ae.event_id, a.alert_id, a.risk_score, a.priority, i.status,
                        ROW_NUMBER() OVER (PARTITION BY ae.event_id ORDER BY a.risk_score DESC) rn
                 FROM alert_events ae JOIN alerts a ON a.alert_id = ae.alert_id JOIN investigations i ON i.alert_id = a.alert_id) WHERE rn = 1) x
               ON x.event_id = e.event_id WHERE 1=1"""
    p: list = []
    if f["emp"]:
        sql += f" AND e.employee_id IN ({','.join('?' * len(f['emp']))})"
        p += f["emp"]
    if f["types"]:
        sql += f" AND e.event_type IN ({','.join('?' * len(f['types']))})"
        p += f["types"]
    if f["outcome"]:
        sql += f" AND e.outcome IN ({','.join('?' * len(f['outcome']))})"
        p += f["outcome"]
    if f["sev"]:
        sql += f" AND x.priority IN ({','.join('?' * len(f['sev']))})"
        p += f["sev"]
    if f["status"]:
        sql += f" AND x.status IN ({','.join('?' * len(f['status']))})"
        p += f["status"]
    if f["dates"] and len(f["dates"]) == 2:
        sql += " AND substr(e.timestamp,1,10) BETWEEN ? AND ?"
        p += [str(f["dates"][0]), str(f["dates"][1])]
    if f["q"]:
        sql += " AND (e.event_id LIKE ? OR e.resource LIKE ? OR e.customer_id LIKE ? OR e.device_id LIKE ? OR e.employee_id LIKE ?)"
        p += [f"%{f['q']}%"] * 5
    return query(sql + " ORDER BY e.timestamp DESC LIMIT 20000", tuple(p))


@st.dialog("Event details", width="large")
def event_dialog(event_id: str):
    ev = query("SELECT * FROM events WHERE event_id=?", (event_id,))
    if ev.empty:
        st.error("Event not found.")
        return
    r = ev.iloc[0]
    st.markdown(f"**{r['event_type']}** · {r['timestamp']} · {r['employee_id']} ({r['role']})")
    c1, c2 = st.columns(2)
    keys = ["event_id", "timestamp", "employee_id", "role", "event_type", "resource", "customer_id", "device_id", "location", "volume_mb", "record_count", "outcome", "context_tag", "source_ref"]
    c1.dataframe(pd.DataFrame({"field": keys[:7], "value": [str(r[k]) if pd.notna(r[k]) else "—" for k in keys[:7]]}), hide_index=True, width="stretch")
    c2.dataframe(pd.DataFrame({"field": keys[7:], "value": [str(r[k]) if pd.notna(r[k]) else "—" for k in keys[7:]]}), hide_index=True, width="stretch")
    st.caption(f"Record fingerprint (SHA-256): {r['record_hash'][:24]}…")
    linked = query("SELECT a.alert_id, a.risk_score, a.priority, i.status FROM alert_events ae JOIN alerts a USING(alert_id) JOIN investigations i USING(alert_id) WHERE ae.event_id=?", (event_id,))
    st.markdown("**Linked alerts**")
    if linked.empty:
        st.write("This event is not part of any alert.")
    else:
        st.dataframe(ds.severity_styler(linked, "priority"), hide_index=True, width="stretch")
        if st.button("Open first linked case", type="primary", icon=":material/policy:"):
            st.session_state["sel_alert"] = linked["alert_id"].iloc[0]
            go_to("investigations")
    near = query("SELECT timestamp, event_type, resource, customer_id FROM events WHERE employee_id=? AND timestamp BETWEEN datetime(?, '-10 minutes') AND datetime(?, '+10 minutes') ORDER BY timestamp LIMIT 40",
                 (r["employee_id"], r["timestamp"], r["timestamp"]))
    st.markdown("**Neighbouring events (±10 min)**")
    st.dataframe(near, hide_index=True, width="stretch", height=200)


def security_events():
    ds.page_header("Security Events", "Search, filter and inspect every activity record collected from the monitored systems.", "Dashboard")
    if not _need_data():
        return
    tab1, tab2 = st.tabs(["Event explorer", "Data quality"])
    with tab1:
        with st.container(border=True):
            f1 = st.columns([2, 2, 2, 2])
            q = f1[0].text_input("Search", placeholder="Event ID, resource, customer, device…")
            emps = query("SELECT DISTINCT employee_id FROM events ORDER BY 1")["employee_id"].tolist()
            types = query("SELECT DISTINCT event_type FROM events ORDER BY 1")["event_type"].tolist()
            emp = f1[1].multiselect("Employee", emps, placeholder="All employees")
            typ = f1[2].multiselect("Category", types, placeholder="All categories")
            outc = f1[3].multiselect("Outcome", ["success", "failure"], placeholder="Any outcome")
            f2 = st.columns([2, 2, 2])
            rng = query("SELECT MIN(substr(timestamp,1,10)) a, MAX(substr(timestamp,1,10)) b FROM events").iloc[0]
            dmin, dmax = pd.Timestamp(rng["a"]).date(), pd.Timestamp(rng["b"]).date()
            dates = f2[0].date_input("Date range", (dmin, dmax), min_value=dmin, max_value=dmax)
            sev = f2[1].multiselect("Alert severity", ds.SEVERITY_ORDER, placeholder="Any (linked alert)")
            stt = f2[2].multiselect("Case status", db.STATUSES, placeholder="Any (linked alert)")
        df = _events_filtered({"q": q, "emp": emp, "types": typ, "outcome": outc, "sev": sev, "status": stt, "dates": tuple(dates) if isinstance(dates, (tuple, list)) else None})
        with st.container(border=True):
            ds.card_title(f"{len(df):,} events", "Select a row to open the event detail panel")
            if df.empty:
                ds.empty_state("No events match", "Try widening the date range or clearing some filters.", "search_off")
            else:
                page = ds.paginate(df[["event_id", "timestamp", "employee_id", "event_type", "resource", "customer_id", "outcome", "risk_score", "priority", "status"]], "ev", sizes=(25, 50, 100))
                cfg = {"timestamp": st.column_config.TextColumn("Timestamp"), "risk_score": st.column_config.ProgressColumn("Risk (linked alert)", min_value=0, max_value=100, format="%.0f"),
                       "priority": "Severity", "event_type": "Category", "employee_id": "Employee", "event_id": "Event ID"}
                ev = st.dataframe(ds.severity_styler(page, "priority"), column_config=cfg, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="ev_tbl")
                rows = ev.selection.rows if ev and ev.selection else []
                if rows:
                    if st.button(f"View details for {page.iloc[rows[0]]['event_id']}", type="primary", icon=":material/open_in_new:"):
                        event_dialog(page.iloc[rows[0]]["event_id"])
                else:
                    st.caption("Select a row to view the event details.")
                st.download_button("Export filtered events (CSV)", df.to_csv(index=False), "events_filtered.csv", "text/csv", icon=":material/download:")
    with tab2:
        qr = json_store("quality_report")
        if not qr:
            ds.empty_state("No quality report", "Import a dataset to generate one.", "fact_check")
            return
        c = st.columns(4)
        c[0].markdown(ds.kpi("Rows in", f"{qr['rows_in']:,}", "upload_file", "indigo"), unsafe_allow_html=True)
        c[1].markdown(ds.kpi("Accepted", f"{qr['rows_accepted']:,}", "task_alt", "mint"), unsafe_allow_html=True)
        c[2].markdown(ds.kpi("Rejected", str(qr["rows_rejected"]), "block", "rose"), unsafe_allow_html=True)
        c[3].markdown(ds.kpi("Duplicates removed", str(qr["exact_duplicates_removed"]), "content_copy", "amber"), unsafe_allow_html=True)
        st.markdown("")
        with st.container(border=True):
            ds.card_title("Missing values in optional columns")
            mv = pd.DataFrame({"column": list(qr["missing_value_counts"]), "missing": list(qr["missing_value_counts"].values())})
            st.dataframe(mv, hide_index=True, width="stretch")
            for lim in qr["limitations"]:
                ds.callout(lim, warn=True)
            if qr["unrecognised_event_types"]:
                ds.callout("Unrecognised event types kept as-is: " + ", ".join(qr["unrecognised_event_types"]), warn=True)
            if qr["rejected_rows"]:
                st.dataframe(pd.DataFrame(qr["rejected_rows"]), hide_index=True, width="stretch")
            st.caption(f"Time range: {qr['time_range'][0]} → {qr['time_range'][1]}")
        meta = json_store("dataset_meta")
        if meta and meta.get("scenarios"):
            with st.expander("Documented simulated scenarios (ground truth, for evaluation only)"):
                st.dataframe(pd.DataFrame(meta["scenarios"]), hide_index=True, width="stretch")


# ================================================================= Employee risk
def employee_risk():
    ds.page_header("Employee Risk", "Ranked view of employees by their highest-priority alert, with the factors behind each score.", "Analytics")
    if not _need_data():
        return
    cfg = load_config()
    a = alerts()
    emps = query("""SELECT e.employee_id, e.role, COUNT(*) events, b.status baseline, b.history_days
                    FROM events e LEFT JOIN baselines b USING(employee_id) GROUP BY e.employee_id""")
    ml = query("SELECT employee_id, SUM(ml_flag) ml_days FROM employee_days WHERE partition!='train' GROUP BY employee_id")
    ag = (a.groupby("employee_id").agg(alerts=("alert_id", "count"), max_risk=("risk_score", "max"), avg_risk=("risk_score", "mean"),
                                       last_alert=("ts_detect", "max")).reset_index() if len(a) else pd.DataFrame(columns=["employee_id", "alerts", "max_risk", "avg_risk", "last_alert"]))
    df = emps.merge(ml, on="employee_id", how="left").merge(ag, on="employee_id", how="left").fillna({"ml_days": 0, "alerts": 0, "max_risk": 0, "avg_risk": 0})
    df["severity"] = df["max_risk"].map(lambda s: priority_for(s, cfg) if s > 0 else "Low")
    df["department"] = df["role"].str.replace("_", " ")
    with st.container(border=True):
        f = st.columns([3, 2, 2, 2])
        q = f[0].text_input("Search employee", placeholder="Employee ID…")
        dep = f[1].multiselect("Department", sorted(df["department"].unique()), placeholder="All departments")
        sev = f[2].multiselect("Severity", ds.SEVERITY_ORDER, placeholder="All severities")
        only = f[3].toggle("Only employees with alerts", value=True)
    if q:
        df = df[df["employee_id"].str.contains(q, case=False)]
    if dep:
        df = df[df["department"].isin(dep)]
    if sev:
        df = df[df["severity"].isin(sev)]
    if only:
        df = df[df["alerts"] > 0]
    df = df.sort_values(["max_risk", "alerts"], ascending=False).reset_index(drop=True)
    with st.container(border=True):
        ds.card_title(f"{len(df)} employees", "Select a row to open the employee risk profile")
        if df.empty:
            ds.empty_state("No employees match", "Clear filters or turn off 'Only employees with alerts'.", "person_search")
            return
        show = df[["employee_id", "department", "max_risk", "severity", "alerts", "ml_days", "baseline", "last_alert"]]
        page = ds.paginate(show, "er", sizes=(10, 25, 50))
        cfgc = {"employee_id": "Employee", "department": "Department", "max_risk": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%.0f"),
                "severity": "Severity", "alerts": "Alerts", "ml_days": st.column_config.NumberColumn("ML-flagged days"), "baseline": "Baseline",
                "last_alert": st.column_config.DatetimeColumn("Last alert", format="YYYY-MM-DD HH:mm")}
        ev = st.dataframe(ds.severity_styler(page, "severity"), column_config=cfgc, hide_index=True, width="stretch", on_select="rerun",
                          selection_mode="single-row", key="er_tbl")
    rows = ev.selection.rows if ev and ev.selection else []
    emp = page.iloc[rows[0]]["employee_id"] if rows else st.session_state.get("emp_focus")
    if emp is None or emp not in set(df["employee_id"]):
        st.caption("Select an employee to see the risk factors.")
        return
    row = df[df["employee_id"] == emp].iloc[0]
    st.markdown("")
    with st.container(border=True):
        h1, h2 = st.columns([3, 1])
        h1.markdown(f"### {emp} &nbsp; {ds.badge(row['severity'])}", unsafe_allow_html=True)
        h1.caption(f"{row['department'].title()} · baseline {row['baseline']} ({int(row['history_days'] or 0)} history days) · {int(row['alerts'])} alerts · {int(row['ml_days'])} ML-flagged days")
        if h2.button("Behavioral analytics", icon=":material/query_stats:", key="er_to_beh"):
            st.session_state["emp_focus"] = emp
            go_to("behavior")
        sig = query("SELECT alert_id, risk_score, signals_json FROM alerts WHERE employee_id=? ORDER BY risk_score DESC", (emp,))
        if sig.empty:
            ds.empty_state("No alerts for this employee", "Their activity stayed within baseline during the monitoring period.", "verified_user")
        else:
            rows_ = [json.loads(r.signals_json).get("signals", {}).get("contributions", {}) for r in sig.itertuples()]
            avg = pd.DataFrame(rows_).mean().rename(index=SIGNAL_LABELS).reset_index()
            avg.columns = ["factor", "points"]
            c1, c2 = st.columns([1, 1])
            with c1:
                ds.card_title("Risk factors", f"Average points per signal across {len(sig)} alert(s)")
                fig = px.bar(avg.iloc[::-1], x="points", y="factor", orientation="h", color_discrete_sequence=[ds.PRIMARY])
                fig.update_layout(yaxis_title=None)
                ds.plot(fig, f"er_f_{emp}", 250)
            with c2:
                ds.card_title("Alerts", "Highest score first")
                al = a[a["employee_id"] == emp].sort_values("risk_score", ascending=False)
                st.dataframe(ds.severity_styler(_alerts_view(al)[["alert_id", "ts_detect", "pattern", "risk_score", "priority", "status"]], "priority"),
                             column_config=ALERT_COLS, hide_index=True, width="stretch", height=250)
            top = a[a["alert_id"] == sig["alert_id"].iloc[0]].iloc[0]
            ds.callout(f"<b>Top alert {top['alert_id']}:</b> {html.escape(top['explanation'])}")


# ================================================================= Behavioral analytics
def behavior():
    ds.page_header("Behavioral Analytics", "Compare each employee's observed behavior with their own historical baseline.", "Analytics")
    if not _need_data():
        return
    emps = query("SELECT DISTINCT employee_id, role FROM events ORDER BY employee_id")
    ids = emps["employee_id"].tolist()
    focus = st.session_state.get("emp_focus", ids[0])
    emp = st.selectbox("Employee", ids, index=ids.index(focus) if focus in ids else 0, format_func=lambda x: f"{x} · {emps.set_index('employee_id').loc[x, 'role']}", key="beh_emp")
    st.session_state["emp_focus"] = emp
    row = query("SELECT baseline_json FROM baselines WHERE employee_id=?", (emp,))
    if row.empty:
        ds.empty_state("No baseline available", "This employee has no history in the selected workspace.", "person_off")
        return
    b = json.loads(row["baseline_json"][0])
    days = query("SELECT * FROM employee_days WHERE employee_id=? ORDER BY date", (emp,))
    c = st.columns(4)
    c[0].markdown(ds.kpi("Baseline status", b["status"].capitalize(), "fact_check", "mint" if b["status"] == "established" else "amber", f"{b['history_days']} active history days"), unsafe_allow_html=True)
    c[1].markdown(ds.kpi("Usual login window", f"{b['login_hour_lo']:.0f}h–{b['login_hour_hi']:.0f}h", "schedule", "indigo", "from own login history"), unsafe_allow_html=True)
    c[2].markdown(ds.kpi("Familiar accounts", str(len(b.get("familiar_customers", []))), "groups", "sky", "customer accounts seen before"), unsafe_allow_html=True)
    flagged = int(days[(days["partition"] != "train")]["ml_flag"].sum()) if len(days) else 0
    c[3].markdown(ds.kpi("ML-flagged days", str(flagged), "psychology", "rose" if flagged else "mint", "in the monitoring period"), unsafe_allow_html=True)
    st.markdown("")
    if b["status"] != "established":
        ds.callout(f"Insufficient personal history (< {load_config()['baseline']['min_history_days']} active days). The pooled <b>{b['role']}</b> role baseline is used; "
                   "device, location and account-familiarity checks are skipped for this employee instead of flagging every first-time activity.", warn=True)
        st.markdown("")
    st.caption(f"Baseline window: {b['window_start']} → {b['window_end']} · events carrying an exception context tag are excluded to limit contamination.")
    labels = {"distinct_accounts": "Distinct customer accounts / day", "n_events": "Events / day", "download_mb": "Download volume (MB) / day",
              "n_failed": "Failed logins / day", "n_priv": "Privileged operations / day", "max_sens_30min": "Peak sensitive searches in 30 min"}
    l, r = st.columns([3, 2])
    with l, st.container(border=True):
        ds.card_title("Baseline versus observed", "Daily value against the employee's own median and normal range (p95)")
        metric = st.selectbox("Metric", list(labels), format_func=labels.get, key="beh_metric", label_visibility="collapsed")
        if days.empty:
            ds.empty_state("No daily data", "", "insights")
        else:
            st_ = b["stats"][metric]
            fig = go.Figure()
            fig.add_hrect(y0=0, y1=max(st_["p95"], st_["median"]), fillcolor="rgba(16,185,129,.09)", line_width=0, annotation_text="normal range", annotation_position="top left")
            fig.add_hline(y=st_["median"], line_dash="dot", line_color=ds.MUTED, annotation_text="baseline median")
            col = ["#F43F5E" if f else ds.PRIMARY for f in days["ml_flag"]]
            fig.add_trace(go.Scatter(x=days["date"], y=days[metric], mode="lines+markers", name="Observed", line=dict(color=ds.PRIMARY, width=2),
                                     marker=dict(color=col, size=[9 if f else 5 for f in days["ml_flag"]]), hovertemplate="%{x}<br>%{y:.1f}<extra></extra>"))
            fig.update_layout(yaxis_title=labels[metric], showlegend=False)
            ds.plot(fig, f"beh_m_{emp}_{metric}", 290)
            st.caption("Red markers = days flagged by the ML anomaly model.")
    with r, st.container(border=True):
        ds.card_title("Login and access pattern", "Share of activity by hour of day")
        hrs = query("""SELECT CAST(substr(timestamp,12,2) AS INT) hour,
                       CASE WHEN timestamp < ? THEN 'Baseline period' ELSE 'Monitoring period' END period, COUNT(*) n
                       FROM events WHERE employee_id=? GROUP BY hour, period""", (b["window_end"], emp))
        if hrs.empty:
            ds.empty_state("No activity", "", "schedule")
        else:
            hrs["share"] = hrs["n"] / hrs.groupby("period")["n"].transform("sum")
            fig = px.bar(hrs, x="hour", y="share", color="period", barmode="group", color_discrete_map={"Baseline period": "#A5B4FC", "Monitoring period": "#F43F5E"})
            fig.add_vrect(x0=b["login_hour_lo"], x1=b["login_hour_hi"], fillcolor="rgba(79,70,229,.07)", line_width=0)
            fig.update_layout(yaxis_tickformat=".0%", xaxis_title="hour of day", yaxis_title="share of events")
            ds.plot(fig, f"beh_h_{emp}", 290)
            st.caption("Shaded band = usual login window.")
    l2, r2 = st.columns([3, 2])
    with l2, st.container(border=True):
        ds.card_title("Anomaly score", "Daily ML anomaly score with the flagging threshold")
        if len(days):
            mi = json_store("model_info") or {}
            fig = go.Figure(go.Scatter(x=days["date"], y=days["anomaly_score"], mode="lines+markers", line=dict(color=ds.PRIMARY, width=2),
                                       marker=dict(color=["#F43F5E" if f else ds.PRIMARY for f in days["ml_flag"]], size=6)))
            if mi.get("threshold"):
                fig.add_hline(y=mi["threshold"], line_dash="dash", line_color="#D97706", annotation_text="ML threshold")
            fig.update_layout(yaxis_title="anomaly score (not a probability)", showlegend=False)
            ds.plot(fig, f"beh_a_{emp}", 270)
    with r2, st.container(border=True):
        ds.card_title("Explained deviations", "Pick a day to see which behaviours deviate from baseline")
        if len(days):
            day = st.selectbox("Day", days["date"].tolist()[::-1], key="beh_day", label_visibility="collapsed")
            rr = days[days["date"] == day].iloc[0]
            zc = [c_ for c_ in days.columns if c_.startswith("z_")]
            z = sorted(((c_[2:], float(rr[c_])) for c_ in zc), key=lambda kv: -kv[1])
            lines = [f"<b>{name.replace('_', ' ')}</b> is {v:.1f} robust deviations above this employee's median." for name, v in z[:4] if v >= 3]
            ds.callout("<br>".join(lines) or "No behaviour deviates strongly from the employee's baseline on this day.", warn=bool(lines))
            zpos = [(n_, v) for n_, v in z[:6] if v > 0]
            if zpos:
                zdf = pd.DataFrame(zpos, columns=["feature", "z"]).iloc[::-1]
                fig = px.bar(zdf, x="z", y="feature", orientation="h", color_discrete_sequence=["#F43F5E"])
                fig.update_layout(xaxis_title="robust z-score above baseline", yaxis_title=None)
                ds.plot(fig, f"beh_z_{emp}_{day}", 200)
            else:
                st.caption("All monitored features are at or below this employee's median for the day.")
    with st.container(border=True):
        ds.card_title("Baseline statistics", "Daily robust statistics used for comparison")
        rows = [{"feature": labels.get(m, m), **{k: round(v, 2) for k, v in b["stats"][m].items()}} for m in METRICS if m in labels]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        wd = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        st.caption(f"Usual weekdays: {', '.join(wd[i] for i in b['usual_weekdays'])} · known devices: {', '.join(b.get('known_devices', [])) or '—'} · "
                   f"known locations: {', '.join(b.get('known_locations', [])) or '—'} · known resources: {len(b['known_resources'])}")
    with st.expander("Recent activity history"):
        st.dataframe(query("SELECT timestamp,event_type,resource,customer_id,device_id,location,volume_mb,outcome,context_tag,event_id FROM events WHERE employee_id=? ORDER BY timestamp DESC LIMIT 300", (emp,)),
                     hide_index=True, width="stretch")


# ================================================================= Alerts & cases
def alerts_cases():
    ds.page_header("Alerts & Cases", "Every alert raised by rules, machine learning and correlation, ranked by risk.", "Operations")
    if not _need_data():
        return
    a = alerts()
    if a.empty:
        ds.empty_state("No alerts were generated", "The dataset produced no activity above the alert threshold.", "notifications_off")
        return
    with st.container(border=True):
        f = st.columns(5)
        pr = f[0].multiselect("Severity", ds.SEVERITY_ORDER, placeholder="All severities")
        stt = f[1].multiselect("Status", db.STATUSES, placeholder="All statuses")
        em = f[2].multiselect("Employee", sorted(a["employee_id"].unique()), placeholder="All employees")
        rl = f[3].multiselect("Rule", sorted({r for x in a["rules"] for r in x.split(",") if r}), placeholder="Any rule")
        kd = f[4].multiselect("Pattern", [KIND_LABELS.get(k, k) for k in sorted(a["kind"].unique())], placeholder="Any pattern")
        g = st.columns([2, 2, 3])
        dmin, dmax = a["ts_detect"].min().date(), a["ts_detect"].max().date()
        dr = g[0].date_input("Date range", (dmin, dmax), min_value=dmin, max_value=dmax)
        et = g[1].multiselect("Event type present", ["login_failed", "login_success", "account_access", "sensitive_search", "bulk_download", "data_transfer", "privileged_op", "resource_access"], placeholder="Any event type")
        q = g[2].text_input("Search", placeholder="Alert ID, employee, explanation…")
    m = pd.Series(True, index=a.index)
    if pr:
        m &= a["priority"].isin(pr)
    if stt:
        m &= a["status"].isin(stt)
    if em:
        m &= a["employee_id"].isin(em)
    if rl:
        m &= a["rules"].apply(lambda x: any(r in x.split(",") for r in rl))
    if kd:
        inv = {v: k for k, v in KIND_LABELS.items()}
        m &= a["kind"].isin([inv.get(k, k) for k in kd])
    if isinstance(dr, (tuple, list)) and len(dr) == 2:
        m &= (a["ts_detect"].dt.date >= dr[0]) & (a["ts_detect"].dt.date <= dr[1])
    if q:
        ql = q.lower()
        m &= a["alert_id"].str.lower().str.contains(ql) | a["employee_id"].str.lower().str.contains(ql) | a["explanation"].str.lower().str.contains(ql)
    if et:
        ids = query(f"SELECT DISTINCT e.alert_id FROM alert_events e JOIN events v USING(event_id) WHERE v.event_type IN ({','.join('?' * len(et))})", tuple(et))["alert_id"]
        m &= a["alert_id"].isin(ids)
    flt = a[m]
    st.session_state["filtered_alerts"] = flt
    c = st.columns(4)
    for col, p in zip(c, ds.SEVERITY_ORDER):
        n = int((flt["priority"] == p).sum())
        col.markdown(ds.kpi(p, str(n), "flag", {"Critical": "rose", "High": "amber", "Medium": "amber", "Low": "mint"}[p], "alerts in current filter"), unsafe_allow_html=True)
    st.markdown("")
    with st.container(border=True):
        ds.card_title(f"{len(flt)} of {len(a)} alerts", "Click a column header to sort; select a row for the full explanation")
        sel = alert_table(flt, "ac", cols=("alert_id", "ts_detect", "employee_id", "role", "pattern", "risk_score", "priority", "rules", "n_events", "status"))
    if sel:
        st.session_state["sel_alert"] = sel
        con = connect()
        try:
            d = forensics.get_alert(con, sel)
        finally:
            con.close()
        st.markdown(f"### Case {sel} &nbsp; {ds.badge(d['alert']['priority'])} &nbsp; {ds.badge(d['investigation'].get('status', 'Pending review'))}", unsafe_allow_html=True)
        render_alert_detail(d)
        b1, b2, _ = st.columns([1, 1, 3])
        if b1.button("Open investigation", type="primary", icon=":material/policy:", key="ac_inv"):
            go_to("investigations")
        if b2.button("Forensic timeline", icon=":material/timeline:", key="ac_tl"):
            go_to("timeline")


# ================================================================= Threat investigations
def investigations():
    ds.page_header("Threat Investigations", "Work a case end-to-end: review evidence, record notes, set status and disposition, export the report.", "Operations")
    if not _need_data():
        return
    a = alerts()
    if a.empty:
        ds.empty_state("No cases to investigate", "No alerts were generated.", "folder_open")
        return
    counts = a["status"].value_counts()
    c = st.columns(5)
    icons = {"Pending review": "hourglass_top", "Under investigation": "manage_search", "Explained / legitimate": "verified", "Escalated": "priority_high", "Closed": "inventory_2"}
    for col, s in zip(c, db.STATUSES):
        col.markdown(ds.kpi(s, str(int(counts.get(s, 0))), icons[s], ds.STATUS_TONE[s]), unsafe_allow_html=True)
    st.markdown("")
    sel = pick_alert("Case", key="inv_pick")
    if not sel:
        return
    d, integrity = _load_detail(sel)
    al, inv = d["alert"], d["investigation"]
    with st.container(border=True):
        st.markdown(f"### {sel} &nbsp; {ds.badge(al['priority'])} &nbsp; {ds.badge(inv.get('status', 'Pending review'))}", unsafe_allow_html=True)
        st.caption(f"{al['employee_id']} ({al['role']}) · detected {al['ts_detect']} · {int(d['timeline']['in_alert'].sum())} linked events · disposition: {inv.get('disposition', 'Not set')}")
        ds.stepper(db.STATUSES, inv.get("status", "Pending review"))
        b1, b2, _ = st.columns([1, 1, 4])
        if b1.button("Forensic timeline", icon=":material/timeline:", key="inv_tl"):
            go_to("timeline")
        if b2.button("Employee behavior", icon=":material/query_stats:", key="inv_beh"):
            st.session_state["emp_focus"] = al["employee_id"]
            go_to("behavior")
    t1, t2, t3, t4 = st.tabs(["Case overview", "Evidence summary", "Analyst review", "Report"])
    with t1:
        render_alert_detail(d)
    with t2:
        summ = forensics.investigation_summary(d)
        names = {"observed_facts": "1. Observed facts", "detection_signals": "2. Detection signals", "inferred_relationships": "3. Inferred relationships",
                 "missing_or_uncertain_evidence": "4. Missing or uncertain evidence", "analyst_conclusions": "5. Analyst conclusions"}
        for k, title in names.items():
            with st.container(border=True):
                ds.card_title(title)
                for item in summ[k] or ["None."]:
                    st.markdown(f"- {item}")
        if integrity["ok"]:
            ds.callout(f"<b>Evidence integrity:</b> {integrity['checked']} source records re-hashed (SHA-256) and match their ingest fingerprints. This detects untracked changes; it is not tamper-proof storage.")
        else:
            st.error(f"Integrity mismatch for events: {', '.join(integrity['mismatched'])}")
    with t3:
        l, r = st.columns(2)
        with l, st.container(border=True):
            ds.card_title("Status and disposition", "Changes are saved to the database and written to the audit log")
            with st.form(f"inv_{sel}"):
                status = st.selectbox("Status", db.STATUSES, index=db.STATUSES.index(inv.get("status", "Pending review")))
                disp = st.selectbox("Final disposition", db.DISPOSITIONS, index=db.DISPOSITIONS.index(inv.get("disposition", "Not set")))
                concl = st.text_area("Analyst conclusion", value=inv.get("conclusion", ""), placeholder="Summarise what you found and why you chose this disposition.")
                if st.form_submit_button("Save status and disposition", type="primary", icon=":material/save:"):
                    who = st.session_state.get("analyst", ACTOR)
                    with db.session(db_path()) as con:
                        db.update_investigation(con, sel, status, disp, concl, who)
                    flash(f"Case {sel} updated: {status}")
                    st.rerun()
        with r, st.container(border=True):
            ds.card_title("Analyst notes", f"Writing as {st.session_state.get('analyst', ACTOR)} (change in System Settings)")
            with st.form(f"note_{sel}", clear_on_submit=True):
                note = st.text_area("Add note", placeholder="Observation, follow-up action, question for the line manager…")
                if st.form_submit_button("Add note", type="primary", icon=":material/add_comment:"):
                    try:
                        with db.session(db_path()) as con:
                            db.add_note(con, sel, st.session_state.get("analyst", ACTOR), note)
                        flash("Note added")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
            if not d["notes"]:
                st.caption("No notes yet.")
            for n in reversed(d["notes"]):
                st.markdown(f"<div class='callout'><b>{html.escape(n['author'])}</b> · {n['created_at']}<br>{html.escape(n['note'])}</div>", unsafe_allow_html=True)
                st.markdown("")
    with t4:
        meta = json_store("dataset_meta") or {}
        info = {k: meta.get(k) for k in ("synthetic", "seed", "n_events", "start", "val_end") if k in meta}
        report = forensics.report_html(d, info, integrity)
        with st.container(border=True):
            ds.card_title("Investigation report", "Includes facts, signals, inferences, missing evidence, analyst conclusions, timeline and integrity check")
            x = st.columns(3)
            x[0].download_button("Report (HTML)", report, f"investigation_{sel}.html", "text/html", icon=":material/description:", type="primary")
            x[1].download_button("Evidence + timeline (JSON)", forensics.evidence_json(d), f"evidence_{sel}.json", "application/json", icon=":material/data_object:")
            x[2].download_button("Timeline (CSV)", d["timeline"].to_csv(index=False), f"timeline_{sel}.csv", "text/csv", icon=":material/table:")
        with st.expander("Preview report"):
            st.iframe(report, height=640)


# ================================================================= Forensic timeline
def al_color(priority: str) -> str:
    return ds.SEVERITY.get(priority, ds.PRIMARY)


def timeline_page():
    ds.page_header("Forensic Timeline", "Chronological reconstruction of the activity behind an alert, with source references.", "Operations")
    if not _need_data():
        return
    sel = pick_alert("Alert", key="tl_pick")
    if not sel:
        return
    d, integrity = _load_detail(sel)
    al, tl = d["alert"], d["timeline"]
    members = tl[tl["in_alert"]]
    c = st.columns(4)
    c[0].markdown(ds.kpi("Alert events", str(len(members)), "event", "indigo", f"{len(tl) - len(members)} context events nearby"), unsafe_allow_html=True)
    c[1].markdown(ds.kpi("Window", f"{pd.Timestamp(members['timestamp'].min()):%H:%M}–{pd.Timestamp(members['timestamp'].max()):%H:%M}", "schedule", "sky",
                         f"{pd.Timestamp(members['timestamp'].min()):%Y-%m-%d}"), unsafe_allow_html=True)
    c[2].markdown(ds.kpi("Severity", al["priority"], "flag", "rose" if al["priority"] in ("Critical", "High") else "amber", f"risk {al['risk_score']:.0f}/100"), unsafe_allow_html=True)
    c[3].markdown(ds.kpi("Integrity", "Verified" if integrity["ok"] else "Mismatch", "verified_user" if integrity["ok"] else "gpp_bad", "mint" if integrity["ok"] else "rose",
                         f"{integrity['checked']} records re-hashed"), unsafe_allow_html=True)
    st.markdown("")
    with st.container(border=True):
        ds.card_title("Event map", "Large markers belong to the alert; small grey markers are surrounding context. Hover for details.")
        show_ctx = st.toggle("Include context events", value=True, key="tl_ctx")
        t = tl if show_ctx else members
        t = t.assign(member=t["in_alert"].map({True: "Alert event", False: "Context"}), size=t["in_alert"].map({True: 10, False: 5}))
        fig = px.scatter(t, x="timestamp", y="event_type", color="member", size="size", size_max=10, color_discrete_map={"Alert event": al_color(al["priority"]), "Context": "#CBD5E1"},
                         hover_data={"event_id": True, "resource": True, "customer_id": True, "contributing_rules": True, "size": False, "member": False})
        fig.update_layout(yaxis_title=None, xaxis_title=None)
        ds.plot(fig, f"tl_map_{sel}", 340)
    l, r = st.columns([3, 2])
    with l, st.container(border=True):
        ds.card_title("Chronological timeline", "Each entry shows time, event, resource and the rules citing it")
        limit = st.select_slider("Entries to show", options=[20, 50, 100, 250, 1000], value=50, key="tl_limit") if len(t) > 20 else len(t)
        items = []
        for row in t.head(limit).itertuples():
            cls = "" if row.in_alert else " ctx"
            col = al_color(al["priority"]) if row.contributing_rules else (ds.PRIMARY if row.in_alert else "#CBD5E1")
            meta = " · ".join(str(x) for x in (row.resource, row.customer_id, f"{row.volume_mb:.0f} MB" if pd.notna(row.volume_mb) else None, row.outcome) if x and str(x) != "nan")
            rules = f" &nbsp;{ds.badge(row.contributing_rules, 'indigo', dot=False)}" if row.contributing_rules else ""
            items.append(f"<div class='tl-item{cls}'><span class='tl-dot' style='background:{col}'></span><div class='tl-time'>{row.timestamp} · {html.escape(str(row.event_id))}</div>"
                         f"<div class='tl-title'>{html.escape(row.event_type.replace('_', ' ').title())}{rules}</div><div class='tl-meta'>{html.escape(meta)}</div></div>")
        st.markdown("<div class='tl'>" + "".join(items) + "</div>", unsafe_allow_html=True)
        if len(t) > limit:
            st.caption(f"Showing {limit} of {len(t)} entries.")
    with r, st.container(border=True):
        ds.card_title("Event detail", "Select an event to see its record and contributing signals")
        eid = st.selectbox("Event", members["event_id"].tolist() if not members.empty else [], key="tl_event", label_visibility="collapsed")
        if eid:
            ev = tl[tl["event_id"] == eid].iloc[0]
            fields = [k for k in ev.index if k not in ("size", "member")]
            st.dataframe(pd.DataFrame({"field": fields, "value": ["—" if pd.isna(ev[k]) else str(ev[k]) for k in fields]}), hide_index=True, width="stretch", height=300)
            rel = [x for x in d["rules"] if eid in x["event_ids"]]
            st.markdown("**Contributing signals**")
            for x in rel:
                st.markdown(f"- **{x['rule_id']}** {x['rule_name']}: {x['explanation']}")
            if not rel:
                st.caption("Not cited directly by a rule.")
        if st.button("Open case", icon=":material/policy:", key="tl_case"):
            go_to("investigations")


# ================================================================= Reports (+ evaluation)
def reports():
    ds.page_header("Reports", "Export alerts, evidence and investigation reports, and review how the detection methods were evaluated.", "Operations")
    if not _need_data():
        return
    tab1, tab2 = st.tabs(["Exports", "Evaluation"])
    with tab1:
        a = alerts()
        flt = st.session_state.get("filtered_alerts", a)
        with st.container(border=True):
            ds.card_title("Alert export", "Choose the alert set and format (CSV, JSON and HTML are supported)")
            scope = st.radio("Alert set", [f"Filtered in Alerts & Cases ({len(flt)})", f"All alerts ({len(a)})"], horizontal=True)
            df = flt if scope.startswith("Filtered") else a
            sev = st.multiselect("Limit to severity", ds.SEVERITY_ORDER, placeholder="All severities")
            if sev:
                df = df[df["priority"].isin(sev)]
            if df.empty:
                ds.empty_state("Nothing to export", "No alerts in the chosen set.", "folder_off")
            else:
                st.dataframe(ds.severity_styler(df.drop(columns=["explanation"]), "priority"), hide_index=True, width="stretch", height=260)
                c = st.columns(4)
                c[0].download_button("Alerts (CSV)", forensics.alerts_to_csv(df), "alerts.csv", "text/csv", icon=":material/download:", type="primary")
                c[1].download_button("Alerts + explanations (JSON)", df.to_json(orient="records", date_format="iso", indent=2), "alerts.json", "application/json", icon=":material/data_object:")
                ev = json_store("evaluation")
                if ev:
                    c[2].download_button("Evaluation (JSON)", json.dumps(ev, indent=2), "evaluation.json", "application/json", icon=":material/analytics:")
        with st.container(border=True):
            ds.card_title("Single-alert investigation report", "Self-contained HTML report consistent with the case page")
            if df.empty:
                ds.empty_state("No alerts available", "", "description")
            else:
                sel = st.selectbox("Alert", df["alert_id"].tolist(), key="rep_alert")
                d, integrity = _load_detail(sel)
                meta = json_store("dataset_meta") or {}
                report = forensics.report_html(d, {k: meta.get(k) for k in ("synthetic", "seed", "n_events") if k in meta}, integrity)
                x = st.columns(3)
                x[0].download_button("Report (HTML)", report, f"investigation_{sel}.html", "text/html", icon=":material/description:", type="primary", key="rep_html")
                x[1].download_button("Evidence + timeline (JSON)", forensics.evidence_json(d), f"evidence_{sel}.json", "application/json", icon=":material/data_object:", key="rep_json")
                x[2].download_button("Timeline (CSV)", d["timeline"].to_csv(index=False), f"timeline_{sel}.csv", "text/csv", icon=":material/table:", key="rep_csv")
                with st.expander("Preview report"):
                    st.iframe(report, height=640)
    with tab2:
        _evaluation()


def _method_chart(ev: dict, part: str):
    t = pd.DataFrame(ev["methods"][part])
    short = {"Rule-only (any rule hit)": "Rule-only", "ML-only (Isolation Forest)": "Isolation Forest", "ML-only (LOF, 2nd detector)": "LOF",
             "Combined (rules+ML+correlation+risk, any alert)": "Combined", "Combined (High/Critical alerts only)": "Combined High+"}
    t["method"] = t["method"].map(lambda m: short.get(m, m))
    m = t.melt(id_vars="method", value_vars=["precision", "recall", "f1"], var_name="metric").dropna()
    fig = px.bar(m, x="method", y="value", color="metric", barmode="group", color_discrete_sequence=["#4F46E5", "#0EA5E9", "#10B981"])
    fig.update_layout(xaxis_title=None, yaxis_title="score", yaxis_range=[0, 1.05])
    ds.plot(fig, f"evc_{part}", 320)


def _evaluation():
    ev = json_store("evaluation")
    if not ev:
        ds.empty_state("Evaluation unavailable", "Evaluation needs ground-truth labels, which exist for the synthetic demo workspace only.", "analytics")
        return
    ds.callout("All values are computed from actual predictions on <b>synthetic</b> data with documented simulated incidents. The sample is small (tens of incidents); "
               "results illustrate the pipeline and do not predict real-world accuracy.", warn=True)
    st.caption("Label method: " + ev["label_method"])
    part = st.radio("Partition", ["test", "validation"], horizontal=True)
    p = ev["partitions"][part]
    c = st.columns(4)
    c[0].markdown(ds.kpi("Employee-days", str(p["employee_days"]), "calendar_month", "indigo", f"{p['start']} → {p['end']}"), unsafe_allow_html=True)
    c[1].markdown(ds.kpi("Positive days", str(p["positive_days"]), "flag", "rose"), unsafe_allow_html=True)
    c[2].markdown(ds.kpi("Negative days", str(p["negative_days"]), "check_circle", "mint"), unsafe_allow_html=True)
    q = ev["alert_quality_test"]
    c[3].markdown(ds.kpi("Alert precision (test)", _pct(q["alert_precision"]), "target", "lavender", f"{q['false_alerts_per_employee_week']:.2f} false alerts / employee / week"), unsafe_allow_html=True)
    st.markdown("")
    t = pd.DataFrame(ev["methods"][part])
    l, r = st.columns([3, 2])
    with l, st.container(border=True):
        ds.card_title("Method comparison", "Precision, recall and F1 per detection method")
        _method_chart(ev, part)
    with r, st.container(border=True):
        ds.card_title("Metrics table")
        st.dataframe(t[["method", "precision", "recall", "f1", "accuracy", "balanced_accuracy"]].round(3), hide_index=True, width="stretch", height=320)
    with st.container(border=True):
        ds.card_title("Confusion matrices", "Employee-day level")
        cols = st.columns(len(t))
        for col, r_ in zip(cols, t.itertuples()):
            fig = go.Figure(go.Heatmap(z=[[r_.tn, r_.fp], [r_.fn, r_.tp]], x=["Pred. normal", "Pred. alert"], y=["Actual normal", "Actual incident"],
                                       text=[[r_.tn, r_.fp], [r_.fn, r_.tp]], texttemplate="%{text}", colorscale=[[0, "#F5F7FB"], [1, "#4F46E5"]], showscale=False))
            fig.update_layout(title=dict(text=r_.method.split(" (")[0], font=dict(size=11)))
            with col:
                ds.plot(fig, f"cm_{part}_{r_.Index}", 230)
    c = st.columns(3)
    c[0].markdown(ds.kpi("Alerts with explanation", f"{q['alerts_with_explanation']}/{q['alerts']}", "article", "mint"), unsafe_allow_html=True)
    c[1].markdown(ds.kpi("Alerts with timeline", f"{q['alerts_with_timeline']}/{q['alerts']}", "timeline", "mint"), unsafe_allow_html=True)
    c[2].markdown(ds.kpi("Alerts with source refs", f"{q['alerts_with_source_refs']}/{q['alerts']}", "link", "mint"), unsafe_allow_html=True)
    st.markdown("")
    me = ev["multi_event_scenarios"]
    inc = pd.DataFrame(ev["incidents"])
    with st.container(border=True):
        ds.card_title("Simulated incident detection", f"Full multi-event chains: {me['detected_as_correlated_sequence']}/{me['full_chain_incidents']} detected as one correlated sequence "
                      f"(mean event coverage {_pct(me['mean_event_coverage'])})")
        summ = inc.groupby("type").agg(incidents=("scenario_id", "count"), rule_only=("detected_rule_only", "sum"), ml_only=("detected_ml_only", "sum"),
                                       combined=("detected_combined", "sum")).reset_index()
        st.dataframe(summ, hide_index=True, width="stretch")
        with st.expander("Per-incident results"):
            st.dataframe(inc, hide_index=True, width="stretch")


# ================================================================= System settings
@st.dialog("Regenerate demo dataset?")
def reset_dialog():
    st.markdown("This **deletes the demo workspace's alerts, notes and investigation records** and rebuilds them from the seeded synthetic generator. "
                "Other workspaces are not touched.")
    conf = st.text_input("Type RESET to confirm")
    c1, c2 = st.columns(2)
    if c1.button("Regenerate", type="primary", disabled=conf != "RESET", icon=":material/restart_alt:"):
        with st.spinner("Generating data, training model, scoring…"):
            r = init_demo(DEFAULT_WORKSPACE, regenerate=True)
        flash(f"Demo workspace rebuilt: {r['events']:,} events, {r['alerts']} alerts")
        st.rerun()
    if c2.button("Cancel"):
        st.rerun()


def settings():
    ds.page_header("System Settings", "Detection configuration, data workspaces and analyst profile.", "System")
    tab1, tab2, tab3 = st.tabs(["Detection engine", "Data & workspaces", "Analyst profile"])
    cfg = load_config()
    with tab1:
        t1, t2, t3, t4 = st.tabs(["Rules", "ML model", "Risk scoring", "Method comparison"])
        with t1:
            ds.callout("Thresholds are centralised in <code>insider/config.py</code> (optional override: <code>config/detection_config.json</code>). Re-process the workspace after changing them.")
            rd = describe_rules(cfg)
            rd["parameters"] = rd["parameters"].apply(json.dumps)
            st.dataframe(rd, hide_index=True, width="stretch")
            mi = json_store("model_info") or {}
            if mi.get("skipped_rules"):
                ds.callout("Rules skipped for this dataset: " + "; ".join(f"{k}: {v}" for k, v in mi["skipped_rules"].items()), warn=True)
        with t2:
            mi = json_store("model_info")
            if not mi:
                ds.empty_state("No model trained", "Process a workspace to train the anomaly model.", "psychology")
            elif not mi.get("ml_enabled"):
                st.error("ML disabled: " + "; ".join(mi.get("warnings", [])))
            else:
                c = st.columns(4)
                c[0].markdown(ds.kpi("Model", mi["model"], "psychology", "lavender"), unsafe_allow_html=True)
                c[1].markdown(ds.kpi("Training employee-days", str(mi["n_train_rows"]), "table_rows", "indigo"), unsafe_allow_html=True)
                c[2].markdown(ds.kpi("Features", str(mi["n_features"]), "tune", "sky"), unsafe_allow_html=True)
                c[3].markdown(ds.kpi("Threshold quantile", str(mi["threshold_quantile"]), "percent", "amber", f"selected on {mi.get('threshold_selected_on', 'default')}"), unsafe_allow_html=True)
                st.markdown("")
                st.dataframe(pd.DataFrame({"setting": ["Training range", "Anomaly-score threshold", "Score median (train) → severity 0", "Score 99.9th pct (train) → severity 1",
                                                       "Comparison model", "Trained at", "Saved model"],
                                           "value": [str(mi.get("train_range")), str(round(mi["threshold"], 4)), str(round(mi["score_q50"], 4)), str(round(mi["score_q999"], 4)),
                                                     mi["comparison_model"], mi["trained_at"], mi["model_path"]]}), hide_index=True, width="stretch")
                ds.callout("<b>Score convention:</b> <code>anomaly_score = -IsolationForest.score_samples(x)</code>; higher = more anomalous. It is an unsupervised anomaly index, <b>not</b> a probability of malicious intent.")
                with st.expander("Feature list"):
                    st.write(mi["features"])
        with t3:
            r = cfg["risk"]
            st.latex(r"\text{score}=100\sum_i w_i S_i\times\bigl(1-d\cdot c\bigr)")
            st.markdown("""
- **S_rules** – noisy-OR of severity weights over *distinct* rule IDs (repeated hits of one rule do not stack).
- **S_ml** – severity index of the employee-day anomaly score.
- **S_deviation** – largest positive robust z-score vs the employee's own baseline, divided by a cap.
- **S_correlation** – (core stages − 1) / 4, reduced if out of order; 0 for isolated activity.
- **S_sensitivity** – highest sensitivity weight among the group's event types.
- **d, c** – context discount and share of events carrying an approval tag (tags are unverified claims).

The score is a **prioritisation index**, not a calibrated probability.""")
            c1, c2 = st.columns(2)
            c1.dataframe(pd.DataFrame({"signal": list(r["weights"]), "weight": list(r["weights"].values())}), hide_index=True, width="stretch")
            c2.json({**r["priority_thresholds"], "alert_min_score": r["alert_min_score"], "context_discount": r["context_discount"], "severity_weights": cfg["severity_weight"]}, expanded=True)
        with t4:
            ev = json_store("evaluation")
            if not ev:
                ds.empty_state("No evaluation", "Method comparison needs ground-truth labels.", "analytics")
            else:
                _method_chart(ev, "test")
    with tab2:
        wss = db.list_workspaces()
        active = db.get_active_workspace()
        with st.container(border=True):
            ds.card_title("Active workspace", "Each workspace is a separate local SQLite database")
            if wss:
                new = st.selectbox("Workspace", wss, index=wss.index(active) if active in wss else 0, label_visibility="collapsed")
                if new != active:
                    db.set_active_workspace(new)
                    flash(f"Switched to workspace '{new}'")
                    st.rerun()
        with st.container(border=True):
            ds.card_title("Upload events (CSV)", f"Validated, previewed, then imported into a NEW workspace — existing data is never overwritten. Max {MAX_UPLOAD_MB} MB.")
            st.caption(f"Required: {', '.join(REQUIRED_COLUMNS)} · Optional: {', '.join(OPTIONAL_COLUMNS)}")
            sample = SYNTH_DIR / "sample_upload.csv"
            if sample.exists():
                st.download_button("Download sample CSV", sample.read_bytes(), "sample_upload.csv", "text/csv", icon=":material/download:")
            up = st.file_uploader("Upload events CSV", type=["csv"], label_visibility="collapsed")
            if up is not None:
                try:
                    clean, rep = validate_and_clean(read_csv_safely(up.getvalue()))
                except IngestError as exc:
                    st.error(str(exc))
                else:
                    st.success(f"Parsed {rep['rows_in']:,} rows: {rep['rows_accepted']:,} accepted, {rep['rows_rejected']} rejected, {rep['exact_duplicates_removed']} duplicates removed.")
                    for lim in rep["limitations"]:
                        ds.callout(lim, warn=True)
                    if rep["unrecognised_event_types"]:
                        ds.callout("Unrecognised event types: " + ", ".join(rep["unrecognised_event_types"]), warn=True)
                    st.dataframe(clean.drop(columns=["record_hash"]).head(50), hide_index=True, width="stretch")
                    name = st.text_input("New workspace name", value="upload1", help="Letters, digits, '-' and '_' (max 40).")
                    ok = st.checkbox("I confirm this file contains only synthetic or explicitly authorised data.")
                    if st.button("Import and analyse", type="primary", disabled=not ok or rep["rows_accepted"] == 0, icon=":material/upload:"):
                        try:
                            path = db.workspace_path(name)
                            if path.exists():
                                st.error(f"Workspace '{name}' already exists — choose another name.")
                            else:
                                with st.spinner("Ingesting and analysing…"):
                                    with db.session(path) as con:
                                        ingest_events(con, clean, rep, None, {"synthetic": False, "source": up.name}, st.session_state.get("analyst", ACTOR))
                                        process_workspace(con, load_config(), model_name=name)
                                db.set_active_workspace(name)
                                flash(f"Workspace '{name}' created and activated")
                                st.rerun()
                        except ValueError as exc:
                            st.error(str(exc))
                        except Exception as exc:  # surfaced to the analyst, not hidden
                            st.error(f"Import failed: {exc}")
        with st.container(border=True):
            ds.card_title("Demo dataset", "Regenerate the seeded synthetic demo workspace")
            if st.button("Regenerate demo dataset…", icon=":material/restart_alt:"):
                reset_dialog()
        if has_data():
            with st.container(border=True):
                ds.card_title("Audit log", "Hash-chained (tamper-evident) record of ingest, processing and analyst actions")
                con = connect()
                try:
                    ok, bad = db.verify_audit_chain(con)
                    st.markdown(ds.badge("Chain verified", "mint") if ok else ds.badge(f"Broken at row {bad}", "rose"), unsafe_allow_html=True)
                    st.dataframe(pd.read_sql_query("SELECT id, ts, actor, action, target, details FROM audit_log ORDER BY id DESC LIMIT 200", con), hide_index=True, width="stretch", height=280)
                finally:
                    con.close()
    with tab3:
        with st.container(border=True):
            ds.card_title("Analyst profile", "Name recorded on notes, dispositions and the audit log")
            with st.form("profile"):
                name = st.text_input("Analyst name", value=st.session_state.get("analyst", ACTOR), max_chars=40)
                if st.form_submit_button("Save profile", type="primary", icon=":material/save:"):
                    clean_name = name.strip()
                    if not clean_name:
                        st.error("Name cannot be empty.")
                    else:
                        st.session_state["analyst"] = clean_name
                        flash("Profile saved")
                        st.rerun()
