"""Sentinel Intelligence - Streamlit entry point:  streamlit run dashboard/app.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

st.set_page_config(page_title="Sentinel Intelligence · Banking Threat Analytics", page_icon=str(Path(__file__).parent / "assets" / "icon.svg"),
                   layout="wide", initial_sidebar_state="expanded")

from dashboard import design as ds  # noqa: E402
from dashboard import views  # noqa: E402
from dashboard.common import alerts, has_data, query  # noqa: E402
from dashboard.dock import dock  # noqa: E402
from insider import db  # noqa: E402

ASSETS = Path(__file__).parent / "assets"
ds.inject_css()
st.logo(str(ASSETS / "logo.svg"), icon_image=str(ASSETS / "icon.svg"), size="large")

P = st.Page
PAGES = {
    "overview": P(views.overview, title="Overview", icon=":material/dashboard:", url_path="overview", default=True),
    "events": P(views.security_events, title="Security Events", icon=":material/receipt_long:", url_path="security-events"),
    "risk": P(views.employee_risk, title="Employee Risk", icon=":material/person_alert:", url_path="employee-risk"),
    "behavior": P(views.behavior, title="Behavioral Analytics", icon=":material/query_stats:", url_path="behavioral-analytics"),
    "investigations": P(views.investigations, title="Threat Investigations", icon=":material/policy:", url_path="investigations"),
    "timeline": P(views.timeline_page, title="Forensic Timeline", icon=":material/timeline:", url_path="forensic-timeline"),
    "alerts": P(views.alerts_cases, title="Alerts & Cases", icon=":material/notifications_active:", url_path="alerts-cases"),
    "reports": P(views.reports, title="Reports", icon=":material/description:", url_path="reports"),
    "settings": P(views.settings, title="System Settings", icon=":material/settings:", url_path="settings"),
}
st.session_state["_pages"] = PAGES
nav = st.navigation({
    "Dashboard": [PAGES["overview"], PAGES["events"]],
    "Analytics": [PAGES["risk"], PAGES["behavior"]],
    "Operations": [PAGES["investigations"], PAGES["timeline"], PAGES["alerts"], PAGES["reports"]],
    "System": [PAGES["settings"]],
})


def topbar() -> None:
    """Global search, notifications (real unresolved High/Critical alerts), profile menu."""
    c_search, c_ctx, c_bell, c_user = st.columns([5, 3, 1.1, 1.6], vertical_alignment="center")
    q = c_search.text_input("Global search", placeholder="Search alerts, employees, rules…", icon=":material/search:", label_visibility="collapsed", key="global_q")
    ws = db.get_active_workspace()
    if has_data():
        rng = query("SELECT MIN(substr(timestamp,1,10)) a, MAX(substr(timestamp,1,10)) b FROM events").iloc[0]
        c_ctx.caption(f"Reporting period {rng['a']} → {rng['b']} · workspace “{ws}”")
    else:
        c_ctx.caption(f"Workspace “{ws}” (empty)")
    a = alerts() if has_data() else None
    urgent = a[(a["priority"].isin(["Critical", "High"])) & (a["status"] == "Pending review")].sort_values("risk_score", ascending=False) if a is not None and len(a) else None
    n = 0 if urgent is None else len(urgent)
    with c_bell.popover(f"{n}" if n else "", icon=":material/notifications:", help="Pending High/Critical alerts", width="stretch"):
        st.markdown("**Needs review**")
        if not n:
            st.caption("No High or Critical alerts are waiting for review.")
        for r in (urgent.head(6).itertuples() if n else []):
            if st.button(f"{r.priority} · {r.employee_id} · {r.risk_score:.0f}", key=f"bell_{r.alert_id}", help=r.alert_id, width="stretch"):
                st.session_state["sel_alert"] = r.alert_id
                st.switch_page(PAGES["investigations"])
        if n > 6:
            st.caption(f"+ {n - 6} more in Alerts & Cases")
    with c_user.popover(st.session_state.get("analyst", "analyst"), icon=":material/account_circle:", width="stretch"):
        st.markdown(f"**{st.session_state.get('analyst', 'analyst')}**")
        st.caption("Security analyst · local session")
        st.caption("Alerts require human review; no automated action is taken against any employee.")
        if st.button("Profile & settings", icon=":material/settings:", width="stretch", key="menu_settings"):
            st.switch_page(PAGES["settings"])
    if q and has_data() and a is not None and len(a):
        ql = q.lower()
        hit = a[a["alert_id"].str.lower().str.contains(ql) | a["employee_id"].str.lower().str.contains(ql) | a["rules"].str.lower().str.contains(ql)
                | a["explanation"].str.lower().str.contains(ql)].sort_values("risk_score", ascending=False)
        with st.container(border=True):
            st.markdown(f"**{len(hit)} matching alert(s)**" + (" — showing top 5" if len(hit) > 5 else ""))
            if hit.empty:
                st.caption("No alerts match. Try an alert ID, employee ID or rule ID (e.g. R07).")
            for r in hit.head(5).itertuples():
                if st.button(f"{r.alert_id} · {r.employee_id} · {r.priority} {r.risk_score:.0f} · {r.status}", key=f"gs_{r.alert_id}", width="stretch"):
                    st.session_state["sel_alert"] = r.alert_id
                    st.switch_page(PAGES["investigations"])


with st.sidebar:
    if has_data():
        _a = alerts()
        st.caption(f"WORKSPACE · {db.get_active_workspace()}")
        if len(_a):
            _counts = _a["priority"].value_counts()
            _c1, _c2 = st.columns(2)
            _c1.metric("Critical", int(_counts.get("Critical", 0)))
            _c2.metric("High", int(_counts.get("High", 0)))
            _c3, _c4 = st.columns(2)
            _c3.metric("Medium", int(_counts.get("Medium", 0)))
            _c4.metric("Pending", int((_a["status"] == "Pending review").sum()))
            _top = _a.sort_values("risk_score", ascending=False).iloc[0]
            if st.button(f"Top alert · {_top['employee_id']} · {_top['risk_score']:.0f}", icon=":material/priority_high:", width="stretch", key="side_top"):
                st.session_state["sel_alert"] = _top["alert_id"]
                st.switch_page(PAGES["investigations"])
        else:
            st.caption("No alerts in this workspace.")
        st.divider()
    st.markdown("<div class='side-note'><b>Human review required.</b><br>Scores prioritise work; they are not probabilities of intent. "
                "Synthetic data by default.</div>", unsafe_allow_html=True)

for msg, icn in st.session_state.pop("_flash", []):
    st.toast(msg, icon=icn)
topbar()
_pending = 0
if has_data():
    _al = alerts()
    _pending = int(((_al["priority"].isin(["Critical", "High"])) & (_al["status"] == "Pending review")).sum()) if len(_al) else 0
_order = ["overview", "events", "risk", "behavior", None, "investigations", "timeline", "alerts", "reports", None, "settings"]
_items = [{"separator": True} if k is None else
          {"key": k, "label": PAGES[k].title, "icon": PAGES[k].icon.strip(":").split("/")[1],
           "active": PAGES[k].url_path == nav.url_path, "badge": _pending if (k == "alerts" and _pending) else 0}
          for k in _order]
_go = dock(_items)
if _go and PAGES[_go].url_path != nav.url_path:
    st.switch_page(PAGES[_go])
nav.run()
